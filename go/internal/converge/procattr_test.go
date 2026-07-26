//go:build unix

package converge

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// childProcAttr must isolate the child into its own process group so a killed
// converge can never leave an apply running headless inside the parent's group.
func TestChildProcAttrIsolatesProcessGroup(t *testing.T) {
	a := childProcAttr()
	if a == nil || !a.Setpgid {
		t.Fatalf("childProcAttr must set Setpgid so the child leads its own group; got %+v", a)
	}
}

// Functional: a child started with childProcAttr becomes its OWN process-group
// leader (pgid == pid), proving Setpgid takes effect end to end.
func TestChildBecomesGroupLeader(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = childProcAttr()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	pid := cmd.Process.Pid
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatalf("getpgid: %v", err)
	}
	if pgid != pid {
		t.Fatalf("child pgid %d != pid %d — Setpgid did not isolate the group", pgid, pid)
	}
}

// TestOrphanGuardHelper is a re-exec HELPER (not a standalone assertion): when armed
// by the env var it spawns a long-lived grandchild with the orphan guard, records the
// grandchild pid, and blocks — modelling a converge with an apply in flight. It skips
// during a normal suite run.
func TestOrphanGuardHelper(t *testing.T) {
	if os.Getenv("GROUNDHOLD_ORPHAN_HELPER") != "1" {
		t.Skip("re-exec helper; not run directly")
	}
	cmd := exec.Command("sleep", "120")
	cmd.SysProcAttr = childProcAttr()
	if err := cmd.Start(); err != nil {
		os.Exit(3)
	}
	_ = os.WriteFile(os.Getenv("GROUNDHOLD_ORPHAN_PIDFILE"),
		[]byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
	select {} // block until this process is killed by the parent test
}

// The orphan fix, proven end to end (Linux): a converge child must DIE when its
// parent is killed — never survive as an orphan still holding the lease. Re-execs
// the test binary as the "converge" parent (running the helper above), reads the
// grandchild "apply" pid, SIGKILLs the parent, and asserts the grandchild is gone.
func TestConvergeChildDiesWhenParentKilled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("parent-death orphan guard (Pdeathsig) is Linux-only")
	}
	pidfile := filepath.Join(t.TempDir(), "grandchild.pid")
	parent := exec.Command(os.Args[0], "-test.run=^TestOrphanGuardHelper$")
	parent.Env = append(os.Environ(),
		"GROUNDHOLD_ORPHAN_HELPER=1", "GROUNDHOLD_ORPHAN_PIDFILE="+pidfile)
	if err := parent.Start(); err != nil {
		t.Fatalf("start helper parent: %v", err)
	}

	gpid := 0
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if b, err := os.ReadFile(pidfile); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 {
				gpid = n
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if gpid == 0 {
		_ = parent.Process.Kill()
		t.Fatal("helper never reported a grandchild pid")
	}

	// kill the parent (the "converge"); the grandchild ("apply") must not outlive it
	if err := parent.Process.Kill(); err != nil {
		t.Fatalf("kill parent: %v", err)
	}
	_, _ = parent.Process.Wait()

	died := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if processGoneOrZombie(gpid) {
			died = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !died {
		_ = syscall.Kill(gpid, syscall.SIGKILL) // cleanup a real failure
		t.Fatalf("grandchild %d survived its parent's death — orphan guard failed", gpid)
	}
}

// processGoneOrZombie reports whether a pid no longer exists as a live process. A
// zombie (state Z, reaped shortly by the subreaper) counts as gone — the child is
// dead, only its exit status lingers.
func processGoneOrZombie(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true // no /proc entry — the process is gone
	}
	s := string(b)
	if i := strings.LastIndexByte(s, ')'); i >= 0 && i+2 < len(s) {
		return s[i+2] == 'Z'
	}
	return false
}
