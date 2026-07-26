//go:build linux

package converge

import (
	"syscall"
	"testing"
)

// On Linux the orphan guard also arms Pdeathsig=SIGKILL: the kernel kills the child
// the instant this process dies, for ANY reason (SIGKILL included) — the core of the
// fix. Pdeathsig is a Linux-only field of syscall.SysProcAttr, so this assertion lives
// in a linux-tagged file; a `//go:build unix` file referencing it fails to COMPILE on
// darwin (the portability matrix caught exactly that).
func TestChildProcAttrPdeathsigOnLinux(t *testing.T) {
	if a := childProcAttr(); a.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("Linux childProcAttr must set Pdeathsig=SIGKILL; got %v", a.Pdeathsig)
	}
}
