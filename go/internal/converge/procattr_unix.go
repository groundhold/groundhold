//go:build unix && !linux

package converge

import "syscall"

// childProcAttr on non-Linux unix (darwin/bsd — dev/CI, not production) isolates
// the child into its own process group. The parent-death orphan guard proper
// (Pdeathsig) is Linux-only, so on these platforms the guard is Setpgid alone; the
// full guarantee holds where production runs (Linux). Honest boundary, not silent.
func childProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
