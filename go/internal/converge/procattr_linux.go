//go:build linux

package converge

import "syscall"

// childProcAttr isolates a converge child into its own process group (Setpgid) and
// asks the kernel to SIGKILL it the moment THIS process dies for any reason
// (Pdeathsig) — the orphan guard. A killed converge (terminated CronJob pod,
// SIGKILL, crash) therefore cannot leave an `apply` mutating headless while still
// holding the lease. A hard kill is safe by construction: apply is write-ahead +
// resumable (D42/D57), so an interrupted child is reconciled by resume, never
// corrupt — which is also why the documented Pdeathsig thread-exit caveat (a rare
// premature kill) is harmless here: the worst case is a resumable interruption.
func childProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
