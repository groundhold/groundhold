//go:build !unix

package converge

import "syscall"

// childProcAttr is a no-op on non-unix platforms (no Setpgid/Pdeathsig). The
// orphan guard is a unix/Linux facility; the runtime targets Linux (production)
// and darwin (dev/CI). Returning nil keeps the package building everywhere.
func childProcAttr() *syscall.SysProcAttr {
	return nil
}
