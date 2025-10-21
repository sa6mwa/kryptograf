//go:build !windows

package keymgmt

import (
	"os"
	"syscall"
)

func terminalSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT}
}
