//go:build windows

package keymgmt

import "os"

func terminalSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
