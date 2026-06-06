//go:build windows

package pulse

import (
	"os/exec"
	"syscall"
)

const createNoWindow = 0x08000000

func setCoreProcessOptions(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
}
