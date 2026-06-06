//go:build !windows

package pulse

import "os/exec"

func setCoreProcessOptions(cmd *exec.Cmd) {
}
