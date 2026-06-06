//go:build !windows

package main

import "os/exec"

func setCoreProcessOptions(cmd *exec.Cmd) {
}
