//go:build windows

package pulse

import (
	"strings"
	"testing"
)

func TestAdminRelaunchPowerShellCommandOmitsEmptyArgumentList(t *testing.T) {
	command := adminRelaunchPowerShellCommand(`E:\Tools\Pulse\Pulse.exe`, `E:\Tools\Pulse`, nil)
	if strings.Contains(command, "-ArgumentList") {
		t.Fatalf("empty args should omit ArgumentList, got %q", command)
	}
	if !strings.Contains(command, "-Verb RunAs") {
		t.Fatalf("command should request elevation, got %q", command)
	}
}

func TestAdminRelaunchPowerShellCommandIncludesArguments(t *testing.T) {
	command := adminRelaunchPowerShellCommand(`E:\Tools\Pulse\Pulse.exe`, `E:\Tools\Pulse`, []string{"clash://install-config?url=https%3A%2F%2Fexample.com"})
	if !strings.Contains(command, "-ArgumentList @(") {
		t.Fatalf("args should include ArgumentList, got %q", command)
	}
	if !strings.Contains(command, "install-config") {
		t.Fatalf("args should be preserved, got %q", command)
	}
}
