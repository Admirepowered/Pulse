package pulse

import "testing"

func TestVersionGreaterUsesPBuildFirst(t *testing.T) {
	tests := []struct {
		name    string
		latest  string
		current string
		want    bool
	}{
		{name: "plain p newer", latest: "P66", current: "P65", want: true},
		{name: "plain p older", latest: "P64", current: "P65", want: false},
		{name: "tagged p newer", latest: "0.1.1-P66", current: "P65", want: true},
		{name: "tagged p older", latest: "0.2.0-P64", current: "P65", want: false},
		{name: "both tagged p newer", latest: "0.1.2-P66", current: "0.1.1-P65", want: true},
		{name: "semver fallback", latest: "0.1.2", current: "0.1.1", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionGreater(tt.latest, tt.current); got != tt.want {
				t.Fatalf("versionGreater(%q, %q) = %t, want %t", tt.latest, tt.current, got, tt.want)
			}
		})
	}
}

func TestUpdateVersionFromArchiveAsset(t *testing.T) {
	tests := map[string]string{
		"Pulse-P66-windows-amd64.exe.zip":             "P66",
		"Pulse-0.1.1-P66-linux-ubuntu24-amd64.tar.gz": "0.1.1-P66",
		"Pulse-0.1.1-P66-darwin-arm64.zip":            "0.1.1-P66",
	}
	for asset, want := range tests {
		if got := updateVersionFromAsset(asset, "v0.1.0"); got != want {
			t.Fatalf("updateVersionFromAsset(%q) = %q, want %q", asset, got, want)
		}
	}
}
