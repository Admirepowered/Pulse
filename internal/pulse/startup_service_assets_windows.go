//go:build windows && !pulse_embed_mihomo

package pulse

import "embed"

//go:embed assets/PulseStartupService.exe
var startupServiceAssets embed.FS
