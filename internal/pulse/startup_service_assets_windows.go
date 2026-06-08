//go:build windows

package pulse

import "embed"

//go:embed assets
var startupServiceAssets embed.FS
