$ErrorActionPreference = "Stop"

$count = (git rev-list --count HEAD).Trim()
$tag = (git tag --points-at HEAD --list "v*" | Select-Object -First 1)
if ([string]::IsNullOrWhiteSpace($tag)) {
    $version = "0.0.$count"
} else {
    $version = $tag.TrimStart("v")
}

$ldflags = "-X Pulse/internal/pulse.AppVersion=$version -X Pulse/internal/pulse.BuildNumber=$count"
$artifactName = "Pulse-$version.$count-windows-amd64.exe"
Write-Host "Building Pulse version $version ($count)"
wails build -ldflags $ldflags -o $artifactName @args
