param(
    [string]$Version = "",
    [string]$VersionCode = "",
    [string]$AndroidHome = "/opt/android-sdk",
    [string]$AndroidNdkHome = "/mnt/e/Tools/android-ndk-r23c",
    [string]$Distro = "",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$projectPath = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$windowsProjectPath = $projectPath -replace "\\", "/"
$wslProjectPath = (wsl wslpath -a "$windowsProjectPath").Trim()

$makeArgs = @()
if ($DryRun) {
    $makeArgs += "-n"
}
$makeArgs += "build-android"
if ($Version) {
    $makeArgs += "VERSION=$Version"
}
if ($VersionCode) {
    $makeArgs += "ANDROID_VERSION_CODE=$VersionCode"
}

$escapedMakeArgs = ($makeArgs | ForEach-Object { "'" + ($_ -replace "'", "'\''") + "'" }) -join " "
$command = @"
set -euo pipefail
export ANDROID_HOME='$AndroidHome'
export ANDROID_SDK_ROOT='$AndroidHome'
export ANDROID_NDK_HOME='$AndroidNdkHome'
export ANDROID_NDK_ROOT='$AndroidNdkHome'
cd '$wslProjectPath'
chmod +x android/gradlew android/native/build-android.sh android/native/collect-binaries.sh
make $escapedMakeArgs
"@

$wslArgs = @()
if ($Distro) {
    $wslArgs += @("-d", $Distro)
}
$wslArgs += @("bash", "-lc", $command)

wsl @wslArgs
