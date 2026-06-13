param(
    [string]$Version = "",
    [string]$BuildNumber = "",
    [string]$ServiceNumber = "",
    [string]$Target = "build"
)

$ErrorActionPreference = "Stop"

$makeArgs = @($Target)
if ($Version) {
    $makeArgs += "VERSION=$Version"
}
if ($BuildNumber) {
    $makeArgs += "COUNT=$BuildNumber"
}
if ($ServiceNumber) {
    $makeArgs += "SERVICE_NUMBER=$ServiceNumber"
}

make @makeArgs
