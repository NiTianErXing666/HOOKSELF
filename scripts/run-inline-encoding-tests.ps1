[CmdletBinding()]
param(
    [string]$Serial = $env:ANDROID_SERIAL,
    [switch]$SkipUbsan
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $File"
    }
}

function Resolve-AndroidSdk {
    if (-not [string]::IsNullOrWhiteSpace($env:ANDROID_SDK_ROOT)) {
        return $env:ANDROID_SDK_ROOT
    }
    $propertiesPath = Join-Path $RepoRoot "local.properties"
    $properties = Get-Content -Raw $propertiesPath
    $match = [regex]::Match($properties, "(?m)^sdk\.dir=(.+)$")
    if (-not $match.Success) {
        throw "sdk.dir is missing from local.properties"
    }
    $value = $match.Groups[1].Value.Trim()
    $value = $value -replace "\\:", ":"
    return $value -replace "\\\\", "\"
}

$SdkRoot = Resolve-AndroidSdk
$libraryGradle = Get-Content -Raw (Join-Path $RepoRoot "hookself/build.gradle")
$ndkMatch = [regex]::Match($libraryGradle, "ndkVersion\s+'([^']+)'")
if (-not $ndkMatch.Success) {
    throw "ndkVersion is missing from hookself/build.gradle"
}
$NdkVersion = $ndkMatch.Groups[1].Value
$Toolchain = Join-Path $SdkRoot "ndk/$NdkVersion/toolchains/llvm/prebuilt/windows-x86_64/bin"
$Clang = Join-Path $Toolchain "clang++.exe"
$Adb = Join-Path $SdkRoot "platform-tools/adb.exe"
if (-not (Test-Path -LiteralPath $Clang)) {
    throw "NDK clang was not found: $Clang"
}
if (-not (Test-Path -LiteralPath $Adb)) {
    throw "adb was not found: $Adb"
}

$CppRoot = Join-Path $RepoRoot "hookself/src/main/cpp"
$OutputDir = Join-Path $RepoRoot "hookself/build/inline-tests"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$Sources = @(
    (Join-Path $CppRoot "inline_hook/tests/arm64_encoding_relocator_test.cpp"),
    (Join-Path $CppRoot "inline_hook/internal/arm64_encoding.cpp"),
    (Join-Path $CppRoot "inline_hook/internal/arm64_relocator.cpp"),
    (Join-Path $CppRoot "inline_hook/internal/memory.cpp")
)
$Common = @(
    "--target=aarch64-linux-android24",
    "-std=c++17",
    "-fPIE",
    "-pie",
    "-nostdlib++",
    "-Wall",
    "-Wextra",
    "-Wconversion",
    "-Wsign-conversion",
    "-Wshadow",
    "-Wundef",
    "-Werror",
    "-I$CppRoot",
    "-I$(Join-Path $CppRoot 'inline_hook/include')"
) + $Sources
$AdbPrefix = @()
if (-not [string]::IsNullOrWhiteSpace($Serial)) {
    $AdbPrefix = @("-s", $Serial)
}

function Build-And-Run {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string[]]$ExtraArguments
    )
    $local = Join-Path $OutputDir $Name
    $remote = "/data/local/tmp/$Name"
    Invoke-Checked $Clang ($Common + $ExtraArguments + @("-o", $local))
    try {
        Invoke-Checked $Adb ($AdbPrefix + @("push", $local, $remote))
        Invoke-Checked $Adb ($AdbPrefix + @("shell", "chmod", "700", $remote))
        Invoke-Checked $Adb ($AdbPrefix + @("shell", $remote))
    } finally {
        & $Adb @AdbPrefix shell rm -f $remote | Out-Null
    }
}

Build-And-Run "hookself_inline_encoding_test" @("-O2")
if (-not $SkipUbsan) {
    Build-And-Run "hookself_inline_encoding_test_ubsan" @(
        "-O1",
        "-g",
        "-fsanitize=undefined",
        "-fno-sanitize=vptr",
        "-fsanitize-minimal-runtime",
        "-fno-sanitize-recover=all",
        "-static-libsan"
    )
}
