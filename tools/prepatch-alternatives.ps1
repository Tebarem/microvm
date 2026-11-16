# SPDX-License-Identifier: MIT
# Pre-patch a freshly built vmlinux's alternatives for this machine's CPU
# (kernel patch 0026). Boots it twice in a VM, stopping just before and just
# after alternative patching, dumps guest memory each time, and has
# guest\kernel\prepatch.py copy what the patching wrote into the image.
#   tools\prepatch-alternatives.ps1 [-Kernel guest\kernel\out\vmlinux] [-Out FILE]
# Without -Out the kernel is pre-patched in place. -Append adds kernel
# arguments to both snapshot boots: pass the ones you will boot with if they
# change CPU features or mitigations, or every boot falls back to patching.
# The result boots anywhere; on another CPU it just patches as usual.
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Exe = "build\microvm.exe",
    [string]$Kernel = "guest\kernel\out\vmlinux",
    [string]$Out = "",
    [string]$Append = "",
    [string]$Python = "python"
)
$ErrorActionPreference = "Stop"
$exePath = (Resolve-Path $Exe).Path
$kernelPath = (Resolve-Path $Kernel).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("mvm-prepatch-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $tmp | Out-Null
try {
    $dumps = @{}
    foreach ($when in "before", "after") {
        $dump = Join-Path $tmp "$when.bin"
        $arg = if ($when -eq "before") { "alt_snapshot=before" } else { "alt_snapshot" }
        if ($Append) { $arg = "$Append $arg" }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $exePath
        $psi.Arguments = "--kernel `"$kernelPath`" --append `"$arg`" --dump-mem `"$dump`""
        $psi.UseShellExecute = $false
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardOutput = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $errTask = $p.StandardError.ReadToEndAsync()
        $log = $p.StandardOutput.ReadToEnd()
        $p.WaitForExit()
        $log += $errTask.Result
        if (-not (Test-Path $dump) -or $log -notmatch "snapshot point $when patching reached") {
            throw "snapshot boot ($when) did not reach its stop point:`n$log"
        }
        $dumps[$when] = $dump
    }
    $target = if ($Out) { $Out } else { $kernelPath }
    if ($Out) { Copy-Item $kernelPath $Out -Force }
    $script = Join-Path $PSScriptRoot "..\guest\kernel\prepatch.py"
    & $Python $script --alternatives $target $dumps["before"] $dumps["after"]
    if ($LASTEXITCODE -ne 0) { throw "prepatch.py failed" }
} finally {
    Remove-Item -Recurse -Force $tmp
}
