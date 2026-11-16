# SPDX-License-Identifier: MIT
# Cold-start benchmark (Windows / WHP). Every run is a fresh process.
#   tools\bench.ps1 -N 50 -- --kernel guest\kernel\out\vmlinux --quiet
# Reports p50 / p90 / p99 for each MVMTRACE field plus wall-clock process time.
[CmdletBinding(PositionalBinding = $false)]
param(
    [int]$N = 50,
    [string]$Exe = "build\microvm.exe",
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$VmArgs
)
$ErrorActionPreference = "Stop"
if (-not $VmArgs) { $VmArgs = @("--hello") }
$VmArgs = @($VmArgs | Where-Object { $_ -ne "--" }) + @("--trace")

$samples = @{}
function Add-Sample($k, [double]$v) {
    if (-not $samples.ContainsKey($k)) { $samples[$k] = New-Object System.Collections.Generic.List[double] }
    $samples[$k].Add($v)
}

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = (Resolve-Path $Exe).Path
$psi.Arguments = ($VmArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
$psi.UseShellExecute = $false
$psi.RedirectStandardError = $true
$psi.RedirectStandardOutput = $true

for ($i = 0; $i -lt $N; $i++) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = [System.Diagnostics.Process]::Start($psi)
    $err = $p.StandardError.ReadToEnd()
    $null = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()
    $sw.Stop()
    if ($p.ExitCode -ne 0) { throw "run $i exited with $($p.ExitCode): $err" }
    Add-Sample "wall_us" ($sw.Elapsed.TotalMilliseconds * 1000)
    $line = ($err -split "`n" | Where-Object { $_ -like "MVMTRACE*" } | Select-Object -Last 1)
    foreach ($kv in ($line -split ' ')) {
        if ($kv -match '^([a-z0-9_]+)=([0-9.]+)$') { Add-Sample $Matches[1] ([double]$Matches[2]) }
    }
}

function Pct($list, $p) {
    $s = $list | Sort-Object
    $idx = [Math]::Min($s.Count - 1, [Math]::Floor($p * ($s.Count - 1) + 0.5))
    return $s[$idx]
}
"{0} runs: {1} {2}" -f $N, $Exe, ($VmArgs -join ' ')
"{0,-14} {1,12} {2,12} {3,12}" -f "metric", "p50", "p90", "p99"
foreach ($k in ($samples.Keys | Sort-Object)) {
    $l = $samples[$k]
    "{0,-14} {1,12:N1} {2,12:N1} {3,12:N1}" -f $k, (Pct $l 0.5), (Pct $l 0.9), (Pct $l 0.99)
}
