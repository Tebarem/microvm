# SPDX-License-Identifier: MIT
# Interleaved A/B cold-start comparison (Windows / WHP). Runs A and B
# alternately so CPU clock and background-load drift hit both equally.
#   tools\ab.ps1 -N 40 -A "--kernel guest\kernel\out\vmlinux --quiet" `
#                      -B "--kernel guest\kernel\out\vmlinux --quiet --ws ws.txt"
# Reports min / p50 / p90 per MVMTRACE timing field, and the p50 delta.
[CmdletBinding(PositionalBinding = $false)]
param(
    [int]$N = 40,
    [string]$Exe = "build\microvm.exe",
    [string]$ExeB = "",  # binary for B (default: same as A), to compare VMM builds
    [Parameter(Mandatory = $true)][string]$A,
    [Parameter(Mandatory = $true)][string]$B,
    [string[]]$Metrics = @("total_us", "setup_us", "guest_us", "vm_us", "prefault_us", "load_us", "wall_us")
)
$ErrorActionPreference = "Stop"
$exePath = @{ A = (Resolve-Path $Exe).Path; B = (Resolve-Path $(if ($ExeB) { $ExeB } else { $Exe })).Path }
$samples = @{ A = @{}; B = @{} }

function Run-One($label, $argline) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exePath[$label]
    $psi.Arguments = "--trace $argline"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardOutput = $true
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = [System.Diagnostics.Process]::Start($psi)
    $err = $p.StandardError.ReadToEnd()
    $null = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()
    $sw.Stop()
    if ($p.ExitCode -ne 0) { throw "$label exited with $($p.ExitCode): $err" }
    $s = $samples[$label]
    $kvs = @{ wall_us = $sw.Elapsed.TotalMilliseconds * 1000 }
    $line = ($err -split "`n" | Where-Object { $_ -like "MVMTRACE*" } | Select-Object -Last 1)
    foreach ($kv in ($line -split ' ')) {
        if ($kv -match '^([a-z0-9_]+)=([0-9.]+)$') { $kvs[$Matches[1]] = [double]$Matches[2] }
    }
    foreach ($k in $kvs.Keys) {
        if (-not $s.ContainsKey($k)) { $s[$k] = New-Object System.Collections.Generic.List[double] }
        $s[$k].Add($kvs[$k])
    }
}

for ($i = 0; $i -lt $N; $i++) {
    if ($i % 2) { Run-One "B" $B; Run-One "A" $A } else { Run-One "A" $A; Run-One "B" $B }
}

function Pct($list, $p) {
    $s = $list | Sort-Object
    $idx = [Math]::Min($s.Count - 1, [Math]::Floor($p * ($s.Count - 1) + 0.5))
    return $s[$idx]
}
"{0} interleaved runs each" -f $N
"A: $A"
"B: $B"
"{0,-12} {1,9} {2,9} {3,9} | {4,9} {5,9} {6,9} | {7,9}" -f "metric", "A min", "A p50", "A p90", "B min", "B p50", "B p90", "B-A p50"
foreach ($k in $Metrics) {
    if (-not $samples.A.ContainsKey($k) -or -not $samples.B.ContainsKey($k)) { continue }
    $sa = $samples.A[$k]; $sb = $samples.B[$k]
    $am = ($sa | Measure-Object -Minimum).Minimum; $bm = ($sb | Measure-Object -Minimum).Minimum
    $a5 = Pct $sa 0.5; $b5 = Pct $sb 0.5
    "{0,-12} {1,9:N0} {2,9:N0} {3,9:N0} | {4,9:N0} {5,9:N0} {6,9:N0} | {7,9:N0}" -f $k, $am, $a5, (Pct $sa 0.9), $bm, $b5, (Pct $sb 0.9), ($b5 - $a5)
}
