# SPDX-License-Identifier: MIT
# Memory density (Windows / WHP): start N idle microVMs, measure what each
# costs, kill them.
#   tools\density.ps1 -N 20 -- --kernel guest\kernel\out\vmlinux --quiet --ws ws.txt
# Each guest runs `/init hold` (kernel cmdline "-- hold"): it boots, reports,
# then idles like a long-running container.
#
# Reported per VM:
#   ws_private  private working set of the VMM process (guest RAM it touched
#               + the VMM itself); what the VM really pins in host RAM
#   ws_shared   shareable part of the working set (exe/DLL pages)
#   commit      commit charge (guest RAM is committed but demand-zeroed)
#   avail_drop  drop in system-wide available memory / N: also catches what
#               no process shows, e.g. hypervisor SLAT tables and VP state
#   cpu         CPU used per VM over the measuring window while idle
[CmdletBinding(PositionalBinding = $false)]
param(
    [int]$N = 10,
    [string]$Exe = "build\microvm.exe",
    [int]$SettleSeconds = 3,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$VmArgs
)
$ErrorActionPreference = "Stop"
$VmArgs = @($VmArgs | Where-Object { $_ -ne "--" })
if (-not $VmArgs) { $VmArgs = @("--kernel", "guest\kernel\out\vmlinux", "--quiet") }
$argline = (($VmArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ') + ' --append "-- hold"'
$exePath = (Resolve-Path $Exe).Path
$tmp = Join-Path $env:TEMP ("mvm-density-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null

function Avail-MB { (Get-Counter '\Memory\Available MBytes').CounterSamples[0].CookedValue }

[System.GC]::Collect()
Start-Sleep -Milliseconds 500
$before = (1..3 | ForEach-Object { Avail-MB; Start-Sleep -Milliseconds 200 } | Measure-Object -Average).Average

$procs = @()
try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $N; $i++) {
        $procs += Start-Process -FilePath $exePath -ArgumentList $argline -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput (Join-Path $tmp "out$i.txt") -RedirectStandardError (Join-Path $tmp "err$i.txt")
    }
    # Wait until every guest reached /init.
    $deadline = (Get-Date).AddSeconds(30)
    for ($i = 0; $i -lt $N; $i++) {
        while (-not (Select-String -Path (Join-Path $tmp "out$i.txt") -Pattern "hello from /init" -Quiet -ErrorAction SilentlyContinue)) {
            if ($procs[$i].HasExited) { throw "VM $i exited early: $(Get-Content (Join-Path $tmp "err$i.txt") -Raw)" }
            if ((Get-Date) -gt $deadline) { throw "VM $i did not reach /init" }
            Start-Sleep -Milliseconds 20
        }
    }
    $allUp = $sw.Elapsed.TotalMilliseconds
    Start-Sleep -Seconds $SettleSeconds

    $cpu0 = ($procs | ForEach-Object { $_.Refresh(); $_.TotalProcessorTime.TotalMilliseconds } | Measure-Object -Sum).Sum
    $t0 = [System.Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Seconds 2
    $cpu1 = ($procs | ForEach-Object { $_.Refresh(); $_.TotalProcessorTime.TotalMilliseconds } | Measure-Object -Sum).Sum
    $window = $t0.Elapsed.TotalMilliseconds

    $after = (1..3 | ForEach-Object { Avail-MB; Start-Sleep -Milliseconds 200 } | Measure-Object -Average).Average
    $ids = @{}
    foreach ($p in $procs) { $ids[[int]$p.Id] = $true }
    $wsPriv = 0.0
    foreach ($s in (Get-CimInstance Win32_PerfRawData_PerfProc_Process -Filter "Name like 'microvm%'")) {
        if ($ids.ContainsKey([int]$s.IDProcess)) { $wsPriv += [double]$s.WorkingSetPrivate }
    }
    $ws = ($procs | ForEach-Object { $_.Refresh(); $_.WorkingSet64 } | Measure-Object -Sum).Sum
    $commit = ($procs | ForEach-Object { $_.PrivateMemorySize64 } | Measure-Object -Sum).Sum

    "{0} idle microVMs, all at /init after {1:N0} ms (started back to back)" -f $N, $allUp
    "per VM:"
    "  ws_private  {0,8:N1} MB" -f ($wsPriv / $N / 1MB)
    "  ws_shared   {0,8:N1} MB" -f (($ws - $wsPriv) / $N / 1MB)
    "  commit      {0,8:N1} MB" -f ($commit / $N / 1MB)
    "  avail_drop  {0,8:N1} MB" -f (($before - $after) / $N)
    "  cpu         {0,8:N2} % of a core while idle" -f (($cpu1 - $cpu0) / $window * 100 / $N)
}
finally {
    foreach ($p in $procs) { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
    Start-Sleep -Milliseconds 300
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
