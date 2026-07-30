param(
    [ValidateSet("canonical", "high")]
    [string]$Profile = "high",
    [string]$HostAddress = "0.0.0.0",
    [int]$ModbusPort = 0,
    [int]$SlmpPort = 0,
    [int]$BeckhoffAdsPort = 0,
    [int]$BeckhoffDiscoveryPort = 0,
    [int]$SiemensPort = 0,
    [int]$EwonPort = 0,
    [switch]$InstallDeps,
    [switch]$DryRun
)

$sim = $PSScriptRoot
$runnerArgs = @(
    "$sim\run_all.py",
    "--profile", $Profile,
    "--host", $HostAddress
)

if ($ModbusPort -gt 0) { $runnerArgs += @("--modbus-port", $ModbusPort) }
if ($SlmpPort -gt 0) { $runnerArgs += @("--slmp-port", $SlmpPort) }
if ($BeckhoffAdsPort -gt 0) { $runnerArgs += @("--beckhoff-ads-port", $BeckhoffAdsPort) }
if ($BeckhoffDiscoveryPort -gt 0) { $runnerArgs += @("--beckhoff-discovery-port", $BeckhoffDiscoveryPort) }
if ($SiemensPort -gt 0) { $runnerArgs += @("--siemens-port", $SiemensPort) }
if ($EwonPort -gt 0) { $runnerArgs += @("--ewon-port", $EwonPort) }
if ($InstallDeps) { $runnerArgs += "--install-deps" }
if ($DryRun) { $runnerArgs += "--dry-run" }

Write-Host "Starting SCADAver simulator suite through run_all.py..."
Write-Host "Use -Profile high to avoid privileged ports 80, 102, and 502."
python @runnerArgs
