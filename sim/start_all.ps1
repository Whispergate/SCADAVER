#Requires -RunAsAdministrator
# Launch all ICS simulators. Ports 80, 102, 502 require Administrator.

$sim = $PSScriptRoot

Write-Host "Installing Python dependencies..."
pip install -r "$sim\requirements.txt"

Write-Host "Launching simulators..."
Start-Process powershell "-NoExit -Command python `"$sim\modbus_sim.py`""
Start-Process powershell "-NoExit -Command python `"$sim\slmp_sim.py`""
Start-Process powershell "-NoExit -Command python `"$sim\siemens_sim.py`""
Start-Process powershell "-NoExit -Command python `"$sim\ewon_sim.py`""

Write-Host ""
Write-Host "All simulators launched in separate windows."
Write-Host ""
Write-Host "  Modbus  TCP 502  -> vendor: Schneider, exploit 'Read Holding Registers 0:10'"
Write-Host "  SLMP    TCP 5007 -> vendor: Mitsubishi, exploit 'Read D Registers 0:10'"
Write-Host "  Siemens TCP 102  -> vendor: Siemens,   exploit 'Read I/O' (0xAA bit pattern)"
Write-Host "  eWON    TCP 80   -> vendor: eWON,      exploit 'Extract Credentials adm:5'"
Write-Host ""
Write-Host "Use separate loopback IPs to add multiple vendors to scadaver-rs:"
Write-Host "  netsh interface ipv4 add address 'Loopback Pseudo-Interface 1' 127.0.0.2"
Write-Host "  netsh interface ipv4 add address 'Loopback Pseudo-Interface 1' 127.0.0.3"
Write-Host "  netsh interface ipv4 add address 'Loopback Pseudo-Interface 1' 127.0.0.4"
