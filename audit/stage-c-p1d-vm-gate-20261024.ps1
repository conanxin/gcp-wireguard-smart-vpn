<#
Stage C P1D VM readiness audit. READ-ONLY and HARD NON-MUTATING.
-Mode Audit: read native host facts and report whether a disposable VM can
  be independently verified. No VM creation, installation or feature changes.
-Mode NativeCanary: ALWAYS HARD BLOCKED in this P1D build, exit 60.
No real routes, WireGuard, NRPT, DNS, WinINET, xray, firewall or GCP writes.
#>
[CmdletBinding()]
param([ValidateSet('Audit','NativeCanary')][string]$Mode='Audit')
$ErrorActionPreference='Continue'
function Emit([string]$Key,$Value){Write-Output ($Key+'='+[string]$Value)}
if($Mode -eq 'NativeCanary'){
 Emit 'NATIVE_CANARY_GATE' 'HARD_DISABLED_NO_VM_ATTESTATION'
 Emit 'SYSTEM_NETWORK_MUTATIONS' 'False'
 exit 60
}
Emit 'STAGE' 'C_P1D'
Emit 'AUDIT_MODE' 'READ_ONLY'
Emit 'OBSERVED_AT' ([DateTimeOffset]::Now.ToString('o'))
try{
 $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
 Emit 'OS_CAPTION' $os.Caption
 Emit 'OS_BUILD' $os.BuildNumber
 Emit 'TOTAL_RAM_GB' ([math]::Round($os.TotalVisibleMemorySize/1048576,2))
 Emit 'AVAILABLE_RAM_GB' ([math]::Round($os.FreePhysicalMemory/1048576,2))
 $enough=($os.FreePhysicalMemory/1048576 -ge 4)
 Emit 'FREE_RAM_AT_LEAST_4GB' $enough
}catch{Emit 'OS_MEMORY_CHECK' ('UNAVAILABLE_'+$_.Exception.GetType().Name);$enough=$false}
try{
 $cpu=Get-CimInstance Win32_Processor -ErrorAction Stop|Select-Object -First 1
 Emit 'CPU_NAME' $cpu.Name
 Emit 'VIRTUALIZATION_FIRMWARE_WMI' $cpu.VirtualizationFirmwareEnabled
 Emit 'SLAT_WMI' $cpu.SecondLevelAddressTranslationExtensions
}catch{Emit 'CPU_VIRT_WMI' ('UNAVAILABLE_'+$_.Exception.GetType().Name)}
try{
 $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
 Emit 'COMPUTER_MODEL' $cs.Model
 Emit 'HYPERVISOR_PRESENT_WMI' $cs.HypervisorPresent
}catch{Emit 'COMPUTER_SYSTEM_WMI' ('UNAVAILABLE_'+$_.Exception.GetType().Name)}
foreach($cmd in @('Get-VM','VBoxManage.exe','vmrun.exe','qemu-system-x86_64.exe')){
 Emit ('VM_COMMAND_'+$cmd) ([bool](Get-Command $cmd -ErrorAction SilentlyContinue))
}
if(Get-Command Get-VM -ErrorAction SilentlyContinue){
 try{
  $vms=@(Get-VM -ErrorAction Stop)
  Emit 'HYPERV_VM_COUNT' $vms.Count
  foreach($vm in $vms){Emit 'HYPERV_VM_CANDIDATE' ($vm.Name+'|'+$vm.State)}
 }catch{Emit 'HYPERV_VM_DISCOVERY' ('UNAVAILABLE_'+$_.Exception.GetType().Name)}
}else{Emit 'HYPERV_VM_DISCOVERY' 'COMMAND_UNAVAILABLE'}
Emit 'SNAPSHOT_EXTERNALLY_VERIFIED' 'False'
Emit 'GUEST_IDENTITY_EXTERNALLY_VERIFIED' 'False'
Emit 'VM_NETWORK_ISOLATION_VERIFIED' 'False'
Emit 'REAL_NATIVE_ROUTE_CANARY_AUTHORIZED' 'False'
Emit 'REAL_NATIVE_ROUTE_CANARY_IMPLEMENTED' 'False'
Emit 'VM_TEST_READINESS' 'BLOCKED_UNVERIFIED_ISOLATION'
Emit 'SYSTEM_NETWORK_MUTATIONS' 'False'
exit 0
