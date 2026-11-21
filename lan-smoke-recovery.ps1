param(
    [ValidateSet('Status','Apply','Restore','Watchdog')][string]$Action='Status',
    [string]$StateDir=(Join-Path $env:LOCALAPPDATA 'exitnode\lan-smoke-recovery'),
    [ValidateRange(60,600)][int]$TimeoutSeconds=300
)
$ErrorActionPreference='Stop'
$prefix='31.77.194.253/32'
$statePath=Join-Path $StateDir 'state.json'
$donePath=Join-Path $StateDir 'done'
$readyPath=Join-Path $StateDir 'watchdog.ready'
if(-not ('ExitnodeRecoveryPipe' -as [type])){
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class ExitnodeRecoveryPipe {
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    public static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
}
"@
}
# GPT: use only the documented local VPN API and its minimal pipe access mask.
function Invoke-RecoveryIpc([string]$Method,$Config=$null){
    if($Method -notin @('status.get','config.get','config.set','connection.connect','connection.disconnect')){throw 'Unsupported IPC method'}
    $open=[System.Diagnostics.Stopwatch]::StartNew()
    do{
        $handle=[ExitnodeRecoveryPipe]::CreateFile('\\.\pipe\VpnProjectClient',0x00100083,0,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
        if(-not $handle.IsInvalid){break}
        $errorCode=[Runtime.InteropServices.Marshal]::GetLastWin32Error();$handle.Dispose()
        if($errorCode -notin @(2,231) -or $open.ElapsedMilliseconds -ge 5000){throw ('VPN IPC open failed: '+$errorCode)}
        Start-Sleep -Milliseconds 50
    }while($true)
    $stream=[System.IO.FileStream]::new($handle,[System.IO.FileAccess]::ReadWrite,4096,$false)
    try{
        $request=@{schema_version=1;request_id=('exitnode-recovery-'+[guid]::NewGuid().ToString('N'));method=$Method}
        if($null -ne $Config){$request.config=$Config}
        $body=[System.Text.Encoding]::UTF8.GetBytes(($request|ConvertTo-Json -Compress -Depth 8))
        $head=[BitConverter]::GetBytes([uint32]$body.Length);[Array]::Reverse($head)
        $stream.Write($head,0,4);$stream.Write($body,0,$body.Length);$stream.Flush()
        $head=Read-RecoveryBytes $stream 4;[Array]::Reverse($head);$length=[BitConverter]::ToUInt32($head,0)
        if($length -lt 1 -or $length -gt 65536){throw 'Invalid VPN IPC frame'}
        $body=Read-RecoveryBytes $stream $length
        $response=[System.Text.Encoding]::UTF8.GetString($body)|ConvertFrom-Json
        if($response.error){throw ('VPN IPC: '+$response.error.code+' '+$response.error.message)}
        return $response
    }finally{$stream.Dispose()}
}
# GPT: bound each IPC read so a stalled response cannot freeze recovery indefinitely.
function Read-RecoveryBytes($Stream,[int]$Count){
    $buffer=[byte[]]::new($Count);$offset=0
    while($offset -lt $Count){
        $read=$Stream.ReadAsync($buffer,$offset,$Count-$offset)
        if(-not $read.Wait(5000)){throw 'VPN IPC read timeout'}
        if($read.Result -le 0){throw 'VPN IPC EOF'}
        $offset+=$read.Result
    }
    return ,$buffer
}
# GPT: store only rollback metadata and exclusions, never keys or full VPN settings.
function Write-RecoveryState($State){
    [System.IO.File]::WriteAllText($statePath,($State|ConvertTo-Json -Depth 8),(New-Object System.Text.UTF8Encoding($false)))
}
# GPT: reconnect in finally even if stopping the previous session times out.
function Restart-RecoveryVpn{
    try{
        $null=Invoke-RecoveryIpc 'connection.disconnect'
        $wait=[System.Diagnostics.Stopwatch]::StartNew()
        do{Start-Sleep -Milliseconds 300;$s=(Invoke-RecoveryIpc 'status.get').result}while($s.state -ne 'disconnected' -and $wait.Elapsed.TotalSeconds -lt 12)
    }finally{$null=Invoke-RecoveryIpc 'connection.connect'}
    $wait=[System.Diagnostics.Stopwatch]::StartNew()
    do{Start-Sleep -Milliseconds 500;$s=(Invoke-RecoveryIpc 'status.get').result}while($s.state -ne 'connected' -and $wait.Elapsed.TotalSeconds -lt 40)
    if($s.state -ne 'connected'){throw ('VPN has not reconnected: '+$s.state)}
}
# GPT: remove only this test's added prefix and preserve concurrent unrelated edits.
function Restore-RecoveryState{
    $state=Get-Content -LiteralPath $statePath -Raw -Encoding utf8|ConvertFrom-Json
    $configError=$null;$changed=$false
    try{
        $current=(Invoke-RecoveryIpc 'config.get').config
        if($state.added -and @($current.exclude) -contains $state.prefix){
            $remaining=@($current.exclude|Where-Object {$_ -ne $state.prefix})
            $null=Invoke-RecoveryIpc 'config.set' @{exclude=$remaining};$changed=$true
        }
    }catch{$configError=$_.Exception.Message}
    if($changed){Restart-RecoveryVpn}else{
        $s=(Invoke-RecoveryIpc 'status.get').result
        if($s.state -ne 'connected'){$null=Invoke-RecoveryIpc 'connection.connect';$wait=[System.Diagnostics.Stopwatch]::StartNew();do{Start-Sleep -Milliseconds 500;$s=(Invoke-RecoveryIpc 'status.get').result}while($s.state -ne 'connected' -and $wait.Elapsed.TotalSeconds -lt 40);if($s.state -ne 'connected'){throw 'VPN recovery is not confirmed'}}
    }
    if($configError){throw $configError}
    $state.restored_utc=[DateTime]::UtcNow.ToString('o');Write-RecoveryState $state
    [System.IO.File]::WriteAllText($donePath,'restored',(New-Object System.Text.UTF8Encoding($false)))
    return [PSCustomObject]@{restored=$true;removed_prefix=$changed;vpn='connected'}
}
if($Action -eq 'Status'){
    $s=(Invoke-RecoveryIpc 'status.get').result;$c=(Invoke-RecoveryIpc 'config.get').config
    [PSCustomObject]@{vpn=$s.state;desired=$s.desired_state;exclude=@($c.exclude);state_dir=$StateDir}|ConvertTo-Json -Compress
    exit 0
}
if($Action -eq 'Watchdog'){
    [System.IO.File]::WriteAllText($readyPath,[string]$PID,(New-Object System.Text.UTF8Encoding($false)))
    $stoppedSince=$null
    while(-not (Test-Path -LiteralPath $donePath)){
        $state=Get-Content -LiteralPath $statePath -Raw -Encoding utf8|ConvertFrom-Json
        # GPT: numeric UTC deadlines survive PowerShell JSON date conversion and locale changes.
        if([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -ge [long]$state.expires_unix_ms){
            try{$null=Restore-RecoveryState;break}catch{[System.IO.File]::WriteAllText((Join-Path $StateDir 'watchdog-error.txt'),$_.Exception.Message,(New-Object System.Text.UTF8Encoding($false)))}
        }else{
            try{
                $s=(Invoke-RecoveryIpc 'status.get').result
                if($s.desired_state -ne 'connected'){
                    if($null -eq $stoppedSince){$stoppedSince=[DateTime]::UtcNow}
                    if(([DateTime]::UtcNow-$stoppedSince).TotalSeconds -ge 12){$null=Invoke-RecoveryIpc 'connection.connect';$stoppedSince=$null}
                }else{$stoppedSince=$null}
            }catch{}
        }
        Start-Sleep -Seconds 2
    }
    exit 0
}
if($Action -eq 'Restore'){Restore-RecoveryState|ConvertTo-Json -Compress;exit 0}
$s=(Invoke-RecoveryIpc 'status.get').result
if($s.state -ne 'connected' -or $s.desired_state -ne 'connected'){throw 'Start the existing VPN before applying the test exception'}
if((Test-Path -LiteralPath $statePath) -and -not (Test-Path -LiteralPath $donePath)){throw 'An unfinished recovery run already exists; restore it first'}
[System.IO.Directory]::CreateDirectory($StateDir)|Out-Null
foreach($marker in @($donePath,$readyPath)){if(Test-Path -LiteralPath $marker){Remove-Item -LiteralPath $marker}}
$current=(Invoke-RecoveryIpc 'config.get').config
$old=@($current.exclude);$added=($old -notcontains $prefix)
$state=[ordered]@{prefix=$prefix;original_exclude=$old;added=$added;started_utc=[DateTime]::UtcNow.ToString('o');expires_utc=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds).ToString('o');expires_unix_ms=[DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds).ToUnixTimeMilliseconds();restored_utc=$null}
Write-RecoveryState $state
$hostExe=(Get-Process -Id $PID).Path
$argsText='-NoProfile -File "'+$PSCommandPath+'" -Action Watchdog -StateDir "'+$StateDir+'"'
$watchdog=Start-Process -FilePath $hostExe -ArgumentList $argsText -WindowStyle Hidden -PassThru
$readyWait=[System.Diagnostics.Stopwatch]::StartNew()
while(-not (Test-Path -LiteralPath $readyPath) -and $readyWait.Elapsed.TotalSeconds -lt 5){Start-Sleep -Milliseconds 100}
if(-not (Test-Path -LiteralPath $readyPath)){throw 'Watchdog did not become ready; VPN configuration was not changed'}
try{
    if($added){$null=Invoke-RecoveryIpc 'config.set' @{exclude=@($old+$prefix)}}
    Restart-RecoveryVpn
    [PSCustomObject]@{applied=$true;prefix=$prefix;watchdog_pid=$watchdog.Id;expires_utc=$state.expires_utc;state_dir=$StateDir}|ConvertTo-Json -Compress
}catch{try{$null=Restore-RecoveryState}catch{};throw}
