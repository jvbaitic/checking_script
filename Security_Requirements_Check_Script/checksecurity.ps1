<#This a script by JVG to get basic data of the computer
and to make some checking about the quality and the state of the 
security. 
#>

#Ask for path 
#$path = Read-Host -prompt "Enter the path to store the results"

if($args.count -gt 0){
    
    $path = $args[0]
}

else{
    
    $path = Split-Path $script:MyInvocation.MyCommand.Path

}


function writeToFile($array)
{
    $date = Get-Date -Format FileDate
    $computerName=$env:COMPUTERNAME
    $fileName="$computerName`_$date.txt"
    $array | Out-File -FilePath "$path\$fileName" -Encoding UTF8

    Write-Host "Analysis complete"

}

function checkAntiVirusState($antivirusCode)
{
    
    
    switch($antivirusCode)
    {
       393472 {$antivirusState="disabled and up to date";break}

       397584 {$antivirusState="enabled and out of date";break}
 
       397568 {$antivirusState="enabled and up to date";break}

       262144 {$antivirusState="disabled and up to date";break}

       266240 {$antivirusState="enabled and up to date";break}

       266256 {$antivirusState="firewall enabled";break}

       262160 {$antivirusState="firewall disabled";break}

       397312 {$antivirusState="enabled and up to date";break}

       393216 {$antivirusState="disabled and up to date";break}
    }

    return ($antivirusState)
}




function getBasicData{

    Write-Host "Analysing your computer..." 

    $osVersion = (Get-WmiObject Win32_OperatingSystem).version


    $windowsUpdateObject = New-Object -ComObject Microsoft.Update.AutoUpdate
    $lastUpdateDate = $windowsUpdateObject.Results | select -ExpandProperty LastInstallationSuccessDate
    
    $isEnable = $windowsUpdateObject.ServiceEnabled

    $antivirusProductObject= Get-WmiObject -Namespace “root\SecurityCenter2” -Query “SELECT * FROM AntiVirusProduct” 

    $isKasperskyOK = "False"

    foreach($antivirus in $antivirusProductObject)
    {
        if($antivirus.displayName -like '*Kaspersky*') {
          
            if($antivirus.productState -eq 266240)
            {
                   $isKasperskyOK = "True" 
                   $state = checkAntiVirusState($antivirus.productState)
            } 
            else{

                $state = checkAntiVirusState($antivirus.productState)
            
            }
        }
    
    }





    $processor = (Get-WMIObject win32_Processor).name

    $firewallEnabledPri = @(netsh advfirewall show private state)[3] -replace 'Estado' -replace '\s'
    $firewallEnabledPu = @(netsh advfirewall show public state)[3] -replace 'Estado' -replace '\s'
    $firewallEnabledDo = @(netsh advfirewall show domain state)[3] -replace 'Estado' -replace '\s'


    
     
    if($firewallEnabledPri -eq "ACTIVAR" -or $firewallEnabledPu -eq "ACTIVAR" -or $firewallEnabledDo -eq "ACTIVAR")
    {
        $firewallEnabled = "True"
    }
    else
    {
        $firewallEnabled = "False"
    }


    $isKeePassInstalled = ((Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") | Where-Object { $_."Name" -like "*KeePass*" } ).Length -gt 0;
    
    $keypassPath = "C:\Program Files (x86)\KeePass Password Safe 2\KeePass.config.enforced.xml"
    $enforced = Test-Path $keypassPath -PathType Leaf 
    
    
    $officeVersion = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like "*Office*"} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | select -first 1 -ExpandProperty DisplayVersion 

    $currentPrincipal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

    $hasAdminPrivileges=$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   
    $guestAccount = Get-WmiObject -Class Win32_UserAccount -Filter  "Name = 'Invitado'"|Select-Object Disabled | select -first 1 -ExpandProperty Disabled
   
    if($guestAccount)
    {
        $guestAccount = "False"
    }
    else
    {
        $guestAccount = "True"
    }



    $ports=Get-NetTCPConnection -State Listen | Select-Object LocalPort
    $openPorts = @()
    foreach ($port in $ports)

    {
        $writePort = $port.localPort
        $openPorts += "$writePort,"
    }
    
    
    $folders=get-WmiObject -class Win32_Share |Select-Object Name, Path 
    $sharedFolders = @()
    foreach ($folder in $folders)

    {
	
		$folderName = $folder.Name
        $folderPath = $folder.Path

        $sharedFolders +="$folderName`: $folderPath,"
    }





    
    $path = $HOME+"\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"

    $isKeepassTaskBar = (Get-ChildItem -Path $path |  Where-Object { $_."Name" -like "*KeePass*" }).Length -gt 0;


    if($isKeepassTaskBar){

        if($isKeePassInstalled){

            $keepassTaskBar = "KeePass anclado a la barra de tareas"

         }

        else{
             
             $keepassTaskBar = "KeePass anclado a la barra de tareas, ¿¿Portable??"
             $isKeePassInstalled = True;
        
        }
    }

    else{
    
        if($isKeePassInstalled){
    
            $keepassTaskBar = "KeePass instalado, pero no se encuentra anlcado a la barra de tareas"
        }
    }

     $date = Get-Date

     $macIntegrada = Get-WmiObject win32_networkadapterconfiguration | Where-Object{ $_."description" -match "Intel" -and  $_."description" -notmatch "Virtual" }  |select macaddress -ExpandProperty macaddress

     
     $macWlan = Get-WmiObject win32_networkadapterconfiguration | Where-Object{  $_."description" -match "WLAN" -and  $_."description" -notmatch "Virtual" }  |select macaddress -ExpandProperty macaddress

   
   $basicDataArray = @("Computer Name:$env:COMPUTERNAME","Date:$date","OS Version:$osVersion","Last Update Date:$lastUpdateDate", "AutoUpdate Enabled:$isEnable", "Kaspersky:$isKasperskyOK", "State:$state","Processor:$processor", "Firewall:$firewallEnabled","KeePass Instaled:$isKeePassInstalled","KeePass State:$keepassTaskBar", "KeyPass Enforced:$enforced", "Office Version:$officeVersion", "Username:$env:username", "Administrator Privileges:$hasAdminPrivileges","Guest Account Enabled:$guestAccount", "Listening Ports: $openPorts", "Shared Folders:$sharedFolders", "MAC Integrada:$macIntegrada","MAC WLAN:$macWlan")
    
   return $basicDataArray


}

$arrayData=getBasicData
writeToFile($arrayData)












