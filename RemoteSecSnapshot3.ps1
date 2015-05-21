﻿#**********************************************************************
#  Remote Forensic Snapshot
#
#  Gathers a large amount of detail on a target server and dumps the output to a chosen directory.
#
#  Usage: Modify $ouputroot to reflect desired output path, $scriptdir to where the required tools can be found.
#  RemoteSecSnapshot -Computername [hostname]
#
#  Additional Options:
#   -Full - Runs a suite of additional checks. 
#   -Hashes - Creates hashes of a range of system files. 
#   -TextFileOutput - forces output to text-only instead of xml
#
#  Tools required for this script to run must be in the $scriptdir folder:
#      AUTORUNSC.EXE       http://www.microsoft.com/sysinternals/
#      ACCESSCHK.EXE       http://www.microsoft.com/sysinternals
#      SHA256DEEP.EXE      http://md5deep.sourceforge.net
#**********************************************************************

Param ([String] $ComputerName, [Switch] $TextFileOutput, [Switch] $Full, [Switch] $Hashes)

$credential = get-credential

#These can be edited to suit your purposes
$outputroot="\\domain.whatever\path\to\output"
$scriptdir="\\domain.whatever\path\to\BaselineSnapshot"

#Get the FQDN of the target machine.
$fqdn = [System.Net.Dns]::GetHostByName("$ComputerName") | FL HostName | Out-String | %{ "{0}" -f $_.Split(':')[1].Trim() };

#Get the date in a couple of different formats for making folder names
$datentime=Get-Date
$datentimeshort=Get-Date -Format yyyyMMddHHmm
$year=Get-Date -Format yyyy

#set the main folder name for this run of the script
$foldername="$computername-$datentimeshort"

#set where that folder should be created
$outputpath="$outputroot\$computername\$year\$foldername"

#create a subdir of that folder for the detailed output
$outputdetails="$outputroot\$computername\$year\$foldername\Details"

#find the output from the last run of the script so we can compare the two later.
$lastrunfolder = (get-childitem $outputroot\$computername\$year\ *) | Sort-Object | Select-Object -Last 1
$lastrundetails = "$outputroot\$computername\$year\$lastrunfolder\Details"

# Create target folder for output.
New-Item -Path $outputdetails -ItemType directory

# Create README.TXT file.
ECHO "SYSTEM SNAPSHOT" > $outputpath\README.TXT
ECHO "Run By User: $env:USERNAME@$env:USERDOMAIN" >> $outputpath\README.TXT
ECHO "Run at: $datentime" >> $outputpath\README.txt

#WriteOut Function 
#If the parameter $TextFileOutput = $true, this writes output to text files in a relatively human-readable format. 
#If not, writes them as xml.
Function WriteOut ($FileName) 
    {
    if ($TextFileOutput){ $Input | Format-List * | Out-File -FilePath ($FileName + ".txt") } 
    else { $Input | Select * -ExcludeProperty RunspaceID,Length | Export-Clixml -Path ("$outputdetails\$FileName" + ".xml") } 
    }

$scriptblock = {
Param ($scriptdir, $outputdetails, $hashes, $full, $credential)


#WriteOut Function again because it needs to be on the remote system too.
#If the parameter $TextFileOutput = $true, this writes output to text files in a relatively human-readable format. 
#If not, writes them as xml.
Function WriteOut ($FileName) 
    {
    if ($TextFileOutput){ $Input | Format-List * | Out-File -FilePath ($FileName + ".txt") } 
    else { $Input | Select * -ExcludeProperty RunspaceID,Length | Export-Clixml -Path ("W:\$FileName" + ".xml") } 
    }

New-PSDrive -Name W -PsProvider FileSystem -credential $credential -Root "$outputdetails" -Persist
New-PSDrive -Name X -PsProvider FileSystem -credential $credential -Root "$scriptdir" -Persist

#################################### Config Gathering ##################################

################# WMIC.EXE based checks
Write-Host -foregroundcolor green "Computer System"
wmic.exe computersystem list full | Out-File W:\Computer-Info.txt
Write-Host -foregroundcolor green "BIOS"
wmic.exe bios list full | Out-File W:\BIOS.txt


################ PSexec based checks.
Write-Host -foregroundcolor green "Password And Lockout Policies"
net.exe accounts | Out-File W:\PasswordandLockoutPolicies.txt

Write-Host -foregroundcolor green "Local Audit Policy"
auditpol.exe /get /category:* | Out-File W:\AuditPolicy.txt

Write-Host -foregroundcolor green "SECEDIT Security Policy Export"
secedit.exe /export /cfg W:\SecEdit-Security-Policy.inf

Write-Host -foregroundcolor green "Networking Configuration"
nbtstat.exe -n | Out-File W:\Network-NbtStat.txt

Write-Host -foregroundcolor green "Network, Firewall and IPSec Connection Rules"
netsh.exe winsock show catalog | Out-File W:\Network-WinSock.txt
netsh.exe ipsec static show all | Out-File W:\Network-IPSec-Static.txt
netsh.exe ipsec dynamic show all | Out-File W:\Network-IPSec-Dynamic.txt

Write-Host -foregroundcolor green "Sysinternals AutoRuns"
. X:\autorunsc.exe -accepteula -a * -c -h | Out-File W:\AutoRuns.csv


############### Powershell Cmdlet based checks
Write-Host -foregroundcolor green "Networking Configuration"
Get-NetAdapter -IncludeHidden | WriteOut -FileName Network-Adapters
Get-NetIPAddress | WriteOut -FileName Network-IPaddresses
Get-NetRoute | WriteOut -FileName Network-Route-Table

Write-Host -foregroundcolor green "Windows Firewall and IPSec Connection Rules"
Get-NetConnectionProfile | WriteOut -FileName Network-Connection-Profiles
Get-NetIPsecRule | WriteOut -FileName Network-IPSec-Rules

Write-Host -foregroundcolor green "Drivers"
Get-WmiObject -Class Win32_SystemDriver | WriteOut -FileName Drivers

Write-Host -ForegroundColor green "Services"
Get-WmiObject -Class Win32_Service | select Name, DisplayName, State, PathName, InstallDate, StartMode, StartName, Total-Sessions | WriteOut -FileName Services

Write-Host -foregroundcolor green "Shared Folders"
Get-SmbShare | fl | Out-File W:\Shared-Folders.txt

Write-Host -foregroundcolor green "Environment Variables"
Get-ChildItem Env: | WriteOut -FileName Environment-Variables.txt


############# File Hashing
# If 'Hashes' switch is used, hash all the files in the below paths.
if ($Hashes){
Write-Host -foregroundcolor green "Hashing Files... This will take a long time."
. "X:\sha256deep.exe" -r "$env:SystemDrive\Windows\System32\*" | Out-File W:\Hashes-System32.txt
Write-Host -foregroundcolor green "Still Hashing"
. "X:\sha256deep.exe" -r "$env:SystemDrive\Windows\SysWOW64\*" | Out-File W:\Hashes-SysWow64.txt
Write-Host -foregroundcolor green "Still Hashing"
. "X:\sha256deep.exe" -r "$env:SystemDrive\Windows\Boot\*" | Out-File W:\Hashes-Boot.txt
Write-Host -foregroundcolor green "Still Hashing"
. "X:\sha256deep.exe" -r "$env:ProgramFiles\*" | Out-File W:\Hashes-ProgramFiles.txt
Write-Host -foregroundcolor green "Still Hashing"
. "X:\sha256deep.exe" -r "${env:ProgramFiles(x86)}\*" | Out-File W:\Hashes-ProgramFilesx86.txt
Write-Host -foregroundcolor green "Done Hashing!"
            }

############ Extra Checks
# If 'Full' switch is used, do all this stuff too. 
# These checks generate at least slightly different output every time so can't be automatically checked 
# without generating a lot of false positives.
if ($Full){
Write-Host -foregroundcolor green "Gathering additional data. This may take some time."

# Processes
Get-Process -IncludeUserName | WriteOut -FileName Processes

# Open TCP and UDP Ports
Get-NetTCPConnection -State Listen | Sort LocalPort | WriteOut -FileName Network-TCP-Listening-Ports
Get-NetUDPEndpoint | Sort LocalPort | WriteOut -FileName Network-UDP-Listening-Ports

# Firewall Rules
Get-NetFirewallProfile | WriteOut -FileName Network-Firewall-Profiles
Get-NetFirewallRule | WriteOut -FileName Network-Firewall-Rules

# Find Hidden Files
Get-Childitem -ErrorAction SilentlyContinue -Hidden -Recurse $env:SystemDrive\ | Format-Table -Property Mode,Name | Writeout -FileName SystemHiddenFiles

# Registry Exports (Add more as you wish)
reg.exe export hklm\system\CurrentControlSet W:\Registry-CurrentControlSet.reg /y
reg.exe export hklm\software\microsoft\windows\currentversion W:\Registry-WindowsCurrentVersion.reg /y 
. "X:\accesschk.exe" -accepteula -s -q $env:SystemDrive\ | Out-File W:\FileSystem-NTFS-Permissions.txt
           }


Remove-PSDrive X
Remove-PSDrive W
}

Invoke-Command -ComputerName $fqdn -credential $credential -ScriptBlock $scriptblock -ArgumentList "$scriptdir","$outputdetails",$hashes,$full,$credential


################## Stuff to do locally so we don't risk too much recursion on the remote machine.

#GroupExploder Function - Recursively finds members of groups
$global:users = @()
function groupExploder
{
    param([string]$group, [int]$pad)

    Write-Output ("".padleft($pad) + $group)

    $EXPLOSION = Get-ADGroupMember $group

    foreach($shrapnel in $EXPLOSION)
    {
        try
        {
            $result = Get-ADGroup $shrapnel
            groupExploder $shrapnel.name ($pad + 5) #explode this group in the group \m/ EXPLOSIONS \m/
        }
        catch
        {
            $global:users += $shrapnel.SamAccountName
            $wound = Get-ADUser $shrapnel.SamAccountName
            Write-Output ("".padleft($pad+5) + $wound.samaccountname + " - " + $wound.givenname + " " + $wound.surname + " Enabled: " + $wound.enabled)
        }
    }
}

############## Users and Groups
Write-Host -foregroundcolor green "Local Users"
$ADSIComputer = [ADSI]"WinNT://$computername"
$Users = $ADSIComputer.psbase.Children | Where {$_.psbase.schemaClassName -eq "user"}
$Users | Out-File $outputdetails\LocalUsers.txt

#Get all the local groups
Write-Host -foregroundcolor green "Getting Groups..."
$Groups = $ADSIComputer.psbase.Children | Where {$_.psbase.schemaClassName -eq "group"}

#explode the local groups and member groups
Write-Host -foregroundcolor green "Exploding Groups!"
ForEach ($Group In $Groups)
{
    "Local Group: " + $Group.Name >> $outputdetails\ExplodedGroups.txt
    $Members = @($Group.psbase.Invoke("Members"))
    ForEach ($Member In $Members)
    {
        $Class = $Member.GetType().InvokeMember("Class", 'GetProperty', $Null, $Member, $Null)
        $Name = $Member.GetType().InvokeMember("Name", 'GetProperty', $Null, $Member, $Null)
        "-- Member: $Name ($Class)" >> $outputdetails\ExplodedGroups.txt
        groupexploder $Name 5 2>$null 1>> $outputdetails\ExplodedGroups.txt
    }
} 


#Automatic comparison to the output of the previous run and write it to Compare.txt in the output folder.
$thisrun = @()
$thisrun = (Get-ChildItem -Path $outputdetails -Name)

ForEach ($outputfile in $thisrun) {
    echo "$outputfile" | out-file -append $outputpath\Comparison.txt
    compare-object (get-content "$outputdetails\$outputfile") (get-content "$lastrundetails\$outputfile") | format-list | Out-File -append $outputpath\Comparison.txt
                                   }