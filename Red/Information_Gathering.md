# Passive Info Gathering

#### Whois

```bash
$ whois megacorpone.com
```

#### [GHDB]( https://www.exploit-db.com/google-hacking-database)

```python
site:megacorpone.com
site:megacorpone.com filetype:php      #only php files
site:megacorpone.com -filetype:html    #Exclude html
site:megacorpone.com intitle: "index of" "parent directory"
    
site:megacorpone.com inurl: /.git
```

#### Source Code

```bash
$ gitleaks -v -r https://github.com/megacorpone/megacorpone.com
```

#### Shodan

```bash
hostname:megacorpone.com port:"22"
```



#### The harvester

```
theharvester -d megacorpone.com -b google
```



**Sublister**

```
./sublist3r.py -d megacorpone.com -t 30
```



# Active Info Gathering 

#### DNS

```bash
$ dnsrecon -d megacorpone.com -t axfr
$ dnsrecon -d megacorpone.com -D ~/list.txt -t brt
$ dnsenum zonetransfer.me
```



#### Network (nmap)

```bash
nmap -sC -sV -oA name <ip>

nmap -sS <ip> #syn scan
nmap -sT <ip> #tcp scan
namp -sU <ip> #udp scan

#scripts
ls /usr/share/nmap/scripts | grep smb
--script=smb-os-discovery
--script=dns-zone-transfer
```



#### Network (masscan)

```bash
masscan -sS --ports 0-65535 10.10.10.209 -e utun2
masscan -sS --ports 0-65535 10.10.10.209 -e utun2 --router-ip 10.10.10.1
```



# Enumeration

**SMb** + **Netbios**

```bash
#NAMP
nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254
nmap --script "vuln" <targetip> -p139,445
nmap --script=smb-check-vulns.nse <targetip> -p445
nmap -v -p 139, 445 --script=smb-os-discovery 10.11.1.227
nmap -v -p 139,445 --script=smb-enum-users 10.1 1.1.5

#smbmap
smbmap -H 192.168.1.13 -R -u Nadine -p L1k3B1gBut7s@W0rk
smbmap -H 192.168.1.13 -R

#smbclient
smbclient -N -L 10.10.10.169
smbclient -L 10.10.10.175 -U EGOTISTICALBANK/administrator
smbclient \\\\<targetip>\\ShareName
smbclient \\\\<targetip>\\ShareName -U john

#enum4linux
enum4linux -a 192.168.1.120

#netbios
nmblookup -A 10.10.10.151
nbtscan 10.10.10.185
```



**RPC**

```bash
\# rpcclient - Connect with a null-session (only works for older windows servers)
rpcclient -U james 10.10.10.52


rpcclient -U "" 192.168.1.105

rpcclient $> srvinfo
rpcclient $> enumdomusers
rpcclient $> enumalsgroups domain
rpcclient $> lookupnames administrators
rpcclient> querydominfo
rpcclient> enumdomusers
rpcclient> queryuser john
rpcclient> enumprinters
```



**NFS**

```bash
#Nmap
nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254
nmap -p 111 --script nfs* 10.11.1.72

#mount shares
sudo mount -o nolock 10.11.1.72:/home ~/home/
sudo mount -t cifs -o //10.11.0.22/Data -o username=Administrator,password=Qwerty09! /mnt/win10_share
```



**SMTP**

```bash

```



**Web**

```bash

```

