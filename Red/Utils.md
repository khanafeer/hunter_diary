# Compilation 

##### Compiling Windows Exploits on Kali

```bash
  wget -O mingw-get-setup.exe http://sourceforge.net/projects/mingw/files/Installer/mingw-get-setup.exe/download
  wine mingw-get-setup.exe
  select mingw32-base
  cd /root/.wine/drive_c/windows
  wget http://gojhonny.com/misc/mingw_bin.zip && unzip mingw_bin.zip
  cd /root/.wine/drive_c/MinGW/bin
  wine gcc -o ability.exe /tmp/exploit.c -lwsock32
  wine ability.exe  
```



# SSH

```sh
sudo scp nosa@192.168.1.13:/tmp/docker.sh /home/khan/Downloads/docker.sh
```





