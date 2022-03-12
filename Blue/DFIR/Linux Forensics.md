## Storage & File System

**Partition Table**

```sh
$ mmls image.raw
$ disktype /dev/sda
```

**Logical Volume**

```sh
$ sudo pvdisplay --maps --foreign --readonly
$ sudo lvdisplay --maps --foreign --readonly
```

**RAID**

```sh
$ mdadm --examine /dev/sda1
```



**File System**

```sh
$ fls -r -p partimage.raw #list all files recursivly and show parent path
$ dumpe2fs -h partimage.raw #superblock’s header information
$ fsstat partimage.raw

$ debugfs -R "ls -drl" partimage.raw
$ debugfs -R "ls -drl /Documents" partimage.raw
```



**Swap File**

```sh
# cat /etc/systemd/system/swapfile.swap
[Swap]
What=/swapfile
# ls -lh /swapfile
-rw------- 1 root root 1.0G 23. Nov 06:24 /swapfile
```



## Files

```sh
$ readelf -n /bin/mplayer
$ ldd /bin/mplayer
$ objdump -p /bin/mplayer |grep NEEDED
```





## Notes

- The DOS/MBR partition type for Linux swap is 0x8200. On GPT systems, the GUID for a Linux swap partition is 0657FD6D­A4AB­43C4­84E5­0933C84B4F4F.  
- A swap partition (or file) contains a hibernation memory image if the
  string S1SUSPEND is found at byte offset 4086 (0xFF6):  