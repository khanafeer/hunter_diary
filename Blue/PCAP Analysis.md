# PCAP Analysis



## Wireshark

**general Filters**

```python
ip.addr eq 192.168.10.195 and ip.addr == 192.168.10.1
http.request && ip.addr == 192.168.10.195
http.request || http.response
dns.qry.name contains microsoft or dns.qry.name contains windows
    
    
http.request or ssl.handshake.type == 1.

udp && ip.src == 192.168.1.26 & ip.dst == 24.39.217.246
```

**USB**

```
usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)
```



## Brim

 [Brim](https://github.com/brimsec/brim) to convert large PCAPs to zeek logs

```bash
_path="dns" | count() by query

172.16.165.132 _path="files"
```



## CapTipper

CapTipper is a python tool to analyze, explore and revive HTTP malicious traffic.
CapTipper sets up a web server that acts exactly as the server in the PCAP file,and contains internal tools, with a powerful interactive console, for analysis and inspection of the hosts, objects and conversations found.

```bash
# sudo python CapTipper.py https.pcapng 
CT> hosts
CT> head 0
CT> body 0
CT> dump all c:\NuclearFiles -e
CT> ziplist 13
```



## Online Tools

https://github.com/omriher/CapTipper