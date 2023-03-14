# Live Examination
Processes

```powershell
wmic process list brief
wmic process list full
wmic process get name,processid
wmic process where processid=pid get commandline
wmic process where "name like '%power'" get name, processid
```

Network Usage

```powershell
netstat -na
netstat -naob
netstat -naob 5
netsh advfirewall show currentprofile
```

