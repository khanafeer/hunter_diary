# PenTenting Tips

### General Tips

- If you enumerated all ports with no vulns, Back to port scan there is a missing port.
- 



### FootHold - Windows

- Open SMB `smbclien -N -L`
- Leaked credentials on other services.
- Vulnerable Web app.
- 



### PrivEsc - Windows

- Run winPEAS.bat on target.
- Check for user permissions `whoami /priv`
- Check User group `net user s.smith`
- Always check for listining services `netstat -ano | findstr LISTENING`
- If AD -- Run bloodhound 
- Check if any SYSTEM service try to connect to editable UNC path, So we could run responder to grep tha NTLM hash
- Check Powershell history USER/AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
- Check Installed apps on `\Program Files\` for vulnerable one.
- Check CVEs for network services.



### PrivEsc - Linux

- Kernel and distribution release details
- System Information:
  - Hostname
  - Networking details:
  - Current IP
  - Default route details
  - DNS server information
- User Information:
  - Current user details
  - Last logged on users
  - Shows users logged onto the host
  - List all users including uid/gid information
  - List root accounts
  - Extracts password policies and hash storage method information
  - Checks umask value
  - Checks if password hashes are stored in /etc/passwd
  - Extract full details for 'default' uid's such as 0, 1000, 1001 etc
  - Attempt to read restricted files i.e. /etc/shadow
  - List current users history files (i.e .bash_history, .nano_history, .mysql_history , etc.)
  - Basic SSH checks
- Privileged access:
  - Which users have recently used sudo
  - Determine if /etc/sudoers is accessible
  - Determine if the current user has Sudo access without a password
  - Are known 'good' breakout binaries available via Sudo (i.e. nmap, vim etc.)
  - Is root's home directory accessible
  - List permissions for /home/
- Environmental:
  - Display current $PATH
  - Displays env information
- Jobs/Tasks:
  - List all cron jobs
  - Locate all world-writable cron jobs
  - Locate cron jobs owned by other users of the system
  - List the active and inactive systemd timers
- Services:
  - List network connections (TCP & UDP)
  - List running processes
  - Lookup and list process binaries and associated permissions
  - List inetd.conf/xined.conf contents and associated binary file permissions
  - List init.d binary permissions
- Version Information (of the following):
  - Sudo
  - MYSQL
  - Postgres
  - Apache
    - Checks user config
    - Shows enabled modules
    - Checks for htpasswd files
    - View www directories
- Default/Weak Credentials:
  - Checks for default/weak Postgres accounts
  - Checks for default/weak MYSQL accounts
- Searches:
  - Locate all SUID/GUID files
  - Locate all world-writable SUID/GUID files
  - Locate all SUID/GUID files owned by root
  - Locate 'interesting' SUID/GUID files (i.e. nmap, vim etc)
  - Locate files with POSIX capabilities
  - List all world-writable files
  - Find/list all accessible *.plan files and display contents
  - Find/list all accessible *.rhosts files and display contents
  - Show NFS server details
  - Locate *.conf and *.log files containing keyword supplied at script runtime
  - List all *.conf files located in /etc
  - Locate mail
- Platform/software specific tests:
  - Checks to determine if we're in a Docker container
  - Checks to see if the host has Docker installed
  - Checks to determine if we're in an LXC container

