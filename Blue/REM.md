# RE Malwares

[TOC]

## Executables

### Basic Static Analysis

- Identify language (PEiD.exe, EXEinfo)
- Check Strings
- PE Headers (PEView, CFF, )
- Import table
- Resource Section
- On Remnux use, peframe -- signsrch -- pescanner

### Static Code Analysis

- Analyzing Source Code (IDA Pro, )



### Dynamic Analysis

- Debugging Application



### Behavioral Analysis

- Monitoring Registry, Processes, APIs, Autoruns (sysinternals)
- Sandboxing
- Network Analysis



### Executable Case Study

**Identification Phase**

```
use PEid to check language, If packed unpack
```

**Basic Static Phase**

```powershell
1. strings.exe <mal.exe> OR floss.exe <mal.exe> #for strings and stack strings
2. #PE header, import and export table
3. resourceHacker.exe #check resources
```

**Behavioral Phase**

```powershell
1. Analyze Network Communication and requested domains
2. get files created and modified, registry, mutexes, processes created or accessed
3. check APIs got called
4. get memory dump (to bypass packing/encryption)
```

**Code Analysis**

```powershell
1. Search for interesting functions (upload, download, C2, ...)
```



## MalDocs

### Tools

```
pip install XLMMacroDeobfuscator
pip install msoffcrypto-tool
```

### Examples

```sql
oledir sheet.xls

msoffcrypto-tool document.doc --test -v
msoffcrypto-tool document.xls --password VelvetSweatshop

 olevba.exe .\sample.bin > vba.txt 
```



**show all hidden sheets**

```vb
Sub ShowAllSheets()
    Dim sh As Worksheet
    For Each sh In ActiveWorkbook.Sheets
    sh.Visible = True
    Next
End Sub
```





