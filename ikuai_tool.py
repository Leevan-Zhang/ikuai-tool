import requests
# from requests import Session
from json import dumps
import json
from hashlib import md5
from base64 import standard_b64encode
from requests import exceptions
import asyncio
import time

class ikuai():
    def __init__(self,ip,username,password,method="http",verify=False):
        # parameters setting
        self.verify=verify
        self.method = method
        self.host = ip
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        })
        def login():
            md = md5()
            md.update(password.encode('UTF-8'))
            url = f"{self.method}://{self.host}/Action/login"
            payload = dumps({
                "username": username,
                "passwd": md.hexdigest(),
                "pass": standard_b64encode(f"salt_11{password}".encode()).decode(),
                "remember_password":"true"
            })
            print(payload)
            response = self.session.post(url=url, data=payload, verify=self.verify)
            if response.status_code==200:
                cookie = response.headers["Set-Cookie"].split(";")[0]+f"; username={username}; login=1"
                # 将字符串格式的 Cookie 转换为字典
                cookies_dict = {}
                for item in cookie.split(";"):
                    key, value = item.strip().split("=", 1) # 以第一个等号分割
                    cookies_dict[key] = value
                from requests.utils import cookiejar_from_dict
                # 将字典转换为 RequestsCookieJar 对象
                cookies_jar = cookiejar_from_dict(cookies_dict)

                # 将 Cookies 设置到 Session 中
                self.session.cookies=cookies_jar
                print("Login Successed ! ")
            else:
                print("Login failed ! HTTP CODE : ",response.status_code)
                print(response.text)
                raise exceptions.HTTPError(response)
        login()

    def actioncall(self,action:str,func_name:str,param:dict):
        url = f"{self.method}://{self.host}/Action/call"
        payload = dumps({
                "action":action,
                "func_name":func_name,
                "param":param
                })
        with self.session.post(url,data=payload,verify=self.verify) as response:
            if response.status_code == 200:return response
            else:
                print(response.text)
                raise exceptions.HTTPError(response)

    def getsysstat(self):
        func_name = "sysstat"
        action="show"
        param = {
            "TYPE": "verinfo,cpu,memory,stream,cputemp",
            }
        response =  self.actioncall(action=action,func_name=func_name,param=param)
        try:
            volumeresp  = json.loads(response.text)
            cpuload = volumeresp["Data"]["cpu"][0]
            memoryused = volumeresp["Data"]["memory"]["used"]
            connectnum = volumeresp["Data"]["stream"]["connect_num"]
            download = volumeresp["Data"]["stream"]["download"]
            upload = volumeresp["Data"]["stream"]["upload"]
            cputemp = volumeresp["Data"]["cputemp"][0]
            infos = {
                "cpuload":cpuload,
                "cputemp":cputemp,
                "memoryused":memoryused,
                "connectnum":connectnum,
                "download":download,
                "upload":upload,
            }
            return infos
        except Exception as e:
            print(e)
    def create_docker(self,params:dict):

        '''
        params = {
            "name":str,
            "interface":str,
            "image":str , #e.g "whyour/qinglong:latest",
            "memory":int , #e.g unit : B , 128MB = 128*1024*1024=134217728 B,
            "auto_start":int , #e.g 0 for false , 1 for true,
            "mounts":str , #e.g  "/s/DockersData/test:/s/DockersData/test",
            "cmd":str ,
            "env":str , #e.g  "aa=bb",
            "ip6addr":"",
            "ipaddr":str , #e.g "192.168.20.4"
        }
        '''
        func_name = "docker_container"
        action = "add"
        param = params
        return self.actioncall(action,func_name,param)
    def addsubnet(self,params):
        
        self.actioncall(action="edit",func_name="static_rt",param=params)
    
    def new_backup(self,path):
        self.actioncall("create_tmpfile","backup",{})
        url = f"{self.method}://{self.host}/Action/download?filename=router_config.bak"
        response = self.session.get(url, verify=self.verify)
        # 检查请求是否成功
       
        if response.status_code == 200:
            # 生成当前时间戳（格式：YYYYMMDD_HHMMSS）
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            # 生成新的文件名
            filename = f"{path}\\router_config_{timestamp}.bak"
            
            # 将文件保存到本地
            with open(filename, "wb") as file:
                file.write(response.content)
            print(f"文件下载成功！保存为：{filename}")
        else:
            print(f"文件下载失败，状态码：{response.status_code}")
        pass
            

