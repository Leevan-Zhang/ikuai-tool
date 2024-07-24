import requests
from json import dumps
import json
from hashlib import md5
from base64 import standard_b64encode
from requests import post
from requests import exceptions
import asyncio
class ikuai():
    def __init__(self,ip,username,password,method="http",verify=False):
        # parameters setting
        self.verify=verify
        self.method = method
        self.host = ip
        self.username = username
        # set the pass field
        self.pas = standard_b64encode(f"salt_11{password}".encode()).decode()
        # set the passwd field
        mdfive = md5()
        mdfive.update(password.encode('UTF-8'))
        self.passwd = mdfive.hexdigest()
        # set the default cookie 
        self.cookie=None

    def login(self): 
        url = f"{self.method}://{self.host}/Action/login"
        payload = dumps({
            "username": self.username,
            "passwd": self.passwd,
            "pass": self.pas,
            "remember_password":"false"
        })
        self.response = requests.request("POST", url, headers="", data=payload, verify=self.verify)
        if self.response.status_code==200:
            sess_key = self.response.headers["Set-Cookie"].split(";")[0]
            self.cookie =  sess_key+f"; username={self.username}; login=1"
            return self.response
        else:
            print("Login failed ! HTTP CODE : ",self.response.status_code)
            raise exceptions.HTTPError(self.response)
    def actioncall(self,action:str,func_name:str,param:dict):
        if self.cookie:
            url = f"{self.method}://{self.host}/Action/call"
            payload = dumps({
                "action":action,
                "func_name":func_name,
                "param":param
            })

            with post(url,headers={"Cookie":self.cookie},data=payload,verify=self.verify) as response:
                if response.status_code == 200:return response
                else:
                    print(response.text)
                    raise exceptions.HTTPError(response)
        else:raise ValueError("Missed cookie, please use login() to get session cookie")
    def getsysstat(self):
        if self.cookie:
            func_name = "sysstat"
            action="show"
            param = {
                "TYPE": "verinfo,cpu,memory,stream,cputemp",
            }
            response =  self.actioncall(action=action,func_name=func_name,param=param)
            # print(response.text,response)

            try:
                volumeresp  = json.loads(response.text)
                cpuload = volumeresp["Data"]["cpu"][0]
                memoryused = volumeresp["Data"]["memory"]["used"]
                connectnum = volumeresp["Data"]["stream"]["connect_num"]
                download = volumeresp["Data"]["stream"]["download"]
                upload = volumeresp["Data"]["stream"]["upload"]
                infos = {
                    "cpuload":cpuload,
                    "memoryused":memoryused,
                    "connectnum":connectnum,
                    "download":download,
                    "upload":upload,
                }
                return infos
            except Exception as e:
                print(e)
        else:
            raise ValueError("Missed cookie, please use login() to get session cookie")
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
