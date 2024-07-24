import requests
from json import dumps
import json
from hashlib import md5
from base64 import standard_b64encode
from requests import post
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
        self.cookie =  self.response.headers["Set-Cookie"]+f"username={self.username}; login=1"
        return self.response
    def actioncall(self,func_name:str,param:dict):
        if self.cookie:
            url = f"{self.method}://{self.host}/Action/call"
            payload = dumps({
                "action":"show",
                "func_name":func_name,
                "param":dumps(param)
            })
            response = post(url,headers={"Cookie":self.cookie},data=payload)
            
            return response
        else:
            raise ValueError("Missed cookie, please use login() to get session cookie")
    
    def getvolumes(self):
        if self.cookie:
            func_name = "monitor_lanip"
            param = {
                "TYPE": "data,total",
                "ORDER_BY":"ip_addr_int",
                "orderType":"IP",
                "limit":"0,20",
                "ORDER":"",
            }
            response =  self.actioncall(func_name=func_name,param=param)
            volumeresp  = json.loads(response.text)
            try:
                self.volumesdata = volumeresp["Data"]["data"]
                print(f"Loading volumes successful ! Result : {volumeresp['Result']} msg:{volumeresp['ErrMsg']}")
            except:
                print(volumeresp)
        else:
            raise ValueError("Missed cookie, please use login() to get session cookie")

