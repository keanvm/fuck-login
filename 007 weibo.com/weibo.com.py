#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import binascii
import codecs
import json
import logging
import random
import re
import rsa
import time

import requests
from urllib import quote_plus


class WeiboComLogin(object):
    AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.81 Safari/537.36'
    HEADERS = {'User-Agent': AGENT}
    INIT_URL = "http://weibo.com/login.php"
    LOGIN_URL = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)'

    def __init__(self, username, password, timeout=3):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.timeout = timeout
        self.headers = WeiboComLogin.HEADERS.copy()
        self.response = None
        self.server_data = None
        self.uuid = None
        self.user_nick_name = None
        self.get(WeiboComLogin.INIT_URL)

    def get(self, url, headers=None, cookies=None, timeout=None):
        if headers is None:
            headers = self.headers
        if timeout is None:
            timeout = self.timeout
        if cookies is None:
            self.response = self.session.get(
                url=url, headers=headers, timeout=timeout)
        else:
            self.response = self.session.get(
                url=url, headers=headers, timeout=timeout, cookies=cookies)
        logging.info("[#] POST STATUS: %s, URL: %s ",
                     self.response.status_code, self.response.url)
        return self.response

    def post(self, url, data, headers=None, cookies=None, timeout=None):
        if headers is None:
            headers = self.headers
        if timeout is None:
            timeout = self.timeout
        if cookies is None:
            self.response = self.session.post(
                url=url, headers=headers, timeout=timeout, data=data)
        else:
            self.response = self.session.post(
                url=url, headers=headers, timeout=timeout, data=data, cookies=cookies)
        logging.info("[#] POST STATUS: %s, URL: %s ",
                     self.response.status_code, self.response.url)
        return self.response

    def _prelogin(self):
        url = "http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su="
        url = url + self.su + \
            "&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.18)&_=" + str(
                int(time.time() * 1000))
        res = self.get(url)
        return eval(res.content.decode("utf-8").replace("sinaSSOController.preloginCallBack", ''))

    @property
    def su(self):
        username_quote = quote_plus(self.username)
        username_base64 = base64.b64encode(username_quote.encode("utf-8"))
        return username_base64.decode("utf-8")

    def _get_password(self, servertime, nonce, pubkey):
        rsaPublickey = int(pubkey, 16)
        key = rsa.PublicKey(rsaPublickey, 65537)  # create rsa public key
        data = str(servertime) + '\t' + str(nonce) + \
            '\n' + str(self.password)  # get data
        # encrypt
        return binascii.b2a_hex(rsa.encrypt(data.encode("utf-8"), key))

    def get_captcha(self, pcid):
        cha_url = "http://login.sina.com.cn/cgi/pin.php?r="
        cha_url = cha_url + \
            str(int(random.random() * 100000000)) + "&s=0&p=" + pcid
        return self.get(cha_url, headers=headers).content

    def prelogin(self):
        self.server_data = self._prelogin()
        showpin = self.server_data["showpin"]
        if showpin:  # have captcha
            return self.get_captcha(self.server_data["pcid"])
        else:
            return None

    def get_json_cookies(self):
        cookies = [ck.__dict__ for ck in self.session.cookies]
        return json.dumps(cookies)

    def _get_login_post_data(self):
        servertime = self.server_data["servertime"]
        nonce = self.server_data['nonce']
        rsakv = self.server_data["rsakv"]
        pubkey = self.server_data["pubkey"]
        return {
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'useticket': '1',
            'pagerefer': "http://login.sina.com.cn/sso/logout.php?entry=miniblog&r=http%3A%2F%2Fweibo.com%2Flogout.php%3Fbackurl",
            'vsnf': '1',
            'su': self.su,
            'service': 'miniblog',
            'servertime': servertime,
            'nonce': nonce,
            'pwencode': 'rsa2',
            'rsakv': rsakv,
            'sp': self._get_password(servertime, nonce, pubkey),
            'sr': '1366*768',
            'encoding': 'UTF-8',
            'prelt': '115',
            'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META'
        }

    def login(self, captcha=None):
        if self.server_data is None:
            raise ValueError("call prelogin first")
        postdata = self._get_login_post_data()
        if captcha is not None:
            postdata["door"] = captcha
        login_page = self.post(self.LOGIN_URL, data=postdata)
        content = login_page.content.decode("GBK")
        self.server_data = None
        try:
            location = re.findall(
                r'location\.replace\([\'"](.*?)[\'"]\)', content)[0]
            page = self.get(location).text
            self.uuid = re.findall(r'"uniqueid":"(.*?)"', page, re.S)[0]
            web_weibo_url = "http://weibo.com/%s/profile?topnav=1&wvr=6&is_all=1" % uuid
            profile_page = self.get(web_weibo_url)
            profile_content = profile_page.content.decode("utf-8", 'ignore')
            self.user_nick_name = re.findall(
                r'<title>(.*?)</title>', profile_content, re.S)[0]
            logging.info("user: %s uuid: %s, nickname: %s login successfully", self.username,
                         self.uuid, self.user_nick_name)
            return True
        except Exception as e:
            logging.exception("login failed: %s", e)
            return False

    def test(self):
        captcha, captcha_value = self.prelogin(), None
        if captcha is not None:
            with open(self.username + ".jpg", "wb") as fl:
                fl.write(captcha)
            captcha_value = input("Captcha Value:")
        self.login(captcha_value)

SITE_NAME = "weibo"
ACCOUNTS_FILE = "../accounts.local.json"

def main():
    logging.root.setLevel(logging.INFO)
    accounts = json.load(codecs.open(ACCOUNTS_FILE, "r", "utf-8"), "utf-8").get(SITE_NAME, [])
    for item in accounts:
        usr, pwd= item["username"], item["password"]
        logging.info("Login Account: %s, Password: %s", usr, pwd)
        weibo = WeiboComLogin(username=usr, password=pwd)
        weibo.test()
        weibo.get("http://weibo.cn")
        cookies = weibo.get_json_cookies()
    
if __name__ == "__main__":
    main()
