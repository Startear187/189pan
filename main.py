import time
import re
import json
import base64
import hashlib
import rsa
import requests
import os
import sys
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dotenv import load_dotenv


class Config:
    """配置类，管理所有常量和URL"""

    # 加密常量
    BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")
    B64MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    # API端点
    LOGIN_TOKEN_URL = "https://m.cloud.189.cn/udb/udb_login.jsp?pageId=1&pageKey=default&clientType=wap&redirectURL=https://m.cloud.189.cn/zhuanti/2021/shakeLottery/index.html"
    LOGIN_SUBMIT_URL = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
    SIGN_URL_TEMPLATE = "https://api.cloud.189.cn/mkt/userSign.action?rand={}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K"

    # 抽奖URL
    DRAW_URLS = [
        "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN",
        "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN",
        "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_2022_FLDFS_KJ&activityId=ACT_SIGNIN"
    ]

    # 请求头
    LOGIN_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
        'Referer': 'https://open.e.189.cn/',
    }

    SIGN_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
        "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
        "Host": "m.cloud.189.cn",
        "Accept-Encoding": "gzip, deflate",
    }


class CryptoUtils:
    """加密工具类"""

    @staticmethod
    def int2char(a: int) -> str:
        """整数转字符"""
        return Config.BI_RM[a]

    @staticmethod
    def b64tohex(a: str) -> str:
        """Base64转十六进制"""
        d = ""
        e = 0
        c = 0
        for i in range(len(a)):
            if list(a)[i] != "=":
                v = Config.B64MAP.index(list(a)[i])
                if 0 == e:
                    e = 1
                    d += CryptoUtils.int2char(v >> 2)
                    c = 3 & v
                elif 1 == e:
                    e = 2
                    d += CryptoUtils.int2char(c << 2 | v >> 4)
                    c = 15 & v
                elif 2 == e:
                    e = 3
                    d += CryptoUtils.int2char(c)
                    d += CryptoUtils.int2char(v >> 2)
                    c = 3 & v
                else:
                    e = 0
                    d += CryptoUtils.int2char(c << 2 | v >> 4)
                    d += CryptoUtils.int2char(15 & v)
        if e == 1:
            d += CryptoUtils.int2char(c << 2)
        return d

    @staticmethod
    def rsa_encode(j_rsakey: str, string: str) -> str:
        """RSA加密"""
        rsa_key = f"-----BEGIN PUBLIC KEY-----\n{j_rsakey}\n-----END PUBLIC KEY-----"
        pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
        result = CryptoUtils.b64tohex((base64.b64encode(rsa.encrypt(f'{string}'.encode(), pubkey))).decode())
        return result

class TianYiCloudBot:
    """天翼云盘自动签到抽奖机器人"""

    def __init__(self, username: str, password: str, account_id: str = ""):
        self.username = username
        self.password = password
        self.account_id = account_id or f"账户{username[:3]}***"
        self.session = requests.Session()

    def _extract_login_params(self, html: str) -> Dict[str, str]:
        """从HTML中提取登录参数"""
        try:
            captcha_token = re.findall(r"captchaToken' value='(.+?)'", html)[0]
            lt = re.findall(r'lt = "(.+?)"', html)[0]
            return_url = re.findall(r"returnUrl= '(.+?)'", html)[0]
            param_id = re.findall(r'paramId = "(.+?)"', html)[0]
            j_rsakey = re.findall(r'j_rsaKey" value="(\S+)"', html, re.M)[0]

            return {
                'captchaToken': captcha_token,
                'lt': lt,
                'returnUrl': return_url,
                'paramId': param_id,
                'j_rsakey': j_rsakey
            }
        except (IndexError, AttributeError) as e:
            raise Exception(f"提取登录参数失败: {e}")

    def login(self) -> bool:
        """登录天翼云盘"""
        try:
            # 获取登录token
            response = self.session.get(Config.LOGIN_TOKEN_URL)

            # 提取重定向URL
            pattern = r"https?://[^\s'\"]+"
            match = re.search(pattern, response.text)
            if not match:
                print("没有找到重定向URL")
                return False

            redirect_url = match.group()
            response = self.session.get(redirect_url)

            # 提取登录页面href
            pattern = r"<a id=\"j-tab-login-link\"[^>]*href=\"([^\"]+)\""
            match = re.search(pattern, response.text)
            if not match:
                print("没有找到登录链接")
                return False

            href = match.group(1)
            response = self.session.get(href)

            # 提取登录参数
            login_params = self._extract_login_params(response.text)
            self.session.headers.update({"lt": login_params['lt']})

            # RSA加密用户名和密码
            encrypted_username = CryptoUtils.rsa_encode(login_params['j_rsakey'], self.username)
            encrypted_password = CryptoUtils.rsa_encode(login_params['j_rsakey'], self.password)

            # 构建登录数据
            login_data = {
                "appKey": "cloud",
                "accountType": '01',
                "userName": f"{{RSA}}{encrypted_username}",
                "password": f"{{RSA}}{encrypted_password}",
                "validateCode": "",
                "captchaToken": login_params['captchaToken'],
                "returnUrl": login_params['returnUrl'],
                "mailSuffix": "@189.cn",
                "paramId": login_params['paramId']
            }

            # 提交登录
            response = self.session.post(
                Config.LOGIN_SUBMIT_URL,
                data=login_data,
                headers=Config.LOGIN_HEADERS,
                timeout=10
            )

            result = response.json()
            if result['result'] == 0:
                # 访问重定向URL完成登录
                self.session.get(result['toUrl'])
                return True
            else:
                return False

        except Exception as e:
            print(f"登录过程出错: {e}")
            return False


    def sign_in(self) -> Tuple[bool, str]:
        """执行签到"""
        try:
            rand = str(round(time.time() * 1000))
            sign_url = Config.SIGN_URL_TEMPLATE.format(rand)

            response = self.session.get(sign_url, headers=Config.SIGN_HEADERS, timeout=10)
            result = response.json()

            netdisk_bonus = result.get('netdiskBonus', 0)
            is_signed = result.get('isSign', False)

            if is_signed:
                message = f"已签到，获得{netdisk_bonus}M空间"
            else:
                message = f"签到成功，获得{netdisk_bonus}M空间"

            return True, message

        except Exception as e:
            error_msg = f"签到失败: {e}"
            print(error_msg)
            return False, error_msg

    def draw_prize(self, round_num: int, url: str) -> Tuple[bool, str]:
        """执行抽奖"""
        try:
            response = self.session.get(url, headers=Config.SIGN_HEADERS, timeout=10)
            data = response.json()

            if "errorCode" in data:
                message = f"抽奖失败，次数不足"
                return False, message
            else:
                prize_name = data.get("prizeName", "未知奖品")
                message = f"抽奖成功，获得{prize_name}"
                return True, message

        except Exception as e:
            error_msg = f"第{round_num}次抽奖出错: {e}"
            print(error_msg)
            return False, error_msg

    def run(self) -> Dict[str, str]:
        """执行完整的签到抽奖流程"""
        results = {
            'account_id': self.account_id,
            'login': '',
            'sign_in': '',
            'draws': []
        }

        # 登录
        if not self.login():
            results['login'] = '登录失败'
            return results

        results['login'] = '登录成功'

        # 签到
        sign_success, sign_msg = self.sign_in()
        results['sign_in'] = sign_msg

        # 抽奖
        for i, draw_url in enumerate(Config.DRAW_URLS, 1):
            if i > 1:  # 第一次抽奖后等待5秒
                time.sleep(5)

            draw_success, draw_msg = self.draw_prize(i, draw_url)
            results['draws'].append(draw_msg)

        return results


def load_accounts() -> List[Tuple[str, str]]:
    """加载账户信息"""
    load_dotenv()

    username_env = os.getenv("TYYP_USERNAME")
    password_env = os.getenv("TYYP_PSW")

    if not username_env or not password_env:
        print("错误：环境变量TYYP_USERNAME或TYYP_PSW未设置")
        print("请确保.env文件存在并包含正确的配置")
        sys.exit(1)

    usernames = username_env.split('&')
    passwords = password_env.split('&')

    if len(usernames) != len(passwords):
        print("错误：用户名和密码数量不匹配")
        sys.exit(1)

    return list(zip(usernames, passwords))


def main():
    """主程序"""
    # 记录开始时间
    start_time = datetime.now()

    print("# 天翼云盘自动签到抽奖程序")
    print()

    # 加载账户信息
    accounts = load_accounts()
    print(f"## 执行概览")
    print(f"- **启动时间**: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"- **账户数量**: {len(accounts)} 个")
    print()

    # 处理每个账户
    for i, (username, password) in enumerate(accounts, 1):
        account_id = f"账户{i}"
        print(f"## {account_id}")

        bot = TianYiCloudBot(username, password, account_id)
        results = bot.run()

        # 输出结果摘要
        print(f"### 执行结果")
        print(f"- **登录状态**: {results['login']}")
        print(f"- **签到结果**: {results['sign_in']}")

        # 抽奖结果
        if results['draws']:
            print(f"- **抽奖结果**:")
            for j, draw_result in enumerate(results['draws'], 1):
                # 提取关键信息，去除重复的"第X次"
                clean_result = draw_result.replace(f"第{j}次", "").strip()
                if "成功" in draw_result:
                    print(f"  - 🎉 第{j}次: {clean_result}")
                else:
                    print(f"  - ❌ 第{j}次: {clean_result}")

        print()

    # 记录结束时间并计算运行时间
    end_time = datetime.now()
    duration = end_time - start_time

    print("---")
    print("## 执行统计")
    print(f"- **结束时间**: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"- **运行时长**: {duration.total_seconds():.2f} 秒")
    print()
    print("✅ **所有账户处理完成！**")


if __name__ == "__main__":
    main()
