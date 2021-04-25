#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import socket
import requests
import chardet
import re
import favicon
import http.client
import mmh3
import codecs
import ssl
import os
import OpenSSL
import json
import jieba
import traceback
from collections import Counter
from datetime import datetime
from decorator import decorator
from urllib.parse import urlparse
from fake_useragent import UserAgent
from concurrent.futures import ThreadPoolExecutor, as_completed
requests.packages.urllib3.disable_warnings()


class Utils(object):
    """docstring for Utils"""

    def makeurl(self, domain):
        if not domain.startswith("http"):
            domain = "http://" + domain
        parse_result = urlparse(domain)
        new_url = parse_result.scheme + "://" + parse_result.netloc + \
            parse_result.path
        return new_url

    def get_hostname(self, url):
        if not url.startswith("http"):
            url = "http://" + url
        return urlparse(url).hostname

    def random_ua(self):
        return UserAgent().random

    def get_schema(self, host):
        conn = http.client.HTTPConnection(host, timeout=3)
        try:
            conn.request("HEAD", '')
        except Exception as TE:
            print(("1", host, TE))
            host = "www." + host
            conn = http.client.HTTPConnection(host, timeout=3)
            try:
                conn.request("HEAD", '')
            except Exception as TE:
                print(("2", host, TE))
        try:
            conn.getresponse()
            ret = "http"
        except Exception as TE:
            print(("3", host, TE))
            ret = "https"
        return ret


class SearchEngine(object):
    """docstring for ClassName"""

    def __init__(self, shodan_token=None, fofa_token=None, zoomEye_token=None):
        self.shodan_token = shodan_token
        self.fofa_token = fofa_token
        self.zoomeye_token = zoomEye_token

    def fofa_search(self, keyword):
        pass

    def shodan_search(self, keyword):
        pass

    def zoomeye_search(self, keyword):
        pass


@decorator
def except_beauty(func, debug=True, *args, **kw):
    try:
        return func(*args, **kw)
    except Exception as e:
        if debug:
            sign = '=' * 60 + '\n'
            print(f'{sign}>>>异常时间：\t{datetime.now()}\n>>>异常函数：\t{func.__name__}\n>>>异常信息：\t{e}')
            print(f'{sign}{traceback.format_exc()}{sign}')
        else:
            pass
    return None


@except_beauty(debug=True)
def get_ip(domain):
    try:
        return socket.getaddrinfo(domain, 'http')[0][4][0]
    except Exception as e:
        print(e)
        return None


@except_beauty(debug=True)
def get_title(url, UA=None):
    headers = {
        "User-Agent": UA
    }
    # print(url)
    resp = requests.get(url, headers=headers, stream=True, verify=False)
    ip, port = resp.raw._connection.sock.socket.getpeername()
    encoding = chardet.detect(resp.content)['encoding']
    resp.encoding = encoding
    # print(resp.content)
    try:
        title = re.findall('<title>(.*)</title>', resp.text)[0]
    except:
        title = None
    return {"title": title, "ip": ip, "port": port, "url": url, "type": "get_title"}


@except_beauty(debug=True)
def get_favicon_hash(url):

    icons = favicon.get(url, timeout=3)
    if icons:
        url = icons[0].url
        icon_hash = mmh3.hash(codecs.lookup('base64').encode(
            requests.get(url).content)[0])
        return {"url":  url, "icon_hash": icon_hash, "type": "favicon"}


@except_beauty(debug=True)
def get_cert_from_endpoint(server, port=443):
    try:
        cert = ssl.get_server_certificate((server, port))
    except Exception:
        return None
    if not cert:
        return None
    # print(cert)
    result = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    subject = result.get_subject()
    issued_OU = subject.OU
    issued_Organization = subject.O
    issued_to = subject.CN
    issuer = result.get_issuer()
    issued_by = issuer.CN
    # Organizational Unit: 技术保障部
    # Organization: 武汉斗鱼网络科技有限公司
    # print(issued_to, ":::::::", issued_by)
    # return issued_to,issued_by
    # return {"cert": cert, "subject": subject, "issuer": issuer, "issued_to": issued_to, "issued_by": issued_by}
    return {"OU": issued_OU, "Organization": issued_Organization, "CN": issued_to, "server": server, "port": port, "type": "ssl"}


def report_init():
    result_path = "./result"
    if not os.path.exists(result_path):
        os.mkdir(result_path)
    # info_file = open(os.path.join(result_path, "info.txt"), "w")
    # ssl_file = open(os.path.join(result_path, "ssl.txt"), "w")
    # icon_file = open(os.path.join(result_path, "icon.txt"), "w")
    # return info_file, ssl_file, icon_file


def run(info_file=None, ssl_file=None, icon_file=None):
    utils = Utils()
    executor = ThreadPoolExecutor(max_workers=50)
    info_task = []
    ssl_task = []
    favicon_task = []
    with open("domains.txt", "r") as targets:
        for target in targets:
            url = utils.makeurl(target.strip())
            random_ua = utils.random_ua()
            task = executor.submit(get_title, url, random_ua)
            info_task.append(task)
            hostname = utils.get_hostname(url)
            task = executor.submit(get_cert_from_endpoint, hostname)
            ssl_task.append(task)
            task = executor.submit(get_favicon_hash, url)
            favicon_task.append(task)
    all_task = info_task + ssl_task + favicon_task
    title = set()
    ip = set()
    ssl = set()
    icon = set()
    for future in as_completed(all_task):
        data = future.result()
        if data is not None:
            # print(data.get("type"))
            _type = data.get("type")
            if _type == "get_title":
                title.add(data.get("title"))
                ip.add(data.get("ip"))
            if _type == "ssl":
                ssl.add(data.get("OU"))
                ssl.add(data.get("Organization"))
                ssl.add(data.get("CN"))
            if _type == "favicon":
                icon.add(data.get("icon_hash"))
    title_key_word = []
    for item in title:
        try:
            title_key_word += [x for x in jieba.cut(item) if len(x) > 1]
        except:
            pass
    subnet = set()
    for item in ip:
        subnet.add(re.findall(r'\d+?\.\d+?\.\d+?\.', item)[0] + '0/24')
    subnet = list(subnet)
    print(subnet)
    # print(title_key_word)
    print(Counter(title_key_word).most_common(3))
    print(title, ip, ssl, icon)


def main():
    run()
    # info_file, ssl_file, icon_file = report_init()
    # run(info_file, ssl_file, icon_file)
    # print("done!")
    # print(getIP("douyu.com"))
    # utils = Utils()
    # print(utils.get_domain("baidu.com"))
    # url = utils.makeurl("https://douyu.com/")
    # random_ua = utils.random_ua()
    # print(get_title(url, random_ua))
    # print(utils.makeurl("douyu.com:80/c=1&a=1?123"))
    # print(utils.get_schema("douyu.com"))
    # print(getTitle("https://douyu.com/"))
    # print(get_favicon_hash("http://douyu.com/"))
    # print(get_cert_from_endpoint("47.94.109.232", 443))


if __name__ == '__main__':
    main()
