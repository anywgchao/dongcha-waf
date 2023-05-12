# -*- coding: utf-8 -*-

from flask import request
from hashlib import md5
from random import Random
import string

# 手机号正则
REG_EXP_PHONE = '^(0|86|17951)?(13[0-9]|15[012356789]|17[678]|18[0-9]|14[57])[0-9]{8}$'

# 追踪正则
REG_EXP_TRACKING = '^\d+$'

# IP正则
REG_EXP_IP = '(((25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d))))'

# MAC正则
REG_EXP_MAC = '^([0-9a-fA-F]{2})(([/\s:-][0-9a-fA-F]{2}){5})$'

# 数字正则
REG_EXP_NUMBER = '^[0-9]*$'

# 数字逗号正则
REG_EXP_DNUM = '^\d+(,\d+)*$'

# 中文、字母、数字、“-”“_”的组合，4-20个字符
REG_EXP_STR = '^[A-Za-z0-9\:\.\-\_\u4e00-\u9fa5]+$'

# 中文、字母、数字、“.”“-”的组合，4-20个字符
REG_EXP_HOST = '^[A-Za-z0-9\:\-\.\_\u4e00-\u9fa5]+$'

# Email正则
REG_EXP_MAIL = '^[a-z0-9]+([._\\-]*[a-z0-9])*@([a-z0-9]+[-a-z0-9]*[a-z0-9]+.){1,63}[a-z0-9]+$'

# URL正则
REG_EXP_URL = '''^(https?):\/\/[\w\-]+(\.[\w\-]+)+([\w\-\.,@?^=%&:\/~\+#]*[\w\-\@?^=%&\/~\+#])?$'''

# IP正则 192.168.1.1
REG_EXP_IPADDR = '^(((25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d))))$'

# IP 段正则 192.168.2.0/24
REG_EXP_IPFIELD = '^(((?<![0-9])0?[0-9]?[0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.(0?[0-9]?[0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.(0?[0-9]?[0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.(0?[0-9]?[0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]))(?:/([1-2][0-9]|3[0-2]|[0-9]))$'

# 多个IP段  192.168.1.1-192.168.1.5
REP_EXP_MOREIP = '^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])-(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$'

# 多个IP地址  192.168.1.1,192.168.1.5
REG_EXP_IPADDRS = '^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5]),(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5]).*$'


def get_client_ip():
    """

    :return:
    """
    # 获取客户端ip地址
    if 'x-forwarded-for' in request.headers:
        ip = request.headers['x-forwarded-for'].split(', ')[0]
    else:
        ip = request.remote_addr
    return ip


def random_str(randomlength=10):
    """

    :param randomlength:
    :return:
    """
    # 生成随机数
    strtmp = ''
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    length = len(chars) - 1
    random = Random()
    for i in range(randomlength):
        strtmp += chars[random.randint(0, length)]
    return md5(strtmp.encode('UTF-8')).hexdigest()


def url_md5hash(url):
    """

    :param url:
    :return:
    """
    return md5(url).hexdigest()


def check_variable(vaule):
    """检测变量值是否存在"""
    if '{}'.format(vaule) not in locals().keys():
        return 'Null'
    else:
        return vaule

def all_return(status, data, msg):
    """Service status"""
    return {
        "status": status,
        "data": data,
        "msg": msg
    }

def check_task_id(task_id):
    """

    :param task_id:
    :return:
    """
    def _(x): return True if x in string.ascii_letters + string.digits + "-" else False

    return True if all(map(_, task_id)) else False
