"""
@Author: Daboluo
@Date: 2019-01-11 14:37:11
@LastEditTime: 2020-02-25 18:47:23
@LastEditors: Do not edit
"""
# -*- coding: utf-8 -*-
import base64
from functools import wraps

from flask import jsonify, request
from app.libs.sonLogs import logs
from configs.settings import ACCESSKEY, SECRETKEY
from app import utils


class Auth:
    """认证模块实现token的生成、解析，以及用户的认证和鉴权。"""

    def __init__(self):
        pass

    def identify(self, request):
        """
        用户鉴权 :return: json
        accesskey=Grq90x4ZXYF5h2sAfCEE8aFd1uXyEfA7M0xb8rN7&secretkey=xGoapEXTuRcyuWfKjWXMvxqvtZj95a2fbOZ8y4Za
        :return code
        550     Token拆分错误
        551     验证Header头错误
        552     accesskey 或 secretkey 不存在
        553     不存在Header头信息
        """
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_header = base64.b64decode(auth_header.encode('utf-8'))
                auth_tokenArr = str(auth_header, encoding="utf-8").split("&")
            except Exception as err:
                return jsonify(utils.all_return(550, '', "Token Key Split Error"))

            if not auth_tokenArr or len(auth_tokenArr) != 2:
                result = utils.all_return(551,
                                          '', 'False validation header information')
            else:
                auth_accesskey = auth_tokenArr[0]
                auth_secretkey = auth_tokenArr[1]
                accesskey = auth_accesskey.split("=")[1]
                secretkey = auth_secretkey.split("=")[1]
                if accesskey and secretkey:
                    result = {
                        "accesskey": accesskey,
                        "secretkey": secretkey
                    }
                else:
                    result = utils.all_return(552, '', 'Token Key Error')
        else:
            result = utils.all_return(553, '', 'Token Key Not Found ')
        return result


def key_required(f):
    """
    API接口验证
    {
        "accesskey": "123",
        "secretkey": "123"
    }
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        """

        :param args:
        :param kwargs:
        :return: code
        400     request Body 非JSON
        550     Token失效
        551     Token未找到
        552     Key/Value错误
        """
        if not isinstance(request.get_json(force=True), dict):
            return jsonify(utils.all_return(400, '', 'JSON Format Error'))
        else:
            result = Auth.identify(Auth(), request)

        try:
            if result['accesskey'] and result['secretkey']:
                if result['accesskey'] == ACCESSKEY and result['secretkey'] == SECRETKEY:
                    return f(*args, **kwargs)
                else:
                    return jsonify(utils.all_return(550, "", "Token invalid"))
            else:
                return jsonify(utils.all_return(551, "", "Token Key Not Found"))
        except Exception as e:
            logs.error("[!] Auth Accsskey or Secretkey : %s." % e)
            return jsonify(utils.all_return(552, "", "Token Key/Value Error"))

    return decorated
