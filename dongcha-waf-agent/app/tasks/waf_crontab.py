"""
@Author: Daboluo
@Date: 2018-12-20 17:20:22
@LastEditTime: 2020-08-04 20:16:35
@LastEditors: Do not edit
"""

# -*- coding:utf8 -*-
import os
import json
import requests
from app.libs.sonLogs import logs
from configs.settings import OPENWAF_CONFIG, OPENWAF_BASE_CONFIG, OPENWAF_GLOBAL_CONFIG


def check_json(myjson):
    """

    :param myjson:
    :return:
    """
    try:
        json.loads(myjson)
    except ValueError as e:
        return False
    return True


def update_ruler(url, jsonFile, waf_api_key, waf_platform_tag):
    """
    更新WAF规则
    """
    headers = {'Content-Type': 'application/json'}
    body = {
        "api_key": waf_api_key,
        "platform_tag": waf_platform_tag,
    }

    try:
        response = requests.post(
            url=url, headers=headers, data=json.dumps(body), verify=False)
    except requests.exceptions.Timeout as e:
        logs.error('[!] 连接管理平台请求超时：: {}'.format(e.message))
    except requests.exceptions.HTTPError as e:
        logs.error('[!] http请求错误：: {}'.format(e.message))
    else:
        # 通过status_code判断请求结果是否正确
        if response.status_code == 200 and check_json(response.text):
            with open(jsonFile, "w") as f:
                f.write(response.text)
        else:
            logs.error('[!] 请求错误：: {},{}'.format(str(response.status_code), str(response.reason)))


def job_5m_update():
    """
        5分钟下载一次文件
    """
    # from datetime import datetime
    # logs.error('[!] Load scheduled task Err: {}'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

    try:
        if os.path.isfile(OPENWAF_CONFIG):
            with open(OPENWAF_CONFIG, 'r') as f:
                jsObj = json.load(f)

        if jsObj:
            security_rules = jsObj["base_rule_update_website"]
            global_config_rules = jsObj["global_rule_update_website"]
            waf_api_key = jsObj["waf_api_key"]
            waf_platform_tag = jsObj["waf_platform_tag"]
    except Exception as e:
        logs.error('[!] Load openwaf_config Err: {}'.format(e))

    try:
        # 更新全局配置文件
        update_ruler(global_config_rules, OPENWAF_GLOBAL_CONFIG, waf_api_key, waf_platform_tag)
        logs.info('[!] Update openwaf_local_base_config Successful.')
    except Exception as e:
        logs.error('[!] Update openwaf_local_global Err: {}'.format(e))

    try:
        # 更新规则文件
        update_ruler(security_rules, OPENWAF_BASE_CONFIG, waf_api_key, waf_platform_tag)
        logs.info('[!] Update openwaf_local_base_config Successful.')
    except Exception as e:
        logs.error('[!] Update openwaf_local_base_config Err: {}'.format(e))
