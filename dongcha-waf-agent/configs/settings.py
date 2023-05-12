"""
@Author: Daboluo
@Date: 2019-07-08 19:51:42
@LastEditTime: 2020-08-03 22:38:43
@LastEditors: Do not edit
"""
# -*- coding: utf-8 -*-

import os

__author__ = 'Daboluo'
__version__ = '1.0.0'

DEBUG = False
PORT = 8839
HOST = "0.0.0.0"

SECRET_KEY = "s2vutMFHgM8WNsdfdsfdsfdsfdsLDp7gmaDm2hBkQUP"
SESSION_COOKIE_NAME = "WAF-Agent"
PERMANENT_SESSION_LIFETIME = 1800
SITE_COOKIE = "GTin7rALDp7gmaDm2vutMFHgM8WNoqZk"
WTF_CSRF_ENABLED = True

# Loging
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST_NAME = "dongcha_waf_agent"
MAX_BYTES = 5242880
BACKUP_COUNT = 5
APP_LOGS = os.path.join(BASE_DIR, 'logs', 'app_access.log')
APP_SCHEDULER_LOCK = os.path.join(BASE_DIR, 'tmp', 'scheduler.lock')

BASE_NGINX_CONF = "/etc/nginx/"
NGINX_CONF = "/data/semf/config/openresty/"
WAF_VHOST = os.path.join(BASE_NGINX_CONF, "conf.d/")
WAF_VHOST_BACK = os.path.join(BASE_NGINX_CONF, "backup/")
WAF_CERT = os.path.join(BASE_NGINX_CONF, "cert_key/")

# 物理主机路径
P_WAF_CERT = os.path.join(NGINX_CONF, "cert_key/")
WAF_SITE_LOGS = "/data/semf/logs/openresty/"

WAF_RELOAD = os.path.join(BASE_DIR, 'script', 'waf_reload.sh')
WAF_CONF_CHECK = os.path.join(BASE_DIR, 'script', 'waf_conf_check.sh')
CMD_TIMEOUT = 60

OPENWAF_CONFIG = os.path.join(BASE_NGINX_CONF, "openwaf/conf/openwaf_config.json")
OPENWAF_BASE_CONFIG = os.path.join(BASE_NGINX_CONF, "openwaf/conf/openwaf_local_base_config.json")
OPENWAF_GLOBAL_CONFIG = os.path.join(BASE_NGINX_CONF, "openwaf/conf/openwaf_local_global.json")

TEMPLATE_FOLDER = os.path.join(BASE_DIR, "app/templates", 'waftpl')

# Agent连接KEY
ACCESSKEY = "Grq90x4ZXYF5h2sAfCEE8aFd1uXyEfA7M0xb8rN7"
SECRETKEY = "xGoapEXTuRcyuWfKjWXMvxqvtZj95a2fbOZ8y4Za"

TIME_ZONE = 'Asia/Shanghai'

# 添加计划任务
SCHEDULER_API_ENABLED = True
JOBS = [
        {
            'id': 'job_5m_update',      # 任务ID
            'timezone': TIME_ZONE,      # 指定时区
            'func': 'app.tasks.waf_crontab:job_5m_update',        # 任务位置
            'args': '',
            'trigger': {
                'type': 'interval',             # 触发器类型，interval(循环任务)，cron(定时任务)，一次性任务
                "seconds": 300  # 时间间隔
            }
        }
]
