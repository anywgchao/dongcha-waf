"""
@Author: Daboluo
@Date: 2019-04-18 21:11:04
@LastEditTime: 2020-08-03 21:47:23
@LastEditors: Do not edit
"""
# -*- coding: utf-8 -*-
import os
#from multiprocessing import cpu_count
from configs.settings import BASE_DIR, PORT

bind = '0.0.0.0:' + os.environ.get('PORT', str(PORT))
workers = 4

debug = False
proc_name = 'dongcha-waf-agent'
user = None
group = None
backlog = 2048
max_requests = 4096
timeout = 30

"""
工作模式协程
sync        同步工作模式
gevent      协程实现
meinheld    协程实现
eventlet    协程实现
"""
worker_class = "eventlet"  # sync, gevent,meinheld eventlet

limit_request_field_size = 0
limit_request_line = 0

# https
keyfile = os.path.join(BASE_DIR, 'configs', 'server.key')
certfile = os.path.join(BASE_DIR, 'configs', 'server.pem')
ssl_version = "TLSv1_2"


loglevel = 'info'
appLogs = os.path.join(BASE_DIR, 'logs', 'app_access.log')
errorlog = os.path.join(BASE_DIR, 'logs', 'app_error.log')
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
