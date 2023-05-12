# -*- coding: utf-8 -*-
import os
from multiprocessing import cpu_count

proc_name = 'dongcha-waf-manager'
log_path = os.path.dirname(os.path.abspath(__file__))
bind = '0.0.0.0:' + os.environ.get('PORT', '8837')
workers = 4

backlog = 2048
max_requests = 4096
worker_class = "eventlet"  # sync, gevent,meinheld eventlet

debug = False
limit_request_field_size = 0
limit_request_line = 0
