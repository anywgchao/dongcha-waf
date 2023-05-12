# coding: utf-8

import datetime
import time
import hmac
import json
import requests
import hashlib
import base64
from urllib.parse import quote_plus
from RBAC.models import User_mails
from SeMF.settings import DING_URL


def send_dingding(msg_neiwang, msg_organi, msg_yisong):
    ding = User_mails.objects.last()
    timestamp = int(round(time.time() * 1000))
    secret = ding.ding_key
    secret_enc = bytes((secret).encode('utf-8'))
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = bytes((string_to_sign).encode('utf-8'))
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = quote_plus(base64.b64encode(hmac_code))

    token = ding.ding_token
    url = '{0}/robot/send?access_token={1}&timestamp={2}&sign={3}'.format(DING_URL, token, timestamp, sign)
    headers = {"Content-Type": "application/json"}
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    message = '{"content": "【WAF报警】 \n 时间: %s \n【env】\n%s【env】\n%s【env】\n%s"}' % (
        current_time, msg_neiwang, msg_organi, msg_yisong)
    datas ={"msgtype": "text", "text": message}
    datas = json.dumps(datas)

    r = requests.post(url, data=datas, headers=headers, verify=False)
