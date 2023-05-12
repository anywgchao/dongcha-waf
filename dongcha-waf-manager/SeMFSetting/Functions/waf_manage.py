# coding:utf-8
from requests.packages import urllib3
from celery.utils.log import get_task_logger
from SeMF.settings import AGENT_KEY

logger = get_task_logger(__name__)
import json
import requests
from django.contrib.auth.models import User
from RuleManage.models import remote_rule


verify = False

Access_Key = AGENT_KEY


def build_url(url, resource):
    url = url.strip('/')
    return '{0}{1}'.format(url, resource)


def connect(method, resource, data, url):
    headers = {
        'Authorization': Access_Key
    }
    if data is not None:
        data = json.dumps(data)
    urllib3.disable_warnings()
    if method == 'POST':
        r = requests.post(build_url(url, resource), data=data, headers=headers, verify=verify)
    elif method == 'PUT':
        r = requests.put(build_url(url, resource), data=data, headers=headers, verify=verify)
    elif method == 'DELETE':
        r = requests.delete(build_url(url, resource), data=data, headers=headers, verify=verify)
    else:
        r = requests.get(build_url(url, resource), params=data, headers=headers, verify=verify)
    if r.status_code != 200:
        e = r.json()
        print(e)
    else:
        try:
            return r.json()
        except:
            return True


def site_add(data, url):
    datas = data
    data = connect('POST', '/waf/v1/site/add', datas, url)
    return data


def site_view(uuid, url):
    datas = {
        "site_uuid": uuid
    }
    data = connect('POST', '/waf/v1/site/view', datas, url)
    return data


def site_reload(url):
    datas = {
        "ops_code": 200
    }
    data = connect('POST', '/waf/v1/reload', datas, url)
    return data



def site_update(uuid, data, url):
    datas = {
        "site_uuid": uuid,
        "site_conf_data": data,
    }
    data = connect('POST', '/waf/v1/site/update', datas, url)
    return data


def site_delete(uuid, url):
    datas = {
        "site_uuid": uuid
    }
    data = connect('DELETE', '/waf/v1/site/delete', datas, url)
    return data


def cert_add(data, url):
    datas = data
    data = connect('POST', '/waf/v1/cert/add', datas, url)
    return data


def cert_delete(uuid, url):
    datas = {
        "certificate_uuid": uuid
    }
    data = connect('DELETE', '/waf/v1/cert/delete', datas, url)
    return data


def license_view(url):
    datas = {
        "ops_code": 200
    }
    data = connect('POST', '/waf/v1/license/view', datas, url)
    return data


def license_updata(waf_license, url):
    datas = {
        "waf_license": waf_license
    }
    data = connect('POST', '/waf/v1/license/update', datas, url)
    return data


def nodelable_updata(node_label, url, manager_address):
    datas = {
        "node_label": node_label,
        "manager_address": manager_address
    }
    data = connect('POST', '/waf/v1/nodelabel/update', datas, url)
    return data


def rule_reload(request, url):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    datas = {
        "ops_code": 200
    }
    data = connect('POST', '/waf/v1/reload', datas, url)
    try:
        num_id = remote_rule.objects.latest('id').id
    except:
        num_id = 0
    num_id += 1
    remote_rule.objects.create(
        remote_id=num_id,
        remote_use=0,
        remote_details=data['data'],
        remote_user=user
    )
    return data