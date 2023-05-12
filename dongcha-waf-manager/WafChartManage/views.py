# coding:utf-8

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from SeMFSetting.Functions.mails import send_waflog_mail
from django.views.decorators.csrf import csrf_protect
from SettingManage.models import Setting_deploy
from SeMF.settings import Access_index, Intercept_index
from RBAC.models import User_mails
from django.db import close_old_connections
from NoticeManage.views import notice_add
from SeMFSetting.views import paging
from django.http import JsonResponse
from django.utils import timezone
from collections import Counter
from datetime import timedelta
from .alarms import send_dingding
from django.db.models import Count
from .models import Waf_log, PlanTask
from .forms import PlanForm
from elasticsearch import helpers
from elasticsearch import Elasticsearch
import elasticsearch
import time
import json


def counter(arr):
    return Counter(arr).most_common(10)


@login_required
def chartview(request):
    user = request.user
    role = user.profile.roles.all()
    roles = [item.title for item in role][0]
    if roles == '管理员' or roles == '审计员':
        user = ''
    else:
        user = User.objects.filter(username=user).first().profile.user_target
    current_date = timezone.now()

    count = Waf_log.objects.filter(update_data__range=(current_date - timedelta(hours=1), current_date),
                                   log_user__icontains=user).count()
    count_change = count - Waf_log.objects.filter(
        update_data__range=(current_date - timedelta(hours=25), current_date - timedelta(hours=24)),
        log_user__icontains=user).count()

    owasp_count = Waf_log.objects.filter(update_data__range=(current_date - timedelta(hours=1), current_date),
                                         log_type='owasp_log', log_user__icontains=user).count()
    owasp_change = owasp_count - Waf_log.objects.filter(
        update_data__range=(current_date - timedelta(hours=25), current_date - timedelta(hours=24)),
        log_type='owasp_log', log_user__icontains=user).count()

    geo_count = Waf_log.objects.filter(update_data__range=(current_date - timedelta(hours=1), current_date),
                                       log_type='geo_log', log_user__icontains=user).count()
    geo_change = geo_count - Waf_log.objects.filter(
        update_data__range=(current_date - timedelta(hours=25), current_date - timedelta(hours=24)),
        log_type='geo_log', log_user__icontains=user).count()

    cc_count = Waf_log.objects.filter(update_data__range=(current_date - timedelta(hours=1), current_date),
                                      log_type='cc_log', log_user__icontains=user).count()
    cc_change = cc_count - Waf_log.objects.filter(
        update_data__range=(current_date - timedelta(hours=25), current_date - timedelta(hours=24)),
        log_type='cc_log', log_user__icontains=user).count()

    attack_count = Waf_log.objects.values_list('target_address').filter(
        update_data__range=(current_date - timedelta(hours=1), current_date), log_user__icontains=user).all()
    attack_change = Waf_log.objects.values_list('target_address').filter(
        update_data__range=(current_date - timedelta(hours=25), current_date - timedelta(hours=24)),
        log_user__icontains=user).all()
    attack_count = len(set(attack_count))
    attack_change = attack_count - len(set(attack_change))

    return render(request, 'WafChartManage/waf_data.html', {
        'count': count,
        'count_change': count_change,
        'owasp_count': owasp_count,
        'owasp_change': owasp_change,
        'geo_count': geo_count,
        'geo_change': geo_change,
        'cc_count': cc_count,
        'cc_change': cc_change,
        'attack_count': attack_count,
        'attack_change': attack_change,
    })


@login_required
def datasearch(request):
    # return render(request, 'WafChartManage/data_search.html')
    return render(request, 'WafChartManage/log_list.html')


def create(es_addr):
    close_old_connections()  # 防止数据库断开连接
    seconds = 1
    user = User.objects.filter(id=1).first()

    es_address = es_addr.split('//')[1].split(':')[0]
    port = es_addr.split('//')[1].split(':')[1].strip('/')
    hosts = [{'host': es_address, 'port': port}]
    es_client = elasticsearch.Elasticsearch(hosts=hosts)

    es_search_options = {
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gt": "now-{0}m".format(str(seconds))}}}],
            }
        }
    }
    try:
        num_id = Waf_log.objects.latest('id').id
    except:
        num_id = 0

    try:
        es_result = helpers.scan(
            client=es_client,
            query=es_search_options,
            scroll='5m',
            index=Intercept_index,
            timeout="1m"
        )
        alarm_neiwang, alarm_organi, alarm_yisong = [], [], []
        cc_log, web_log, geo_log = 0, 0, 0
        for item in es_result:
            log = item['_source']
            num_id += 1
            log_id = '01' + time.strftime('%Y%m%d', time.localtime(time.time())) + str(num_id)
            Waf_log.objects.create(
                log_id=log_id,
                log_type=log.get('log_type'),
                attack_type=log.get('rule_category'),
                request_time=log.get('http_request_time'),
                attack_origin=log.get('remote_addr'),
                target_address=log.get('http_request_host'),
                uri_address=log.get('rule_uri'),
                describe=log.get('rule_detail'),
                log_user=log.get('platform_tag'),
                detail=log,
            )
            if log.get('log_type') == 'cc_log':
                cc_log += 1
            elif log.get('log_type') == 'geo_log':
                geo_log += 1
            else:
                web_log += 1
            alarm_yisong.append(log.get('rule_detail'))

        data = {
            'notice_title': '拦截日志报警',
            'notice_body': 'HTTP Flood防护{0}条记录,境外区域限制{1}条记录,web安全防护{2}条记录'.format(str(cc_log),str(geo_log),str(web_log)),
            'notice_url': '***',
            'notice_type': 'normal'
        }
        if cc_log !=0 or geo_log !=0 or web_log !=0:
            notice_add(user, data)

        # dingding = Setting_deploy.objects.last()
        # if str(dingding.deploy_alarm) == 'true' and len(alarm_neiwang + alarm_organi + alarm_yisong) > 0:
        #     msg_neiwang = data_processing(alarm_neiwang)
        #     msg_organi = data_processing(alarm_organi)
        #     msg_yisong = data_processing(alarm_yisong)
        #     send_dingding(msg_neiwang, msg_organi, msg_yisong)
    except:
        pass


def data_processing(data):
    data = counter(data)
    data = ''.join(str(i) for i in data).replace('(', '      ').replace(')', '\n').replace('\'', '').replace(',', ': ')
    return data


# 记录日志
def creates():
    try:
        es_address = User_mails.objects.last()
        es_addr = es_address.es_address
        create(es_addr)
    except Exception as e:
        print(e)


DES_DICT = {
    'cc_log': 'HTTP Flood防护',
    'geo_log': '境外区域限制',
    'owasp_log': 'web安全防护',
}


@login_required
@csrf_protect
def log_detail(request, log_id):
    user = request.user
    role = user.profile.roles.all()
    roles = [item.title for item in role][0]
    if roles == '管理员' or roles == '审计员':
        user = ''
    else:
        user = User.objects.filter(username=user).first().profile.user_target
    logs = Waf_log.objects.filter(log_id=log_id, log_user__icontains=str(user)).first()
    logs = logs.detail
    return render(request, 'WafChartManage/details.html', {'log': json.dumps(eval(logs))})


@login_required
@csrf_protect
def log_del(request):
    error = '删除成功'
    from RBAC.models import UserLog
    from RBAC.views import operateinfo
    UserLog.objects.all().delete()
    operateinfo(request, str(request.user), '清除日志', '', '成功')
    return JsonResponse({"error": error})


def datelist(argv=23):
    result = []
    curr_date = timezone.now()
    start_date = curr_date - timedelta(hours=argv)
    while curr_date != start_date:
        result.append("%02d" % (start_date.hour))
        start_date = start_date + timedelta(hours=1)
    result.append("%02d" % (start_date.hour))
    return result


def logdatesecond(request):
    argu = 'hour'
    result = {
        'date': [],
        'common_date': [],
        'xss_date': [],
        'sql_date': [],
        'file_date': [],
        'command_date': [],
        'info_date': [],
        'other_date': [],
    }

    date = datelist(23)
    user = request.user
    role = user.profile.roles.all()
    roles = [item.title for item in role][0]
    if roles == '管理员' or roles == '审计员':
        user = ''
    else:
        user = User.objects.filter(username=user).first().profile.user_target
    result['date'] = date

    current_date = timezone.now()

    # 统计一天内每小时通用基础攻击数量
    common_date = Waf_log.objects.filter(attack_type='通用基础', update_data__range=(current_date - timedelta(hours=23),
                                                                                 current_date),
                                         log_user__icontains=user).extra(
        select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(dcount=Count('update_data'))

    res_data = {}
    for item in common_date:
        res_data[str(item[argu]).zfill(2)] = item['dcount']
    res_date_keys = res_data.keys()
    for item in date:
        if item in res_date_keys:
            result['common_date'].append(res_data[item])
        else:
            result['common_date'].append(0)

    # 统计一天内每小时XSS攻击数量
    xss_date = Waf_log.objects.filter(attack_type='XSS攻击', update_data__range=(current_date - timedelta(hours=23),
                                                                               current_date),
                                      log_user__icontains=user).extra(
        select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(dcount=Count('update_data'))

    res_data = {}
    for item in xss_date:
        res_data[str(item[argu]).zfill(2)] = item['dcount']
    res_date_keys = res_data.keys()
    for item in date:
        if item in res_date_keys:
            result['xss_date'].append(res_data[item])
        else:
            result['xss_date'].append(0)

    # 统计一天内每小时SQL注入攻击数量
    sql_date = Waf_log.objects.filter(attack_type='SQL注入', update_data__range=(current_date - timedelta(hours=23),
                                                                               current_date),
                                      log_user__icontains=user).extra(
        select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(dcount=Count('update_data'))

    res_data = {}
    for item in sql_date:
        res_data[str(item[argu]).zfill(2)] = item['dcount']
    res_date_keys = res_data.keys()
    for item in date:
        if item in res_date_keys:
            result['sql_date'].append(res_data[item])
        else:
            result['sql_date'].append(0)

    # 统计一天内每小时文件读取攻击数量
    file_date = Waf_log.objects.filter(attack_type='文件读取', update_data__range=(current_date - timedelta(hours=23),
                                                                               current_date),
                                       log_user__icontains=user).extra(
        select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(dcount=Count('update_data'))

    res_data = {}
    for item in file_date:
        res_data[str(item[argu]).zfill(2)] = item['dcount']
    res_date_keys = res_data.keys()
    for item in date:
        if item in res_date_keys:
            result['file_date'].append(res_data[item])
        else:
            result['file_date'].append(0)

    # 统计一天内每小时命令注入攻击数量
    command_date = Waf_log.objects.filter(attack_type='命令注入', update_data__range=(current_date - timedelta(hours=23),
                                                                                  current_date),
                                          log_user__icontains=user).extra(
        select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(dcount=Count('update_data'))

    res_data = {}
    for item in command_date:
        res_data[str(item[argu]).zfill(2)] = item['dcount']
    res_date_keys = res_data.keys()
    for item in date:
        if item in res_date_keys:
            result['command_date'].append(res_data[item])
        else:
            result['command_date'].append(0)

    # 统计一天内每小时信息泄露攻击数量
    info_date = Waf_log.objects.filter(attack_type='信息泄露', update_data__range=(current_date - timedelta(hours=23),
                                                                               current_date),
                                       log_user__icontains=user).extra(
        select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(dcount=Count('update_data'))

    res_data = {}
    for item in info_date:
        res_data[str(item[argu]).zfill(2)] = item['dcount']
    res_date_keys = res_data.keys()
    for item in date:
        if item in res_date_keys:
            result['info_date'].append(res_data[item])
        else:
            result['info_date'].append(0)

    # 统计一天内每小时其他攻击数量
    other_date = Waf_log.objects.filter(attack_type=None, update_data__range=(current_date - timedelta(hours=23),
                                                                              current_date),
                                        log_user__icontains=user).extra(
        select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(dcount=Count('update_data'))

    res_data = {}
    for item in other_date:
        res_data[str(item[argu]).zfill(2)] = item['dcount']
    res_date_keys = res_data.keys()
    for item in date:
        if item in res_date_keys:
            result['other_date'].append(res_data[item])
        else:
            result['other_date'].append(0)
    return JsonResponse(result)


@login_required
def logattacktype(request):
    current_date = timezone.now()
    user = request.user
    role = user.profile.roles.all()
    roles = [item.title for item in role][0]
    if roles == '管理员' or roles == '审计员':
        user = ''
    else:
        user = User.objects.filter(username=user).first().profile.user_target

    result = {
        'categories': [],
        'data': [],
    }
    attack_type = Waf_log.objects.filter(
        update_data__range=(current_date - timedelta(hours=23), current_date), log_type='owasp_log',
        log_user__icontains=user).all().values(
        'attack_type').annotate(
        number=Count('id'))

    if attack_type:
        for item in attack_type:
            result['categories'].append(item['attack_type'])
            result['data'].append({'name': item['attack_type'], 'value': item['number']})
    return JsonResponse(result)


@login_required
def logattackorigin(request):
    user = request.user
    role = user.profile.roles.all()
    roles = [item.title for item in role][0]
    if roles == '管理员' or roles == '审计员':
        user = ''
    else:
        user = User.objects.filter(username=user).first().profile.user_target

    current_date = timezone.now()

    results = dict()
    attack_type = Waf_log.objects.filter(
        update_data__range=(current_date - timedelta(hours=23), current_date), log_type='owasp_log',
        log_user__icontains=user).all().values(
        'attack_origin').annotate(
        number=Count('id'))

    if attack_type:
        for item in attack_type:
            results[item['attack_origin']] = item['number']
    results = sorted(results.items(), key=lambda item: item[1], reverse=True)[:5]

    names, values = [i[0] for i in results], [i[1] for i in results]
    results = {'names': names, 'values': values}
    return JsonResponse(results)


@login_required
def logtargetaddress(request):
    user = request.user
    role = user.profile.roles.all()
    roles = [item.title for item in role][0]
    if roles == '管理员' or roles == '审计员':
        user = ''
    else:
        user = User.objects.filter(username=user).first().profile.user_target
    current_date = timezone.now()

    attack_type = Waf_log.objects.filter(
        update_data__range=(current_date - timedelta(hours=23), current_date), log_type='owasp_log',
        log_user__icontains=user).all().values(
        'target_address').annotate(
        number=Count('id'))

    results = dict()
    if attack_type:
        for item in attack_type:
            results[item['target_address']] = item['number']
    results = sorted(results.items(), key=lambda item: item[1], reverse=True)[:5]

    names, values = [i[0] for i in results], [i[1] for i in results]
    results = {'names': names, 'values': values}
    return JsonResponse(results)


@login_required
@csrf_protect
def waflogsearch(request):
    current_date = timezone.now()
    user = request.user
    role = user.profile.roles.all()
    roles = [item.title for item in role][0]
    if roles == '管理员' or roles == '审计员':
        user = ''
    else:
        user = User.objects.filter(username=user).first().profile.user_target
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')

    id_rule = request.POST.get('id_rule')
    if not id_rule:
        id_rule = ''

    id_ip = request.POST.get('id_ip')
    if not id_ip:
        id_ip = ''

    id_target = request.POST.get('id_target')
    if not id_target:
        id_target = ''

    istime = request.POST.get('istimes')
    if not istime:
        istime = 24
    else:
        istime = int(istime)

    loglist = Waf_log.objects.filter(
        update_data__range=(current_date - timedelta(hours=istime), current_date),
        describe__icontains=id_rule,
        attack_origin__icontains=id_ip,
        target_address__icontains=id_target,
        log_user__icontains=str(user),
    ).all().order_by('-update_data')

    total = loglist.count()
    loglist = paging(loglist, rows, page)
    data = []
    for log in loglist:
        dic = {}
        dic['log_id'] = log.log_id
        dic['log_type'] = DES_DICT.get(log.log_type)
        dic['request_time'] = log.request_time
        dic['attack_origin'] = log.attack_origin
        dic['target_address'] = log.target_address
        dic['uri_address'] = log.uri_address
        dic['describe'] = log.describe
        dic['update_data'] = str(log.update_data).split('.')[0]
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "风险事件列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


def logcount(request):
    user = request.user
    role = user.profile.roles.all()
    roles = [item.title for item in role][0]
    if roles == '管理员' or roles == '审计员':
        user = ''
    else:
        user = User.objects.filter(username=user).first().profile.user_target
    date = datelist(23)

    result = {
        'categories': [],
        'data': [],
    }
    result['categories'] = date

    current_date = timezone.now()

    count_date = Waf_log.objects.filter(update_data__range=(current_date - timedelta(days=1), current_date)
                                        , log_user__icontains=user).extra(
        select={'hour': 'extract( hour from update_data )'}).values(
        'hour').annotate(dcount=Count('id'))

    res_data = {}
    for item in count_date:
        res_data[str(item['hour']).zfill(2)] = item['dcount']
    res_date_keys = res_data.keys()
    for item in date:
        if item in res_date_keys:
            result['data'].append(res_data[item])
        else:
            result['data'].append(0)
    return JsonResponse(result)


def waflog_del():
    from SettingManage.models import OS_info
    current_date = timezone.now()
    Waf_log.objects.filter(update_data__lte=(current_date - timedelta(days=7))).delete()
    OS_info.objects.filter(update_data__lte=(current_date - timedelta(days=7))).delete()


# es日志前端数据返回
@login_required
@csrf_protect
def loglist(request):
    resultdict = {}

    page = request.POST.get('page')
    rows = request.POST.get('limit')

    ip_addr = request.POST.get('ip')
    if ip_addr:
        ip_addr = {"term": {"remote_addr": ip_addr}}
    url_addr = request.POST.get('url')
    if url_addr:
        url_addr = {"term": {"url": url_addr}}
    status = request.POST.get('status')
    if status:
        status = {"term": {"status": status}}
    user_agent = request.POST.get('user_agent')
    if user_agent:
        user_agent = {"term": {"http_user_agent": user_agent}}

    date = request.POST.get('istimes')
    loglist, totals = es_data(date, ip_addr, url_addr, status, user_agent, page)
    loglist = paging(loglist, rows, page)
    data = []
    for logs in loglist:
        log = logs['_source']
        dic = {}
        dic['cmd_id'] = logs['_id'] + '@' + logs['_index']
        dic['remote_addr'] = log.get('remote_addr')
        dic['url'] = log.get('url')
        dic['request_uri'] = log.get('request_uri')
        dic['status'] = log.get('status')
        dic['http_user_agent'] = log.get('http_user_agent')
        dic['cmd_info'] = str(log)
        dic['update_data'] = str(log.get('@timestamp')).replace('T', ' ')
        data.append(dic)

    resultdict['code'] = 0
    resultdict['msg'] = "操作审计"
    resultdict['count'] = totals
    resultdict['data'] = data
    return JsonResponse(resultdict)


# es日志查询
def es_data(date=None, ip_addr=None, url_addr=None, status=None, user_agent=None,  page=None):
    start, end = (int(page) - 1) * 20, int(page) * 20
    es, index = es_connect()
    if es and index:
        context_list = [ip_addr, url_addr, status, user_agent]
        rule_list = [rule for rule in context_list if rule]
        if date:
            rule_list.append({"range": {"@timestamp": {"gt": "now-{0}h".format(date)}}})
        query = {
            "query": {
                "bool": {
                    "must": rule_list,
                }
            },
            "sort": {
                "@timestamp": {
                    "order": "desc"
                }
            },
        }
        try:
            query['from'] = start
            query['size'] = end
            resp = es.search(index=index, body=query, ignore=400)
            resp_docs = resp['hits']['hits']
            return resp_docs, resp['hits']['total']['value']
        except:
            query = {"query": {"bool": {"must": rule_list}}, "sort": {"@timestamp": {"order": "desc"}}}
            size = 10000
            queryData = es.search(index=index, body=query, size=size, scroll='1m', )
            resp_docs = queryData.get("hits").get("hits")

            # scroll_id 的值就是上一个请求中返回的 _scroll_id 的值
            scroll_id = queryData['_scroll_id']  # 获取scrollID
            total = queryData['hits']['total']['value']  # 返回数据的总条数

            for i in range(divmod(total, size)[0] + 1):
                res = es.scroll(scroll_id=scroll_id, scroll='1m')  # scroll参数必须指定否则会报错
                resp_docs += res["hits"]["hits"]
            return resp_docs, total
    else:
        return [], 0


# 连接es
def es_connect():
    try:
        es_address = User_mails.objects.last()
        es_addr = es_address.es_address
        ip_addr = es_addr.split('//')[1].split(':')[0]
        port = es_addr.split('//')[1].split(':')[1].strip('/')
        es = Elasticsearch([{'host': ip_addr, 'port': port}], timeout=3600)
        index = Access_index
        return es, index
    except:
        return '', ''


# 详情展示
@login_required
@csrf_protect
def log_details(request, log_id):
    es, index = es_connect()
    query = {
        "query": {
            "ids": {
                "values": [
                    log_id.split('@')[0]
                ]
            }
        }
    }
    resp = es.search(index=log_id.split('@')[1], body=query, ignore=400)
    resp_docs = resp['hits']['hits'][0]['_source']
    return render(request, 'WafChartManage/log_details.html', {'log': json.dumps(resp_docs)})


def total_count(keyword):
    es, index = es_connect()
    query = {"aggs" : {"{0}".format(keyword) : {"terms" : {"field" : "{0}.keyword".format(keyword)}}}}
    return es.search(index=index, body=query, ignore=400)['aggregations'][keyword]['buckets']


@login_required
def acceslogiporigin(request):
    data = total_count('remote_addr')
    names = [i['key'] for i in data][:5]
    values = [i['doc_count'] for i in data][:5]
    results = {'names': names, 'values': values}
    return JsonResponse(results)


@login_required
def acceslogurlorigin(request):
    data = total_count('url')
    names = [i['key'] for i in data][:5]
    values = [i['doc_count'] for i in data][:5]
    results = {'names': names, 'values': values}
    return JsonResponse(results)


@login_required
def acceslogstatus(request):
    result= {}
    data = total_count('status')
    result['categories'] = [i['key'] for i in data]
    result['data'] = [{'name':i['key'], 'value':i['doc_count']} for i in data]
    return JsonResponse(result)

def waf_mail():
    users = [i.username for i in User.objects.all()]
    for user in users:
        results = dict()
        user_get = User.objects.filter(username=user).first()
        es_address = user_get.profile.es_address
        if es_address:
            user = user_get.profile.user_target
            argu = 'hour'
            result = {
                'date': [],
                'common_date': [],
                'xss_date': [],
                'sql_date': [],
                'file_date': [],
                'command_date': [],
                'info_date': [],
                'other_date': [],
            }

            date = datelist(23)

            result['date'] = date

            current_date = timezone.now()

            count = Waf_log.objects.filter(update_data__range=(current_date - timedelta(hours=24), current_date),
                                           log_user=user).count()
            count_change = count - Waf_log.objects.filter(
                update_data__range=(current_date - timedelta(hours=48), current_date - timedelta(hours=24)),
                log_user=user).count()

            owasp_count = Waf_log.objects.filter(update_data__range=(current_date - timedelta(hours=24), current_date),
                                                 log_type='owasp_log', log_user=user).count()
            owasp_change = owasp_count - Waf_log.objects.filter(
                update_data__range=(current_date - timedelta(hours=48), current_date - timedelta(hours=24)),
                log_type='owasp_log', log_user=user).count()

            geo_count = Waf_log.objects.filter(update_data__range=(current_date - timedelta(hours=24), current_date),
                                               log_type='geo_log', log_user=user).count()
            geo_change = geo_count - Waf_log.objects.filter(
                update_data__range=(current_date - timedelta(hours=48), current_date - timedelta(hours=24)),
                log_type='geo_log', log_user=user).count()

            cc_count = Waf_log.objects.filter(update_data__range=(current_date - timedelta(hours=24), current_date),
                                              log_type='cc_log', log_user=user).count()
            cc_change = cc_count - Waf_log.objects.filter(
                update_data__range=(current_date - timedelta(hours=48), current_date - timedelta(hours=24)),
                log_type='cc_log', log_user=user).count()

            attack_count = Waf_log.objects.values_list('target_address').filter(
                update_data__range=(current_date - timedelta(hours=24), current_date), log_user=user).all()
            attack_change = Waf_log.objects.values_list('target_address').filter(
                update_data__range=(current_date - timedelta(hours=48), current_date - timedelta(hours=24)),
                log_user=user).all()
            attack_count = len(set(attack_count))
            attack_change = attack_count - len(set(attack_change))

            # 统计一天内每小时通用基础攻击数量
            common_date = Waf_log.objects.filter(attack_type='通用基础',
                                                 update_data__range=(current_date - timedelta(hours=23),
                                                                     current_date), log_user=user).extra(
                select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(
                dcount=Count('update_data'))

            res_data = {}
            for item in common_date:
                res_data[str(item[argu]).zfill(2)] = item['dcount']
            res_date_keys = res_data.keys()
            for item in date:
                if item in res_date_keys:
                    result['common_date'].append(res_data[item])
                else:
                    result['common_date'].append(0)

            # 统计一天内每小时XSS攻击数量
            xss_date = Waf_log.objects.filter(attack_type='XSS攻击',
                                              update_data__range=(current_date - timedelta(hours=23),
                                                                  current_date), log_user=user).extra(
                select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(
                dcount=Count('update_data'))

            res_data = {}
            for item in xss_date:
                res_data[str(item[argu]).zfill(2)] = item['dcount']
            res_date_keys = res_data.keys()
            for item in date:
                if item in res_date_keys:
                    result['xss_date'].append(res_data[item])
                else:
                    result['xss_date'].append(0)

            # 统计一天内每小时SQL注入攻击数量
            sql_date = Waf_log.objects.filter(attack_type='SQL注入',
                                              update_data__range=(current_date - timedelta(hours=23),
                                                                  current_date), log_user=user).extra(
                select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(
                dcount=Count('update_data'))

            res_data = {}
            for item in sql_date:
                res_data[str(item[argu]).zfill(2)] = item['dcount']
            res_date_keys = res_data.keys()
            for item in date:
                if item in res_date_keys:
                    result['sql_date'].append(res_data[item])
                else:
                    result['sql_date'].append(0)

            # 统计一天内每小时文件读取攻击数量
            file_date = Waf_log.objects.filter(attack_type='文件读取',
                                               update_data__range=(current_date - timedelta(hours=23),
                                                                   current_date), log_user=user).extra(
                select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(
                dcount=Count('update_data'))

            res_data = {}
            for item in file_date:
                res_data[str(item[argu]).zfill(2)] = item['dcount']
            res_date_keys = res_data.keys()
            for item in date:
                if item in res_date_keys:
                    result['file_date'].append(res_data[item])
                else:
                    result['file_date'].append(0)

            # 统计一天内每小时命令注入攻击数量
            command_date = Waf_log.objects.filter(attack_type='命令注入',
                                                  update_data__range=(current_date - timedelta(hours=23),
                                                                      current_date), log_user=user).extra(
                select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(
                dcount=Count('update_data'))

            res_data = {}
            for item in command_date:
                res_data[str(item[argu]).zfill(2)] = item['dcount']
            res_date_keys = res_data.keys()
            for item in date:
                if item in res_date_keys:
                    result['command_date'].append(res_data[item])
                else:
                    result['command_date'].append(0)

            # 统计一天内每小时信息泄露攻击数量
            info_date = Waf_log.objects.filter(attack_type='信息泄露',
                                               update_data__range=(current_date - timedelta(hours=23),
                                                                   current_date), log_user=user).extra(
                select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(
                dcount=Count('update_data'))

            res_data = {}
            for item in info_date:
                res_data[str(item[argu]).zfill(2)] = item['dcount']
            res_date_keys = res_data.keys()
            for item in date:
                if item in res_date_keys:
                    result['info_date'].append(res_data[item])
                else:
                    result['info_date'].append(0)

            # 统计一天内每小时其他攻击数量
            other_date = Waf_log.objects.filter(attack_type=None,
                                                update_data__range=(current_date - timedelta(hours=23),
                                                                    current_date), log_user=user).extra(
                select={'hour': 'extract( hour from update_data )'}).values('hour').annotate(
                dcount=Count('update_data'))

            res_data = {}
            for item in other_date:
                res_data[str(item[argu]).zfill(2)] = item['dcount']
            res_date_keys = res_data.keys()
            for item in date:
                if item in res_date_keys:
                    result['other_date'].append(res_data[item])
                else:
                    result['other_date'].append(0)

            result1 = {
                'categories': [],
                'data': [],
            }
            attack_type = Waf_log.objects.filter(
                update_data__range=(current_date - timedelta(hours=23), current_date), log_type='owasp_log',
                log_user=user).all().values(
                'attack_type').annotate(
                number=Count('id'))

            if attack_type:
                for item in attack_type:
                    result1['categories'].append(item['attack_type'])
                    result1['data'].append({'name': item['attack_type'], 'value': item['number']})

            data_result = {
                'counts': str(count),
                'count_change': str(count_change),
                'owasp_count': str(owasp_count),
                'owasp_change': str(owasp_change),
                'geo_count': str(geo_count),
                'geo_change': str(geo_change),
                'cc_count': str(cc_count),
                'cc_change': str(cc_change),
                'attack_count': str(attack_count),
                'attack_change': str(attack_change),
                'result2': result,
                'result1': result1,
            }
            results[user] = data_result
            send_waflog_mail(user_get.email, results)


@login_required
def plantask_add(request):
    from WafChartManage.urls import actions
    error = ''
    if request.method == 'POST':
        form = PlanForm(request.POST)
        if form.is_valid():
            task_name = form.cleaned_data['task_name']
            task_target = form.cleaned_data['task_target']
            execution = form.cleaned_data['execution']
            if request.POST.get('time_start'):
                time_start = request.POST.get('time_start')
            else:
                time_start = '2020-02-20'
            if request.POST.get('time_end'):
                time_end = request.POST.get('time_end')
            else:
                time_end = '2040-02-20'
            task_starttime = time_start + '/' + time_end
            task_period = deal_null(request.POST.get('min')) + ' ' + deal_null(
                request.POST.get('hour')) + ' ' + deal_null(request.POST.get(
                'dates')) + ' ' + deal_null(request.POST.get('month')) + ' ' + deal_null(request.POST.get('week'))

            error = input_cro(request.POST.get('min'), request.POST.get('hour'), request.POST.get('dates'),
                              request.POST.get('month'), request.POST.get('week'))
            if error:
                error = error
            else:
                git = PlanTask.objects.filter(task_name=task_name).first()
                if git:
                    error = '温馨提示! 该任务已存在'
                    actions()
                else:
                    PlanTask.objects.get_or_create(
                        task_name=task_name,
                        task_target=task_target,
                        execution=execution,
                        task_period=task_period,
                        task_starttime=task_starttime
                    )
                    actions()
                    error = '任务创建成功'
        else:
            error = '非法输入或规则已存在'
        return render(request, 'SettingManage/plantask_add.html',
                      {'form': form, 'post_url': 'plantask_add', 'error': error})
    else:
        form = PlanForm()
    return render(request, 'SettingManage/plantask_add.html',
                  {'form': form, 'post_url': 'plantask_add', 'error': error})


@login_required
@csrf_protect
def plantask_update(request, task_name):
    from WafChartManage.urls import actions
    user = request.user
    error = ''
    task_datas = PlanTask.objects.filter(task_name=task_name).first()
    task_data = dict()
    try:
        task_data['min'] = task_datas.task_period.split(' ')[0]
        task_data['hour'] = task_datas.task_period.split(' ')[1]
        task_data['dates'] = task_datas.task_period.split(' ')[2]
        task_data['month'] = task_datas.task_period.split(' ')[3]
        task_data['week'] = task_datas.task_period.split(' ')[4]
        task_data['time_start'] = task_datas.task_starttime.split('/')[0]
        task_data['time_end'] = task_datas.task_starttime.split('/')[1]
    except:
        pass

    tasks = get_object_or_404(PlanTask, task_name=task_name)
    if request.method == 'POST':
        form = PlanForm(request.POST, instance=tasks)
        if form.is_valid():
            if request.POST.get('time_start'):
                time_start = request.POST.get('time_start')
            else:
                time_start = '2020-02-20'
            if request.POST.get('time_end'):
                time_end = request.POST.get('time_end')
            else:
                time_end = '2040-02-20'
            task_starttime = time_start + '/' + time_end
            task_period = deal_null(request.POST.get('min')) + ' ' + deal_null(
                request.POST.get('hour')) + ' ' + deal_null(request.POST.get(
                'dates')) + ' ' + deal_null(request.POST.get('month')) + ' ' + deal_null(request.POST.get('week'))
            error = input_cro(request.POST.get('min'), request.POST.get('hour'), request.POST.get('dates'),
                              request.POST.get('month'), request.POST.get('week'))
            if error:
                error = error
            else:
                tasks.task_starttime = task_starttime
                tasks.task_period = task_period
                tasks.save()
                form.save()
                error = '修改成功'
                actions()
        else:
            error = '请检查输入'
            actions()
    else:
        form = PlanForm(instance=tasks)
    return render(request, 'SettingManage/task_list.html',
                  {'form': form, 'post_url': 'plantaskupdate', 'argu': task_name, 'error': error,
                   'task_data': task_data})


@login_required
def plantask_del(request, task_name):
    error = '已删除'
    PlanTask.objects.filter(task_name=task_name).delete()
    return JsonResponse({'提示': error}, json_dumps_params={'ensure_ascii': False})


def deal_null(data):
    if data:
        return data
    else:
        return '1'


def input_cro(min, hour, dates, month, week):
    error = ''
    try:
        if min != "*":
            try:
                if int(min) <= 59 and int(min) >= 0:
                    pass
                else:
                    error = '请输入正确分钟'
            except:
                error = '请输入正确分钟'
        if hour != '*':
            if '/' in hour:
                dates1 = hour.split('/')[-1]
                try:
                    if int(dates1) <= 23 and int(dates1) >= 0:
                        pass
                    else:
                        error = '请输入正确小时'
                except:
                    error = '请输入正确小时'
            elif '-' in hour:
                dates1 = hour.split('-')[0]
                dates2 = hour.split('-')[-1]
                try:
                    if int(dates1) <= 23 and int(dates1) >= 0 and int(dates2) <= 23 and int(dates2) >= 0 and int(
                            dates1) < int(dates2):
                        pass
                    else:
                        error = '请输入正确小时'
                except:
                    error = '请输入正确小时'
            else:
                try:
                    if int(hour) <= 23 and int(hour) >= 0:
                        pass
                    else:
                        error = '请输入正确小时'
                except:
                    error = '请输入正确小时'

        if dates != '*':
            if '/' in dates:
                dates1 = dates.split('/')[-1]
                try:
                    if int(dates1) <= 31 and int(dates1) >= 1:
                        pass
                    else:
                        error = '请输入正确日期'
                except:
                    error = '请输入正确日期'
            elif '-' in dates:
                dates1 = dates.split('-')[0]
                dates2 = dates.split('-')[-1]
                try:
                    if int(dates1) <= 31 and int(dates1) >= 1 and int(dates2) <= 31 and int(dates2) >= 1 and int(
                            dates1) < int(dates2):
                        pass
                    else:
                        error = '请输入正确日期'
                except:
                    error = '请输入正确日期'
            else:
                try:
                    if int(dates) <= 31 and int(dates) >= 1:
                        pass
                    else:
                        error = '请输入正确日期'
                except:
                    error = '请输入正确日期'
        if month != '*':
            if '/' in month:
                dates1 = month.split('/')[-1]
                try:
                    if int(dates1) <= 12 and int(dates1) >= 1:
                        pass
                    else:
                        error = '请输入正确月份'
                except:
                    error = '请输入正确月份'
            elif '-' in month:
                dates1 = month.split('-')[0]
                dates2 = month.split('-')[-1]
                try:
                    if int(dates1) <= 12 and int(dates1) >= 1 and int(dates2) <= 12 and int(dates2) >= 1 and int(
                            dates1) < int(dates2):
                        pass
                    else:
                        error = '请输入正确月份'
                except:
                    error = '请输入正确月份'
            else:
                try:
                    if int(month) <= 12 and int(month) >= 1:
                        pass
                    else:
                        error = '请输入正确月份'
                except:
                    error = '请输入正确月份'
        if week != '*':
            if '/' in week:
                dates1 = week.split('/')[-1]
                try:
                    if int(dates1) <= 54 and int(dates1) >= 1:
                        pass
                    else:
                        error = '请输入正确周'
                except:
                    error = '请输入正确周'
            elif '-' in week:
                dates1 = week.split('-')[0]
                dates2 = week.split('-')[-1]
                try:
                    if int(dates1) <= 54 and int(dates1) >= 1 and int(dates2) <= 54 and int(dates2) >= 1 and int(
                            dates1) < int(dates2):
                        pass
                    else:
                        error = '请输入正确周'
                except:
                    error = '请输入正确周'
            else:
                try:
                    if int(week) <= 54 and int(week) >= 1:
                        pass
                    else:
                        error = '请输入正确周数'
                except:
                    error = '请输入正确周数'
        return error
    except:
        error = '输入时间格式错误'
        return error
