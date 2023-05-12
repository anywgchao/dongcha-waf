#!/usr/bin env python3
# -*- coding: utf-8 -*-

import os
import time
import datetime
import csv, codecs
from django.shortcuts import HttpResponse
from django.http import StreamingHttpResponse
from SeMFSetting.views import paging
from django.http import JsonResponse
from WafChartManage import models
from RBAC.models import UserLog, User_setting, User_mails
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from SeMF.settings import TMP_PATH, DATABASES, Access_index
from elasticsearch import helpers
import elasticsearch

# 定义服务器，用户名、密码、数据库名称（多个库分行放置）和备份的路径
DB_HOST = DATABASES['default']['HOST']
DB_USER = DATABASES['default']['USER']
DB_USER_PASSWD = DATABASES['default']['PASSWORD']
dbname = DATABASES['default']['NAME']
BACKUP_PATH = TMP_PATH + '/'


def operate_info(request, user, action, name, status):  # 修改网站访问量和访问ip等信息
    try:
        num_id = UserLog.objects.latest('id').id
    except:
        num_id = 0
    if 'HTTP_X_FORWARDED_FOR' in request.META:  # 获取ip
        client_ip = request.META['HTTP_X_FORWARDED_FOR']
        client_ip = client_ip.split(",")[0]  # 所以这里是真实的ip
    else:
        client_ip = request.META['REMOTE_ADDR']  # 这里获得代理ip

    des = action + '了备份文件' + name

    UserLog.objects.create(
        uesr_logid=num_id,
        user_name=user,
        user_ip=client_ip,
        log_type=status,
        user_action=action,
        action_description=user + des,
    )


# 创建备份文件夹
if not os.path.exists(BACKUP_PATH):
    os.makedirs(BACKUP_PATH)


# 定义执行备份脚本，读取文件中的数据库名称，注意按行读写，不校验是否存在该库
def run_backup():
    dbnames = time.strftime('%Y%m%d-%H%M%S') + dbname.strip()
    dumpcmd = "mysqldump -u" + DB_USER + " -p" + DB_USER_PASSWD + " " + dbname + " > " + BACKUP_PATH + dbnames + ".sql"
    os.system(dumpcmd)
    file_size = os.stat(BACKUP_PATH + dbnames + ".sql")
    huamn_readable_size = (file_size.st_size) / 1024 / 1024
    models.Backups.objects.get_or_create(
        backups_name=dbnames + ".sql",
        backups_target='数据库备份',
        backups_size=round(huamn_readable_size, 2)
    )


def backup():
    datas = time.strftime('%Y%m%d-%H%M%S') + 'log'

    f = open('{0}{1}.csv'.format(BACKUP_PATH, datas), 'w', newline='', encoding='utf-8-sig')

    writer = csv.writer(f)
    log_all = UserLog.objects.all()

    headers = ["用户名", "来源ip", "操作时间", "操作类型", '操作描述', '状态']
    writer.writerow(headers)
    for log_item in log_all:
        log_list = []
        log_list.append(log_item.user_name)
        log_list.append(log_item.user_ip)
        log_list.append(str(log_item.updatetime).split('.')[0])
        log_list.append(log_item.log_type)
        log_list.append(log_item.action_description)
        log_list.append(log_item.user_action)
        writer.writerow(log_list)
    f.close()
    file_size = os.stat(BACKUP_PATH + datas + ".csv")
    huamn_readable_size = (file_size.st_size) / 1024 / 1024
    models.Backups.objects.get_or_create(
        backups_name=datas + ".csv",
        backups_target='审计日志备份',
        backups_size=round(huamn_readable_size, 2)
    )


def log_backup():
    index_name = [Access_index]

    es_addr = User_mails.objects.last()
    es_address = es_addr.split('//')[1].split(':')[0]
    port = es_addr.split('//')[1].split(':')[1].strip('/')

    es_search_options = {
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gt": "now-1d"}}}],
            }
        }
    }
    ES_SERVERS = [{'host': es_address, 'port': port}]

    es_client = elasticsearch.Elasticsearch(hosts=ES_SERVERS)
    es_result = helpers.scan(
        client=es_client,
        query=es_search_options,
        scroll='5m',
        index=index_name,
        timeout="1m"
    )
    today = datetime.date.today()
    with open(BACKUP_PATH + 'access' + str(today) + '.log', 'w') as f:
        for item in es_result:
            item = str(item['_source']) + "\n"
            f.write(item)
    f.close()
    file_size = os.stat(BACKUP_PATH + 'access' + str(today) + '.log')
    huamn_readable_size = (file_size.st_size) / 1024 / 1024
    models.Backups.objects.get_or_create(
        backups_name=BACKUP_PATH + 'access' + str(today) + '.log',
        backups_target='访问日志备份',
        backups_size=round(huamn_readable_size, 2)
    )


def remove_files():
    path = BACKUP_PATH
    bretime = User_setting.objects.last()
    if bretime.del_time and bretime.alarm_use=='开启':
        if bretime == '7天':
            bretime = 7
        elif bretime == '一个月':
            bretime = 30
        else:
            bretime = 365
    else:
        bretime = 0
    bretime = time.time() - 3600 * 24 * bretime

    for file in os.listdir(path):
        filename = path + os.sep + file
        if os.path.getmtime(filename) < bretime:
            try:
                if os.path.isfile(filename):
                    os.remove(filename)
                elif os.path.isdir(filename):
                    os.removedirs(filename)
                else:
                    os.remove(filename)
            except Exception as error:
                print(error)
                print("%s remove faild." % filename)


@login_required
@csrf_protect
def backupslist(request):
    today = datetime.date.today()

    current_date = today + datetime.timedelta(days=1)
    former_date = today + datetime.timedelta(days=-7)
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')
    start_time = request.POST.get('start_time')
    end_time = request.POST.get('end_time')
    type = request.POST.get('type')

    if not start_time:
        start_time = [int(x) for x in str(former_date).split('-')]
        start_time = datetime.date(start_time[0], start_time[1], start_time[2])
    else:
        start_time = [int(x) for x in start_time.split('-')]
        start_time = datetime.date(start_time[0], start_time[1], start_time[2])
    if not end_time:
        end_time = [int(x) for x in str(current_date).split('-')]
        end_time = datetime.date(end_time[0], end_time[1], end_time[2])
    else:
        end_time = [int(x) for x in end_time.split('-')]
        end_time = datetime.date(end_time[0], end_time[1], end_time[2])

    if not type:
        type = ''

    loglist = models.Backups.objects.filter(
        task_endtime__range=(start_time, end_time),
        backups_target__icontains=type
    ).all().order_by(
        '-task_endtime')

    total = loglist.count()
    loglist = paging(loglist, rows, page)
    data = []
    for log in loglist:
        dic = {}
        dic['backups_name'] = log.backups_name
        dic['backups_target'] = log.backups_target
        dic['backups_size'] = log.backups_size
        dic['start_time'] = str(log.task_endtime).split('.')[0]
        dic['end_time'] = str(log.task_endtime).split('.')[0]
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "风险事件列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


@login_required
def download(request, log_id):
    if request.method == 'GET':
        """
        下载压缩文件
        :param request:
        :param id: 数据库id
        :return:
        """

        file_path = BACKUP_PATH + log_id
        file_name = log_id

        def file_iterator(file_path, chunk_size=512):
            """
            文件生成器,防止文件过大，导致内存溢出
            :param file_path: 文件绝对路径
            :param chunk_size: 块大小
            :return: 生成器
            """
            with open(file_path, mode='rb') as f:
                while True:
                    c = f.read(chunk_size)
                    if c:
                        yield c
                    else:
                        break

        try:
            # 设置响应头
            # StreamingHttpResponse将文件内容进行流式传输，数据量大可以用这个方法
            response = StreamingHttpResponse(file_iterator(file_path))
            # 以流的形式下载文件,这样可以实现任意格式的文件下载
            response['Content-Type'] = 'application/octet-stream'
            # Content-Disposition就是当用户想把请求所得的内容存为一个文件的时候提供一个默认的文件名
            response['Content-Disposition'] = 'attachment;filename="{}"'.format(file_name)
        except:
            return HttpResponse("Sorry but Not Found the File")
        operate_info(request, str(request.user), '下载', file_name, '成功')
        return response


@login_required
@csrf_protect
def planlist(request):
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')

    loglist = models.PlanTask.objects.all().order_by(
        '-task_endtime')

    total = loglist.count()
    loglist = paging(loglist, rows, page)
    data = []
    for log in loglist:
        dic = {}
        dic['task_name'] = log.task_name
        dic['task_target'] = log.task_target
        dic['task_period'] = log.task_period
        dic['execution'] = log.execution
        dic['task_starttime'] = str(log.task_starttime).split('/')[0]
        dic['task_endtime'] = str(log.task_starttime).split('/')[1]
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "风险事件列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


@login_required
@csrf_protect
def stationlist(request):
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')
    name = request.POST.get('name')
    url_name = request.POST.get('url_name')

    if not name:
        name = ''
    if not url_name:
        url_name = ''

    loglist = models.Station.objects.filter(
        station_name__icontains=name,
        station_url__icontains=url_name
    ).all().order_by(
        '-task_endtime')

    total = loglist.count()
    loglist = paging(loglist, rows, page)
    data = []
    for log in loglist:
        dic = {}
        dic['station_name'] = log.station_name
        dic['station_id'] = log.station_id
        dic['station_url'] = log.station_url
        if log.certificate_ids:
            dic['station_certficate'] = models.Certificate.objects.filter(
                certificate_id=log.certificate_ids).first().certificate_name
        else:
            dic['station_certficate'] = []
        dic['station_agreement'] = log.station_agreement
        dic['task_endtime'] = str(log.task_endtime).split('.')[0]
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "风险事件列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


@login_required
@csrf_protect
def certificatelist(request):
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')
    name = request.POST.get('name')
    if not name:
        name = ''
    loglist = models.Certificate.objects.filter(
        certificate_name__icontains=name).all().order_by(
        '-task_endtime')

    total = loglist.count()
    loglist = paging(loglist, rows, page)
    data = []
    for log in loglist:
        dic = {}
        dic['certificate_name'] = log.certificate_name
        dic['certificate_id'] = log.certificate_id
        dic['impower_time'] = log.impower_time
        dic['certificate_des'] = log.certificate_des
        dic['certificate_public'] = log.certificate_public
        dic['certificate_key'] = log.certificate_key
        dic['task_endtime'] = str(log.task_endtime).split('.')[0]
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "风险事件列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


@login_required
@csrf_protect
def nodelist(request):
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')
    name = request.POST.get('name')
    if not name:
        name = ''

    loglist = models.Node.objects.filter(
        node_name__icontains=name
    ).all().order_by(
        '-node_time')

    total = loglist.count()
    loglist = paging(loglist, rows, page)
    data = []
    for log in loglist:
        dic = {}
        dic['node_id'] = log.node_id
        dic['node_name'] = log.node_name
        dic['node_license'] = log.node_license
        dic['node_impowertime'] = log.node_impowertime
        dic['node_des'] = log.node_des
        dic['node_group'] = str(log.node_group)
        dic['version'] = log.node_version
        dic['task_endtime'] = str(log.node_time).split('.')[0]
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "风险事件列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


@login_required
@csrf_protect
def nodegrouplist(request):
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')
    loglist = models.Node_group.objects.all().order_by(
        '-group_time')
    total = loglist.count()
    loglist = paging(loglist, rows, page)
    data = []
    for log in loglist:
        dic = {}
        dic['group_name'] = log.group_name
        dic['group_time'] = str(log.group_time).split('.')[0]
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "风险事件列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


@login_required
def nodegroupdel(request, group_name):
    error = '已删除'
    models.Node_group.objects.filter(group_name=group_name).delete()
    return JsonResponse({'提示': error}, json_dumps_params={'ensure_ascii': False})
