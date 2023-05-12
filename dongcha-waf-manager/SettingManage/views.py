# coding:utf-8
from django.shortcuts import render, get_object_or_404, render_to_response
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
from SeMFSetting.views import paging
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.db.models import Count
from . import models, forms
from datetime import timedelta
from django.utils import timezone
import time
import uuid
import psutil
import os

ALARM = {
    'true': 'checked',
    'flase': ''
}


@login_required
@csrf_protect
def SettingView(request):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    setting = models.Setting_deploy.objects.filter(deploy_user=user).last()
    alarms = models.Setting_deploy.objects.last()
    check = {}
    if setting:
        setting = eval(setting.deploy_data)
        check['alarms'] = ALARM[str(alarms.deploy_alarm)]
        for key, value in setting.items():
            if value == 'true':
                check[key] = 'checked'
            elif value == 'false':
                check[key] = ''
            else:
                check[key] = value
        if check['log_remote'] == 'checked':
            check[setting['log_sock_type']] = 'selected'
    return render(request, "SettingManage/Setting.html", {'check': check})


@login_required
@csrf_protect
def get_rule(request):
    error = ""
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    if request.method == "POST" and request.POST.get("rule") != None:
        try:
            num_id = models.Setting_template.objects.latest("id").id
        except:
            num_id = 0
        rule_name = request.POST.get("rule")
        content_type = request.POST.get("content_type")
        desc = request.POST.get("desc")
        template_create = models.Setting_template.objects.get_or_create(
            setting_id=num_id,
            setting_name=rule_name,
            setting_type=content_type,
            setting_content=desc,
            template_user=user,
        )
        error = "添加成功"
    else:
        pass
    return render(request, "SettingManage/rule_template.html", {"post_url": "get_rule", "error": error})


@login_required
@csrf_protect
def get_setting(request):
    deploy = {}
    error = ""
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    list_vul = ["log_local", "http_redirect", "base_engine", "observ_mode", "log_all", "cc_engine", "log_remote",
                "log_port",
                "log_ip", "log_sock_type", "log_flush_limit", "resp_engine", "cookie_safe", "cookie_safe_is_safe",
                "geo_protection",
                "cookie_safe_client_ip", "aes_random_key", "cookie_safe_client_ip"]

    if request.method == "POST" and request.POST:
        deploy_gloab = dict(request.POST)
        try:
            num_id = models.Setting_deploy.objects.latest("id").id
        except:
            num_id = 0
        num_id += 1
        num_id = time.strftime('%Y%m%d', time.localtime(time.time())) + str(num_id)
        deploy["observ_mode_white_ip"] = ["false"]
        for i in list_vul:
            vul = deploy_gloab.get(i)
            if not vul:
                deploy[i] = "false"
            elif vul == ["on"]:
                deploy[i] = "true"
            else:
                deploy[i] = ",".join(str(k) for k in vul)
        if deploy['log_remote'] == 'false':
            deploy['log_port'] = ''
            deploy['log_ip'] = ''
            deploy['log_sock_type'] = ''
            deploy['log_flush_limit'] = ''
        else:
            if deploy['log_port'] == '':
                deploy['log_port'] = '5555'
            if deploy['log_ip'] == '':
                deploy['log_ip'] = '127.0.0.1'
            if deploy['log_sock_type'] == '':
                deploy['log_sock_type'] = 'udp'
            if deploy['log_flush_limit'] == '':
                deploy['log_flush_limit'] = '1'

        alarm = deploy_gloab.get('alarms')
        if alarm == ['on']:
            alarm = 'true'
        else:
            alarm = 'flase'

        deploy_create = models.Setting_deploy.objects.get_or_create(
            deploy_id=num_id,
            deploy_data=deploy,
            deploy_user=user,
            deploy_alarm=alarm
        )

        setting = models.Setting_deploy.objects.filter(deploy_user=user).last()
        alarms = models.Setting_deploy.objects.last()
        check = {}
        setting = eval(setting.deploy_data)
        check['alarms'] = ALARM[str(alarms.deploy_alarm)]
        for key, value in setting.items():
            if value == 'true':
                check[key] = 'checked'
            elif value == 'false':
                check[key] = ''
            else:
                check[key] = value
        if check['log_remote'] == 'checked':
            check[setting['log_sock_type']] = 'selected'
        error = '配置成功'
        return render(request, "SettingManage/Setting.html", {'check': check, "error": error})
    else:
        error = "配置失败"
    return render(request, "SettingManage/Setting.html", {"post_url": "get_setting", "error": error})


@login_required
@csrf_protect
def rule_template(request):
    return render(request, "SettingManage/rule_template.html")


@login_required
@csrf_protect
def setting_update(request, setting_id):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    error = ""

    setting = get_object_or_404(models.Setting_template, setting_id=setting_id, template_user=str(user))
    if request.method == "POST":
        form = forms.Setting_template_form(request.POST, instance=setting)
        if form.is_valid():
            form.save()
            error = "修改成功"
        else:
            error = "请检查输入"
    else:
        form = forms.Setting_template_form(instance=setting)
    return render(request, "formupdate.html",
                  {"form": form, "post_url": "settingupdate", "argu": setting_id, "error": error})


@login_required
def setting_del(request, setting_id):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    error = "已删除"
    setting = models.Setting_template.objects.filter(setting_id=setting_id, template_user=user).delete()
    return JsonResponse({"提示": error}, json_dumps_params={"ensure_ascii": False})


TYPE = {
    "0": "text/html",
    "1": "application/json",
}
USE = {
    "0": "启用",
    "1": "未启用",
}


@login_required
@csrf_protect
def templatelist(request):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    resultdict = {}
    page = request.POST.get("page")
    rows = request.POST.get("limit")

    name = request.POST.get("name")
    if not name:
        name = ""
    key = request.POST.get("key")

    if not key:
        key = ""

    ruleslist = models.Setting_template.objects.filter(
        setting_id__icontains=key,
        template_user=str(user),
    ).order_by("-setting_updatetime")

    total = ruleslist.count()
    ruleslist = paging(ruleslist, rows, page)
    data = []
    for setting_item in ruleslist:
        dic = {}
        dic["setting_id"] = setting_item.setting_id
        dic["rule_name"] = setting_item.setting_name
        dic["content_type"] = TYPE[setting_item.setting_type]
        dic["setting_use"] = USE[setting_item.setting_use]
        dic["desc"] = setting_item.setting_content
        data.append(dic)
    resultdict["code"] = 0
    resultdict["msg"] = "用户列表"
    resultdict["count"] = total
    resultdict["data"] = data
    return JsonResponse(resultdict)


def test(request):
    key = uuid.uuid1()
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    create = models.Setting_uuid.objects.get_or_create(
        uuid=key,
        uuid_user=user,
    )
    secure_key = models.Setting_uuid.objects.filter(uuid_user=user).all().order_by("-uuid_updatetime")[0]
    secure_key = secure_key.uuid
    return render_to_response("SettingManage/Setting.html", {'key': secure_key})


def datelist(argv=23):
    result = []
    curr_date = timezone.now()
    start_date = curr_date - timedelta(minutes=argv)
    while curr_date != start_date:
        result.append("%02d" % (start_date.minute))
        start_date = start_date + timedelta(minutes=1)
    result.append("%02d" % (start_date.minute))
    return result


def host_view(request):
    result = {
    }

    date = datelist(23)

    result['date'] = date

    current_date = timezone.now()

    cpu_date = models.OS_info.objects.filter(
        updatetime__range=(current_date - timedelta(hours=23), current_date)).values_list('os_cpu').order_by("-id")[:24]
    mem_date = models.OS_info.objects.filter(
        updatetime__range=(current_date - timedelta(hours=23), current_date)).values_list('os_men').order_by("-id")[:24]
    resource_date = models.OS_info.objects.filter(
        updatetime__range=(current_date - timedelta(hours=23), current_date)).values_list('os_resource').order_by(
        "-id")[:24]
    load_date = models.OS_info.objects.filter(
        updatetime__range=(current_date - timedelta(hours=23), current_date)).values_list('os_load').order_by("-id")[
                :24]
    disk_date = models.OS_info.objects.filter(
        updatetime__range=(current_date - timedelta(hours=23), current_date)).values_list('disk_readio').order_by(
        "-id")[:24]
    disk_wdate = models.OS_info.objects.filter(
        updatetime__range=(current_date - timedelta(hours=23), current_date)).values_list('disk_writeio').order_by(
        "-id")[:24]
    net_date = models.OS_info.objects.filter(
        updatetime__range=(current_date - timedelta(hours=23), current_date)).values_list('net_sent').order_by("-id")[
               :24]
    net_wdate = models.OS_info.objects.filter(
        updatetime__range=(current_date - timedelta(hours=23), current_date)).values_list('net_recv').order_by("-id")[
                :24]

    result['cpu_date'] = deal_list([i[0] for i in cpu_date])
    result['mem_date'] = deal_list([i[0] for i in mem_date])
    result['resource_date'] = deal_list([i[0] for i in resource_date])
    result['load_date'] = deal_list([i[0].split('/')[0] for i in load_date])
    result['load_date1'] = deal_list([i[0].split('/')[1] for i in load_date])
    result['load_date2'] = deal_list([i[0].split('/')[2] for i in load_date])
    result['disk_date'] = deal_list([i[0] for i in disk_date])
    result['disk_wdate'] = deal_list([i[0] for i in disk_wdate])
    result['net_date'] = deal_list([i[0] for i in net_date])
    result['net_wdate'] = deal_list([i[0] for i in net_wdate])
    return JsonResponse(result)


def deal_list(lists):
    for i in range(24):
        if len(lists) < 24:
            lists.append('')
        else:
            break
    lists.reverse()
    return lists


from NoticeManage.views import notice_add


def host_info():
    user = User.objects.filter(id = 1).first()
    load = os.popen('uptime').readlines()
    load = [i.split() for i in load][0]
    load = load[-3].strip(',') + '/' + load[-2].strip(',') + '/' + load[-1].strip(',')

    cpu_info = psutil.cpu_percent(1)
    mem_info = psutil.virtual_memory().percent
    disk_info = psutil.disk_usage('/').percent
    disk_rio = int(psutil.disk_usage('/').used) // 1024 // 1024 // 1024
    disk_wio = int(psutil.disk_usage('/').free) // 1024 // 1024 // 1024
    net_rio = int(psutil.net_io_counters().bytes_sent) // 1024 // 1024 // 1024
    net_wio = int(psutil.net_io_counters().bytes_recv) // 1024 // 1024 // 1024
    models.OS_info.objects.get_or_create(
        os_cpu=cpu_info,
        os_men=mem_info,
        os_resource=disk_info,
        os_load=load,
        disk_readio=disk_rio,
        disk_writeio=disk_wio,
        net_sent=net_rio,
        net_recv=net_wio,
    )
    if int(mem_info) >= 80 or int(cpu_info) >= 80 or int(disk_info) >= 80:

        data = {
            'notice_title': '监控报警',
            'notice_body': '内存使用率{0}%,cpu使用率{1}%,磁盘使用率{2}%'.format(str(mem_info),str(cpu_info),str(disk_info)),
            'notice_url': '***',
            'notice_type': 'notice'
        }
        notice_add(user, data)
