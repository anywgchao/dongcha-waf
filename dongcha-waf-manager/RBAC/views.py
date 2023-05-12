# coding:utf-8
from django.shortcuts import render, HttpResponseRedirect, get_object_or_404
# Create your views here.
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
import django.utils.timezone as timezone
from django.contrib import auth
import datetime, time
from SeMFSetting.Functions.checkpsd import checkpsd, emaillist, phonelist, checkmail, checkpone
from . import forms, models
import hashlib
from django.contrib.auth.hashers import make_password
from .templatetags.check_code import create_validate_code
from SeMFSetting.views import paging, strtopsd
from SeMFSetting.Functions import mails, waf_manage
from SettingManage.models import Setting_deploy, Setting_template
from RuleManage.models import Rules, CC_rule, remote_rule
from .service.init_permission import init_permission
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from geetest import GeetestLib
from SeMF.settings import pc_geetest_id, pc_geetest_key, AGENT_KEY
from WafChartManage.models import Waf_log
from datetime import timedelta
from qrcode import QRCode, constants
from django.conf import settings
from WafChartManage.forms import CertificateForm, NodeForm, NodegroupForm, ImpowertimeForm
from WafChartManage.models import Certificate, Node, Station, Node_group
from io import BytesIO
from pypinyin import lazy_pinyin
import psutil
import uuid
import os
import random
import string
import pyotp
import json
import ssl
import requests

ssl._create_default_https_context = ssl._create_unverified_context

REAUEST_STATUS = {
    "0": "待审批",
    "1": "审批通过",
    "2": "审批拒绝",
}
KIND = {
    "0": "通用基础",
    "1": "SQL注入",
    "2": "XSS攻击",
    "3": "命令注入",
    "4": "代码执行",
    "5": "上传漏洞",
    "6": "信息泄露",
    "7": "逻辑漏洞",
    "8": "权限绕过",
    "9": "文件读取",
    "10": "其他",
}
LOG_USE = {
    "0": "true",
    "1": "false",
}
TYPE = {
    '0': 'text/html',
    '1': 'application/json',
}


@csrf_exempt
def deploy(request):
    try:
        if request.method == "POST":  # 当提交表单时
            if request.body:
                try:
                    key = json.loads(request.body).get("api_key")
                    tag = json.loads(request.body).get("platform_tag")
                except:
                    key = str(request.body).split("'")[1].split('=')[1]
                    tag = ''
                user_get = User.objects.all()
                taget_list = [i.profile.user_target for i in user_get]
                if tag in taget_list:
                    if key == AGENT_KEY:
                        if Setting_deploy.objects.filter(deploy_user=tag).all().order_by("-deploy_updatetime"):
                            if Setting_template.objects.filter(setting_use=0, template_user=tag):
                                deploy = \
                                    Setting_deploy.objects.filter(deploy_user=tag).all().order_by("-deploy_updatetime")[
                                        0]
                                template = Setting_template.objects.filter(setting_use=0, template_user=tag).first()
                                deploy = eval(deploy.deploy_data)
                                deploy['template_status'] = 'true'
                                deploy['template_name'] = template.setting_name
                                deploy['template_type'] = TYPE[template.setting_type]
                                deploy['template_content'] = template.setting_content
                                deploy = json.dumps(deploy)
                                return HttpResponse(deploy)
                            else:
                                deploy = \
                                    Setting_deploy.objects.filter(deploy_user=tag).all().order_by("-deploy_updatetime")[
                                        0]
                                deploy = eval(deploy.deploy_data)
                                deploy['template_status'] = 'false'
                                deploy['template_name'] = ''
                                deploy['template_type'] = ''
                                deploy['template_content'] = ''
                                deploy = json.dumps(deploy)
                                return HttpResponse(deploy)
                        else:
                            error = {"status": 400, "data": {"title": "WAFsetting Api"}, "msg": "Temporarily no data"}
                            return JsonResponse(error)
                    else:
                        error = {"status": 400, "data": {"title": "WAFsetting Api"}, "msg": "The secret key error"}
                        return JsonResponse(error)
                else:
                    error = {"status": 400, "data": {"title": "WAFsetting Api"}, "msg": "The secret tag error"}
                    return JsonResponse(error)
            else:
                error = {"status": 400, "data": {"title": "WAFsetting Api"}, "msg": "Unsubmitted parameter"}
                return JsonResponse(error)
        else:
            error = {"status": 400, "data": {"title": "WAFsetting Api"}, "msg": "Submission mode error"}
            return JsonResponse(error)
    except Exception as e:
        print(e)
        error = {"status": 500, "data": {"title": "WAFsetting Api"}, "msg": "Internal error"}
        return JsonResponse(error)


def get_remotedata(tag):
    try:
        data = remote_rule.objects.filter(remote_user=tag).last()
        if data:
            return data.remote_details
        else:
            return 1
    except:
        return 1



@csrf_exempt
def rules(request):
    try:
        if request.method == "POST":
            if request.body:
                try:
                    key = json.loads(request.body).get("api_key")
                    tag = json.loads(request.body).get("platform_tag")
                except:
                    key = str(request.body).split("'")[1].split('=')[1]
                    tag = ''
                user_get = User.objects.all()
                taget_list = [i.profile.user_target for i in user_get]
                if tag in taget_list:
                    if key == AGENT_KEY:
                        remote_data = get_remotedata(tag)
                        if remote_data != 1:
                            rules = Rules.objects.filter(rule_group__rules_use=0, rule_user=tag).exclude(
                                rule_group__rules_details='基础防护规则集', rule_use=1).all()
                        else:
                            rules = Rules.objects.filter(rule_group__rules_use=0, rule_user=tag).exclude(rule_use=1).all()
                        cc_rules = CC_rule.objects.filter(cc_group__ccgroup_use=0, cc_user=tag).exclude(
                            rule_use=1).all()
                        data = []
                        for rule in rules:
                            rule_key = {}
                            rule_matchs, rule_var = [], []
                            rule_match = {}
                            rule_match["rule_transform"] = eval(rule.parameter_handle)
                            if rule.parameter_select != '[]':
                                extra_key = list(eval(rule.extra).keys())
                                for i in eval(rule.parameter_select):
                                    if i in extra_key:
                                        extra_value = eval(eval(rule.extra)[i])
                                        if len(extra_value) < 2:
                                            rule_var.append({"rule_var": i})
                                        else:
                                            val = extra_value[1].split(',')
                                            rule_var.append({"rule_var": i, extra_value[0]: val})
                                    else:
                                        rule_var.append({"rule_var": i})
                            else:
                                rule_var = []
                            rule_match["rule_vars"] = rule_var
                            rule_match["rule_operator"] = rule.match_pattern
                            if rule.parameter_match:
                                if "\'" in rule.parameter_match:
                                    rule.parameter_match = rule.parameter_match.replace("\'", 'quotes')
                                    rule_match["rule_pattern"] = rule.parameter_match
                                if '\"' in rule.parameter_match:
                                    rule.parameter_match = rule.parameter_match.replace('\"', 'yinhao')
                                    rule_match["rule_pattern"] = rule.parameter_match
                                else:
                                    rule_match["rule_pattern"] = rule.parameter_match
                            else:
                                rule_match["rule_pattern"] = ''
                            rule_match["rule_negated"] = LOG_USE[rule.resulr_negation]
                            rule_matchs.append(rule_match)
                            rule_key["rule_phase"] = "req"
                            rule_key["rule_global"] = "false"
                            rule_key["rule_nodelay"] = "false"
                            rule_key["rule_action_replace_data"] = "false"
                            rule_key["rule_key_vars"] = "false"
                            rule_key["rule_matchs"] = rule_matchs
                            rule_key["rule_detail"] = rule.rule_detail
                            rule_key["rule_rate_or_count"] = "false"
                            rule_key["rule_category"] = KIND[rule.kind]
                            rule_key["rule_log"] = LOG_USE[rule.log]
                            rule_key["rule_serverity"] = rule.level
                            rule_key["rule_action_data"] = "false"
                            rule_key["rule_action"] = rule.handle
                            rule_key["rule_id"] = rule.rule_id
                            rule_key["rule_burst_or_time"] = "false"
                            data.append(rule_key)
                        for cc in cc_rules:
                            cc_key = {}
                            cc_matchs, cc_var, cc_key_vars = [], [], []
                            cc_match = {}
                            cc_match["rule_transform"] = eval(cc.parameter_handle)
                            if cc.parameter_select != '[]':
                                extra_key1 = list(eval(cc.extra).keys())
                                for i in eval(cc.parameter_select):
                                    if i in extra_key1:
                                        extra_value = eval(eval(cc.extra)[i])
                                        if len(extra_value) < 2:
                                            cc_var.append({"rule_var": i})
                                        else:
                                            val = extra_value[1].split(',')
                                            cc_var.append({"rule_var": i, extra_value[0]: val})
                                    else:
                                        cc_var.append({"rule_var": i})
                            cc_match["rule_vars"] = cc_var
                            cc_match["rule_operator"] = cc.match_pattern
                            if cc.parameter_match:
                                if "\'" in cc.parameter_match:
                                    cc.parameter_match = cc.parameter_match.replace("\'", 'quotes')
                                    cc_match["rule_pattern"] = cc.parameter_match
                                if '\"' in cc.parameter_match:
                                    cc.parameter_match = cc.parameter_match.replace('\"', 'yinhao')
                                    cc_match["rule_pattern"] = cc.parameter_match
                                else:
                                    cc_match["rule_pattern"] = cc.parameter_match
                            else:
                                cc_match["rule_pattern"] = ''
                            cc_match["rule_negated"] = LOG_USE[cc.resulr_negation]
                            if cc.global_defend == '1':
                                cc_matchs.append(cc_match)
                            else:
                                cc_matchs = []
                            cc_key["rule_phase"] = "cc"
                            cc_key["rule_global"] = LOG_USE[cc.global_defend]
                            cc_key["rule_nodelay"] = LOG_USE[cc.delay]
                            if cc.parameter_sign != '[]':
                                for i in eval(cc.parameter_sign):
                                    cc_key_vars.append({"rule_var": i})
                            else:
                                cc_key_vars = "false"
                            cc_key["rule_action_replace_data"] = "false"
                            cc_key["rule_key_vars"] = cc_key_vars
                            cc_key["rule_matchs"] = cc_matchs
                            cc_key["rule_detail"] = cc.cc_detail
                            cc_key["rule_rate_or_count"] = cc.rate_or_count
                            cc_key["rule_category"] = "false"
                            cc_key["rule_log"] = LOG_USE[cc.log]
                            cc_key["rule_serverity"] = "false"
                            cc_key["rule_action_data"] = "false"
                            cc_key["rule_action"] = cc.handle
                            cc_key["rule_id"] = cc.cc_id
                            cc_key["rule_burst_or_time"] = cc.burst_or_time
                            data.append(cc_key)
                        if "\'" in str(data):
                            data = str(data).replace("\'", '\"')
                        else:
                            pass
                        data = str(data).replace("None", "\"false\"").replace('quotes', "\'").replace('yinhao', r'\"')
                        data = json.dumps(json.loads(data)).replace(
                            r'\\u00c2\\u00b4\\u00e2\\u0080\\u0099\\u00e2\\u0080\\u0098',
                            r'\u00c2\u00b4\u00e2\u0080\u0099\u00e2\u0080\u0098')
                        # data = json.dumps(json.loads(json.dumps(eval(data))))
                        if remote_data != 1:
                            return HttpResponse(data + remote_data)
                        else:
                            return HttpResponse(data)
                    else:
                        error = {"status": 400, "data": {"title": "WAF Api"}, "msg": "The secret key is not valid"}
                        return JsonResponse(error)
                else:
                    error = {"status": 400, "data": {"title": "WAF Api"}, "msg": "The secret tag is not valid"}
                    return JsonResponse(error)
            else:
                error = {"status": 400, "data": {"title": "WAF Api"}, "msg": "Unsubmitted parameter"}
                return JsonResponse(error)

        else:
            error = {"status": 400, "data": {"title": "WAF Api"}, "msg": "Submission mode error"}
            return JsonResponse(error)
    except Exception as e:
        print(e)
        error = {"status": 500, "data": {"title": "WAF Api"}, "msg": "Internal error"}
        return JsonResponse(error)


@login_required
def main(request):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    current_date = timezone.now()

    count = Waf_log.objects.filter(update_data__range=(current_date - timedelta(hours=1), current_date),
                                   log_user=user).count()
    count_change = count - Waf_log.objects.filter(
        update_data__range=(current_date - timedelta(hours=25), current_date - timedelta(hours=24)),
        log_user=user).count()

    owasp_count = Waf_log.objects.filter(update_data__range=(current_date - timedelta(hours=1), current_date),
                                         log_type='owasp_log', log_user=user).count()
    owasp_change = owasp_count - Waf_log.objects.filter(
        update_data__range=(current_date - timedelta(hours=25), current_date - timedelta(hours=24)),
        log_type='owasp_log', log_user=user).count()

    geo_count = Waf_log.objects.filter(update_data__range=(current_date - timedelta(hours=1), current_date),
                                       log_type='geo_log', log_user=user).count()
    geo_change = geo_count - Waf_log.objects.filter(
        update_data__range=(current_date - timedelta(hours=25), current_date - timedelta(hours=24)),
        log_type='geo_log', log_user=user).count()

    cc_count = Waf_log.objects.filter(update_data__range=(current_date - timedelta(hours=1), current_date),
                                      log_type='cc_log', log_user=user).count()
    cc_change = cc_count - Waf_log.objects.filter(
        update_data__range=(current_date - timedelta(hours=25), current_date - timedelta(hours=24)),
        log_type='cc_log', log_user=user).count()

    attack_count = Waf_log.objects.values_list('target_address').filter(
        update_data__range=(current_date - timedelta(hours=1), current_date), log_user=user).all()
    attack_change = Waf_log.objects.values_list('target_address').filter(
        update_data__range=(current_date - timedelta(hours=25), current_date - timedelta(hours=24)),
        log_user=user).all()
    attack_count = len(set(attack_count))
    attack_change = attack_count - len(set(attack_change))

    return render(request, 'WafChartManage/main.html', {
        'counts': count,
        'count_changes': count_change,
        'owasp_counts': owasp_count,
        'owasp_changes': owasp_change,
        'geo_counts': geo_count,
        'geo_changes': geo_change,
        'cc_counts': cc_count,
        'cc_changes': cc_change,
        'attack_counts': attack_count,
        'attack_changes': attack_change,
    })


@login_required
def dashboard(request):
    try:
        user = request.user
        role = user.profile.roles.all()
        roles = [item.title for item in role][0]
    except:
        roles = ''
    return render(request, "Dashboard.html", {'role': roles})


def operate_info(request, user, action, name, status):  # 修改网站访问量和访问ip等信息
    try:
        num_id = models.UserLog.objects.latest('id').id
    except:
        num_id = 0
    if 'HTTP_X_FORWARDED_FOR' in request.META:  # 获取ip
        client_ip = request.META['HTTP_X_FORWARDED_FOR']
        client_ip = client_ip.split(",")[0]  # 所以这里是真实的ip
    else:
        client_ip = request.META['REMOTE_ADDR']  # 这里获得代理ip
    if action == '登录':
        des = '访问了系统'
    else:
        des = action + '了用户' + name

    models.UserLog.objects.create(
        uesr_logid=num_id,
        user_name=user,
        user_ip=client_ip,
        log_type=status,
        user_action=action,
        action_description=user + des,
    )


def operateinfo(request, user, action, name, status):  # 修改网站访问量和访问ip等信息
    try:
        num_id = models.UserLog.objects.latest('id').id
    except:
        num_id = 0
    if 'HTTP_X_FORWARDED_FOR' in request.META:  # 获取ip
        client_ip = request.META['HTTP_X_FORWARDED_FOR']
        client_ip = client_ip.split(",")[0]  # 所以这里是真实的ip
    else:
        client_ip = request.META['REMOTE_ADDR']  # 这里获得代理ip

    des = action + name

    models.UserLog.objects.create(
        uesr_logid=num_id,
        user_name=user,
        user_ip=client_ip,
        log_type=status,
        user_action=action,
        action_description=user + des,
    )


@login_required
def userlog(request):
    return render(request, "RBAC/userlog.html")


@login_required
@csrf_protect
def userloglist(request):
    user = request.user
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')

    name = request.POST.get('name')
    if not name:
        name = ''

    key = request.POST.get('key')
    if not key:
        key = ''

    attack_type = request.POST.get('type')
    if not attack_type:
        attack_type = ''

    if user.is_superuser:
        loglist = models.UserLog.objects.filter(
            user_name__icontains=name,
            user_ip__icontains=key,
            user_action__icontains=attack_type,
        ).all().order_by('-updatetime')
    else:
        loglist = models.UserLog.objects.filter(
            user_name__icontains=name,
            user_ip__icontains=key,
            user_action__icontains=attack_type,
        ).all().order_by('-updatetime')
    total = loglist.count()
    loglist = paging(loglist, rows, page)
    data = []
    for log in loglist:
        dic = {}
        dic['uesr_logid'] = log.uesr_logid
        dic['user_name'] = log.user_name
        dic['user_ip'] = log.user_ip
        dic['log_type'] = log.log_type
        dic['user_action'] = log.user_action
        dic['action_description'] = log.action_description
        dic['updatetime'] = str(log.updatetime).split('.')[0]
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "用户访问列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


@csrf_protect
def regist(request, argu):
    error = ""
    if argu == "regist":
        if request.method == "POST":
            form = forms.UserRequestForm(request.POST)
            if form.is_valid():
                email = form.cleaned_data["email"]
                user_get = User.objects.filter(username=email)
                if user_get:
                    error = "用户已存在"
                else:
                    userregist_get = models.UserRequest.objects.filter(email=email)
                    if userregist_get.count() > 2:
                        error = "用户已多次添加"
                    else:
                        area = form.cleaned_data["area"]
                        request_type = form.cleaned_data["request_type"]
                        urlarg = strtopsd(email)
                        models.UserRequest.objects.get_or_create(
                            email=email,
                            urlarg=urlarg,
                            area=area,
                            request_type=request_type,
                        )
                        error = "申请成功，审批通过后会向您发送邮箱"
            else:
                error = "请检查输入"
        else:
            form = forms.UserRequestForm()
        return render(request, "RBAC/registrequest.html", {"form": form, "error": error})
    else:
        regist_get = get_object_or_404(models.UserRequest, urlarg=argu, is_use=False)
        if request.method == "POST":
            form = forms.Account_Reset_Form(request.POST)
            if form.is_valid():
                email = form.cleaned_data["email"]
                firstname = form.cleaned_data["firstname"]
                lastname = form.cleaned_data["lastname"]
                password = form.cleaned_data["password"]
                repassword = form.cleaned_data["repassword"]
                username = email.split("@")[0]
                check_res = checkpsd(password)
                if check_res:
                    if regist_get.email == email:
                        if password == repassword:
                            user_create = auth.authenticate(username=username, password=password)
                            if user_create:
                                error = "用户已存在"
                            else:
                                operate_info(request, username, '添加', username, '成功')
                                user_create = User.objects.create_user(
                                    first_name=firstname,
                                    last_name=lastname,
                                    username=username,
                                    password=password,
                                    email=email,
                                )
                                user_create.profile.roles.add(regist_get.request_type)
                                user_create.profile.area = regist_get.area
                                user_create.save()
                                regist_get.is_use = True
                                regist_get.save()
                                return HttpResponseRedirect("/view/")
                        else:
                            error = "两次密码不一致"
                    else:
                        error = "密码长度8-32位，需要大小写字母、数字、符号最少三种组合"
                else:
                    error = "恶意注册是不对滴"
            else:
                error = "请检查输入"
        else:
            form = forms.Account_Reset_Form()
        return render(request, "RBAC/regist.html", {"form": form, "error": error})


@csrf_protect
def resetpasswd(request, argu="resetpsd"):
    error = ""
    if argu == "resetpsd":
        if request.method == "POST":
            form = forms.ResetpsdRequestForm(request.POST)
            if form.is_valid():
                email = form.cleaned_data["email"]
                user = get_object_or_404(User, email=email)
                if user:
                    hash_res = hashlib.md5()
                    hash_res.update(make_password(email).encode("utf-8"))
                    urlarg = hash_res.hexdigest()
                    models.UserResetpsd.objects.get_or_create(
                        email=email,
                        urlarg=urlarg
                    )
                    res = mails.sendresetpsdmail(email, urlarg)
                    if res:
                        error = "申请已发送，请检查邮件通知，请注意检查邮箱"
                    else:
                        error = "重置邮件发送失败，请重试"
                else:
                    error = "请检查信息是否正确"
            else:
                error = "请检查输入"
        else:
            form = forms.ResetpsdRequestForm()
        return render(request, "RBAC/resetpsdquest.html", {"form": form, "error": error})
    else:
        resetpsd = get_object_or_404(models.UserResetpsd, urlarg=argu)
        if resetpsd:
            email_get = resetpsd.email
            if request.method == "POST":
                form = forms.ResetpsdForm(request.POST)
                if form.is_valid():
                    email = form.cleaned_data["email"]
                    password = form.cleaned_data["password"]
                    repassword = form.cleaned_data["repassword"]
                    if checkpsd(password):
                        if password == repassword:
                            if email_get == email:
                                user = get_object_or_404(User, email=email)
                                if user:
                                    user.set_password(password)
                                    user.save()
                                    resetpsd.delete()
                                    return HttpResponseRedirect("/view/")

                                else:
                                    error = "用户信息有误"
                            else:
                                error = "用户邮箱不匹配"
                        else:
                            error = "两次密码不一致"
                    else:
                        error = "密码长度8-32位，需要大小写字母、数字、符号最少三种组合"
                else:
                    error = "请检查输入"
            else:
                form = forms.ResetpsdForm()
            return render(request, "RBAC/resetpsd.html", {"form": form, "error": error, "title": "重置"})


@login_required
@csrf_protect
def changeuserinfo(request):
    user = request.user
    if user.email:
        mails = user.email
    else:
        mails = ''
    if request.method == "POST":
        form = forms.UserInfoForm(request.POST, instance=user.profile)
        if form.is_valid():
            mail = request.POST.get('mail')
            if mail:
                if checkmail(mail):
                    user.email = mail
                    user.save()
                    form.save()
                    operate_info(request, str(user), '修改', str(user), '成功')
                    error = "修改成功"
                else:
                    error = '输入正确邮箱'
            else:
                error = '输入邮箱'
        else:
            error = "请检查输入"
        return render(request, "formuseredit.html",
                      {"form": form, "post_url": "changeuserinfo", "error": error, 'mail': mails})
    else:
        form = forms.UserInfoForm(instance=user.profile)
    return render(request, "formuseredit.html", {"form": form, "post_url": "changeuserinfo", 'mail': mails})


@login_required
def userinfo(request):
    return render(request, "RBAC/userinfo.html")


@login_required
@csrf_protect
def changepsd(request):
    error = ""
    if request.method == "POST":
        form = forms.ChangPasswdForm(request.POST)
        if form.is_valid():
            old_password = form.cleaned_data["old_password"]
            new_password = form.cleaned_data["new_password"]
            re_new_password = form.cleaned_data["re_new_password"]
            username = request.user.username
            if checkpsd(new_password):
                if new_password and new_password == re_new_password:
                    if old_password:
                        user = auth.authenticate(username=username, password=old_password)
                        if user:
                            user.set_password(new_password)
                            user.save()
                            auth.logout(request)
                            error = "修改成功"
                        else:
                            error = "账号信息错误"
                    else:
                        error = "请检查原始密码"
                else:
                    error = "两次密码不一致"
            else:
                error = "密码长度8-32位，需要大小写字母、数字、符号最少三种组合"
        else:
            error = "请检查输入"
        return render(request, "formedit.html", {"form": form, "post_url": "changepsd", "error": error})
    else:
        form = forms.ChangPasswdForm()
    return render(request, "formedit.html", {"form": form, "post_url": "changepsd"})


@login_required
def logout(request):
    auth.logout(request)
    request.session.clear()
    return HttpResponseRedirect("/view/")


def pcgetcaptcha(request):
    user_id = 'test'
    gt = GeetestLib(pc_geetest_id, pc_geetest_key)
    status = gt.pre_process(user_id)
    request.session[gt.GT_STATUS_SESSION_KEY] = status
    request.session["user_id"] = user_id
    response_str = gt.get_response_str()
    return HttpResponse(response_str)


def pcvalidate(request):
    if request.method == "POST":
        gt = GeetestLib(pc_geetest_id, pc_geetest_key)
        challenge = request.POST.get(gt.FN_CHALLENGE, '')
        validate = request.POST.get(gt.FN_VALIDATE, '')
        seccode = request.POST.get(gt.FN_SECCODE, '')
        status = request.session[gt.GT_STATUS_SESSION_KEY]
        user_id = request.session["user_id"]
        if status:
            result = gt.success_validate(challenge, validate, seccode, user_id)
        else:
            result = gt.failback_validate(challenge, validate, seccode)
        result = "<html><body><h1>登录成功</h1></body></html>" if result else "<html><body><h1>登录失败</h1></body></html>"
        return HttpResponse(result)
    return HttpResponse("error")


def pcajax_validate(request):
    if request.method == "POST":
        gt = GeetestLib(pc_geetest_id, pc_geetest_key)
        challenge = request.POST.get(gt.FN_CHALLENGE, '')
        validate = request.POST.get(gt.FN_VALIDATE, '')
        seccode = request.POST.get(gt.FN_SECCODE, '')
        status = request.session[gt.GT_STATUS_SESSION_KEY]
        user_id = request.session["user_id"]
        if status:
            result = gt.success_validate(challenge, validate, seccode, user_id)
        else:
            result = gt.failback_validate(challenge, validate, seccode)
        results = {"status": "success"} if result else {"status": "fail"}
        results = results['status']
        cap = models.captcha.objects.first()
        if cap:
            cap.captcha_name = results
            cap.save()
        else:
            models.captcha.objects.get_or_create(
                captcha_name=results
            )
    return HttpResponse("error")


def check_code(request):
    stream = BytesIO()
    # 生成图片 img、数字代码 code，保存在内存中，而不是 Django 项目中
    img, code = create_validate_code()
    img.save(stream, 'PNG')

    # 写入 session
    request.session['valid_code'] = code
    return HttpResponse(stream.getvalue())


def mfa_use():
    try:
        if models.User_setting.objects.last().mfa == '开启':
            for i in User.objects.all():
                i.profile.mfa = '开启'
                i.save()
        else:
            for i in User.objects.all():
                if i.profile.mfa_key:
                    pass
                else:
                    i.profile.mfa = '关闭'
                    i.save()
    except:
        pass


@csrf_protect
def login(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        code = request.POST.get('check_code')
        if code.upper() == request.session.get('valid_code').upper():
            if username and password:
                user_get = User.objects.filter(username=username).first()
                if user_get:
                    if user_get.profile.lock_time > timezone.now():
                        error = u"账号已锁定," + str(user_get.profile.lock_time.strftime("%Y-%m-%d %H:%M")) + "后可尝试"
                        return JsonResponse({'msg': error})
                    else:
                        user = auth.authenticate(username=username, password=password)
                        if user:
                            if username == 'admin':
                                user.profile.error_count = 0
                                user.save()
                                auth.login(request, user)
                                init_permission(request, user)
                                operate_info(request, username, '登录', username, '成功')
                                return HttpResponseRedirect("/user/")
                            else:
                                mfa_use()
                                if user.profile.mfa == '开启':
                                    if user.profile.mfa_key:
                                        request.session['username'] = username
                                        request.session['password'] = password
                                        return HttpResponseRedirect("/view/mfa/")
                                    else:
                                        request.session['username'] = username
                                        request.session['password'] = password
                                        secret_key = pyotp.random_base32()
                                        file_path = './static/images/MFA/'
                                        data = pyotp.totp.TOTP(secret_key).provisioning_uri(str(user),
                                                                                            issuer_name="WafPlatform")
                                        qr = QRCode(
                                            version=1,
                                            error_correction=constants.ERROR_CORRECT_L,
                                            box_size=6,
                                            border=4,
                                        )
                                        qr.add_data(data)
                                        qr.make(fit=True)
                                        img = qr.make_image()
                                        img.save(file_path + str(user) + '.png')  # 保存条形码图片
                                        request.session['secret_key'] = secret_key
                                        return HttpResponseRedirect("/view/init_approve/")
                                else:
                                    user.profile.error_count = 0
                                    user.save()
                                    auth.login(request, user)
                                    init_permission(request, user)
                                    operate_info(request, username, '登录', username, '成功')
                                    return HttpResponseRedirect("/user/")
                        else:
                            user_get.profile.error_count += 1
                            if user_get.profile.error_count >= 5:
                                user_get.profile.error_count = 0
                                user_get.profile.lock_time = timezone.now() + datetime.timedelta(minutes=1)
                            user_get.save()
                            error = "登陆失败,已错误登录" + str(user_get.profile.error_count) + "次,5次后账号锁定"
                            operate_info(request, username, '登录', username, '失败')
                            return render(request, "RBAC/login.html", {"error": error})
                else:
                    error = "请检查用户信息"
                    operate_info(request, username, '登录', username, '失败')
                    return render(request, "RBAC/login.html", {"error": error})
            else:
                error = "请检查输入"
                return render(request, "RBAC/login.html", {"error": error})
        else:
            error = u"验证失败"
        return render(request, "RBAC/login.html", {"error": error})
    else:
        if request.user.is_authenticated:
            return HttpResponseRedirect("/user/")
    return render(request, "RBAC/login.html")


@csrf_protect
def login_jiyan(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        validate = request.POST.get('geetest_validate')
        if validate:
            if username and password:
                user_get = User.objects.filter(username=username).first()
                if user_get:
                    if user_get.profile.lock_time > timezone.now():
                        error = u"账号已锁定," + str(user_get.profile.lock_time.strftime("%Y-%m-%d %H:%M")) + "后可尝试"
                        return JsonResponse({'msg': error})
                    else:
                        user = auth.authenticate(username=username, password=password)
                        if user:
                            if username == 'admin':
                                user.profile.error_count = 0
                                user.save()
                                auth.login(request, user)
                                init_permission(request, user)
                                operate_info(request, username, '登录', username, '成功')
                                return JsonResponse({'msg': 'success'})
                            else:
                                mfa_use()
                                if user.profile.mfa == '开启':
                                    if user.profile.mfa_key:
                                        request.session['username'] = username
                                        request.session['password'] = password
                                        return JsonResponse({'msg': 'mfa'})
                                    else:
                                        request.session['username'] = username
                                        request.session['password'] = password
                                        secret_key = pyotp.random_base32()
                                        file_path = './static/images/MFA/'
                                        data = pyotp.totp.TOTP(secret_key).provisioning_uri(str(user),
                                                                                            issuer_name="WafPlatform")
                                        qr = QRCode(
                                            version=1,
                                            error_correction=constants.ERROR_CORRECT_L,
                                            box_size=6,
                                            border=4,
                                        )
                                        qr.add_data(data)
                                        qr.make(fit=True)
                                        img = qr.make_image()
                                        img.save(file_path + str(user) + '.png')  # 保存条形码图片
                                        request.session['secret_key'] = secret_key
                                        return JsonResponse({'msg': 'approve'})
                                else:
                                    user.profile.error_count = 0
                                    user.save()
                                    auth.login(request, user)
                                    # 这里需要加入权限初始化
                                    init_permission(request, user)
                                    operate_info(request, username, '登录', username, '成功')
                                    return JsonResponse({'msg': 'success'})
                        else:
                            user_get.profile.error_count += 1
                            if user_get.profile.error_count >= 5:
                                user_get.profile.error_count = 0
                                user_get.profile.lock_time = timezone.now() + datetime.timedelta(minutes=1)
                            user_get.save()
                            error = "登陆失败,已错误登录" + str(user_get.profile.error_count) + "次,5次后账号锁定"
                            operate_info(request, username, '登录', username, '失败')
                            return JsonResponse({'msg': error})
                else:
                    error = "请检查用户信息"
                    operate_info(request, username, '登录', username, '失败')
                    return JsonResponse({'msg': error})
            else:
                error = "请检查输入"
                return JsonResponse({'msg': error})
        else:
            error = u"验证失败"
        return render(request, "RBAC/login_jiyan.html", {"error": error})
    else:
        if request.user.is_authenticated:
            return HttpResponseRedirect("/user/")
    return render(request, "RBAC/login_jiyan.html")


@csrf_exempt
def mfa_verify(request):
    if request.method == "POST":
        username = request.session.get('username', None)
        password = request.session.get('password', None)
        user = auth.authenticate(username=username, password=password)
        secret_key = user.profile.mfa_key
        verifycode = request.POST.get('verifycode')
        result = Google_Verify_Result(secret_key, verifycode)
        if result:
            request.session.clear()
            user.profile.error_count = 0
            user.save()
            auth.login(request, user)

            init_permission(request, user)
            operate_info(request, username, '登录', username, '成功')
            return HttpResponseRedirect("/user/")
        else:
            error = '秘钥错误,请重新认证'
            return render(request, "RBAC/login_verify.html", {"post_url": "mfa_verify", 'error': error})
    return render(request, "RBAC/login_verify.html", {"post_url": "mfa_verify"})


@csrf_exempt
def init_approve(request):
    username = request.session.get('username', None)
    password = request.session.get('password', None)
    secret_key = request.session.get('secret_key', None)
    user = auth.authenticate(username=username, password=password)
    image = username + '.png'
    if request.method == 'POST':
        verifycode = request.POST.get('verifycode')
        result = Google_Verify_Result(secret_key, verifycode)
        if result:
            request.session.clear()
            user.profile.error_count = 0
            user.profile.mfa_key = secret_key
            user.save()
            auth.login(request, user)
            init_permission(request, user)
            operate_info(request, username, '登录', username, '成功')
            return HttpResponseRedirect("/user/")
        else:
            error = '验证失败,请重试'
        return render(request, 'RBAC/init_verify.html', {'post_url': 'init_approve',
                                                         'error': error, 'image': image, 'secret_key': secret_key})
    return render(request, 'RBAC/init_verify.html', {'post_url': 'init_approve',
                                                     'image': image, 'secret_key': secret_key})


def Google_Verify_Result(secret_key, verifycode):
    t = pyotp.TOTP(secret_key)
    result = t.verify(verifycode)
    msg = result if result is True else False
    return msg


@login_required
@csrf_protect
def userlist(request):
    user = request.user
    error = ""
    if user.is_superuser:
        area = models.Area.objects.filter(parent__isnull=True)
        city = models.Area.objects.filter(parent__isnull=False)
        return render(request, "RBAC/userlist.html", {"area": area, "city": city})
    else:
        error = "权限错误"
    return render(request, "error.html", {"error": error})


@login_required
@csrf_protect
def userlisttable(request):
    user = request.user
    resultdict = {}
    page = request.POST.get("page")
    rows = request.POST.get("limit")
    name = request.POST.get("name")
    if not name:
        name = ""
    nickname = request.POST.get("nickname")
    if not nickname:
        nickname = ""
    phone = request.POST.get("phone")
    if not phone:
        phone = ""
    role = request.POST.get("role")
    if not role:
        role = ""

    is_active = request.POST.get("active")
    if not is_active:
        is_active = ["True", "False"]
    else:
        is_active = [is_active]
    user_list = User.objects.filter(
        username__icontains=name,
        profile__user_nickname__icontains=nickname,
        profile__mobilephone__icontains=phone,
        profile__roles__title__icontains=role,
        is_active__in=is_active
    ).all().order_by("-date_joined")
    total = user_list.count()
    user_list = paging(user_list, rows, page)
    data = []
    for user_item in user_list:
        dic = {}
        dic["name"] = user_item.username
        dic["mail"] = emaillist(user_item.email)
        dic["date"] = str(user_item.date_joined).split('.')[0].replace('T', '-')
        dic["phone"] = phonelist(user_item.profile.mobilephone)
        dic["nickname"] = user_item.profile.user_nickname
        if user_item.is_active:
            dic["status"] = "启用"
        else:
            dic["status"] = "禁用"
        if user_item.last_login:
            dic["lastlogin"] = str(user_item.last_login).split('.')[0].replace('T', '-')
        else:
            dic["lastlogin"] = ''
        role = user_item.profile.roles.all()
        roles = []
        for item in role:
            roles.append(item.title)
        dic["role"] = roles
        data.append(dic)
    resultdict["code"] = 0
    resultdict["msg"] = "用户列表"
    resultdict["count"] = total
    resultdict["data"] = data
    return JsonResponse(resultdict)


@login_required
@csrf_protect
def userregistaction(request):
    user = request.user
    error = ""
    if user.is_superuser:
        regist_id = request.POST.get("request_id")
        action = request.POST.get("action")
        userregist = get_object_or_404(models.UserRequest, id=regist_id)
        if userregist.is_check:
            error = "请勿重复审批"
        else:
            if action == "access":
                userregist.is_check = True
                userregist.status = "1"
                res = mails.sendregistmail(userregist.email, userregist.urlarg)
                if res:
                    error = "添加成功，已向该员工发送邮件"
                else:
                    error = "添加成功，邮件发送失败，请重试"
                userregist.save()
            elif action == "deny":
                userregist.is_check = True
                userregist.status = "2"
                userregist.is_use = True
                userregist.save()
                error = "已审批"
            else:
                error = "未指定操作"
    else:
        error = "权限错误"
    return JsonResponse({"error": error})


@login_required
def userregistlist1(request):
    user = request.user
    error = ""
    if user.is_superuser:
        area = models.Area.objects.filter(parent__isnull=True)
        return render(request, "RBAC/userregistlist.html", {"area": area})
    else:
        error = "权限错误"
    return render(request, "error.html", {"error": error})


@login_required
@csrf_protect
def userregisttable(request):
    user = request.user
    resultdict = {}
    error = ""
    page = request.POST.get("page")
    rows = request.POST.get("limit")

    email = request.POST.get("email")
    if not email:
        email = ""
    status = request.POST.get("status")
    if not status:
        status = ""
    is_use = request.POST.get("is_use")
    if not is_use:
        is_use = ["True", "False"]
    else:
        is_use = [is_use]
    is_check = request.POST.get("is_check")
    if not is_check:
        is_check = ["True", "False"]
    else:
        is_check = [is_check]

    if user.is_superuser:
        userrequest_list = models.UserRequest.objects.filter(email__icontains=email, status__icontains=status,
                                                             is_use__in=is_use, is_check__in=is_check).order_by(
            "is_check", "is_use", "-updatetime")
        total = userrequest_list.count()
        userrequest_list = paging(userrequest_list, rows, page)
        data = []
        for userrequest in userrequest_list:
            dic = {}
            dic["request_id"] = userrequest.id
            dic["email"] = userrequest.email
            if userrequest.is_check:
                dic["is_check"] = "已审批"
                dic["starttime"] = userrequest.starttime
                if userrequest.action_user:
                    dic["action_user"] = userrequest.action_user.username
                dic["updatetime"] = userrequest.updatetime
            else:
                dic["is_check"] = "待审批"
            if userrequest.is_use:
                dic["is_use"] = "已使用"
            else:
                dic["is_use"] = "待使用"
            dic["request_type"] = userrequest.request_type.title
            dic["status"] = REAUEST_STATUS[userrequest.status]
            data.append(dic)
        resultdict["code"] = 0
        resultdict["msg"] = "用户申请列表"
        resultdict["count"] = total
        resultdict["data"] = data
        return JsonResponse(resultdict)
    else:
        error = "权限错误"
    return render(request, "error.html", {"error": error})


@login_required
@csrf_protect
def user_add(request):
    user = request.user
    error = ""
    if user.is_superuser:
        if request.method == "POST":
            form = forms.UserRequestForm(request.POST)
            if form.is_valid():
                email = form.cleaned_data["email"]
                user_get = User.objects.filter(username=email)
                if user_get:
                    error = "用户已存在"
                else:
                    userregist_get = models.UserRequest.objects.filter(email=email)
                    if userregist_get.count() > 2:
                        error = "用户已多次添加"
                    else:
                        area = form.cleaned_data["area"]
                        request_type = form.cleaned_data["request_type"]
                        urlarg = strtopsd(email)
                        models.UserRequest.objects.get_or_create(
                            email=email,
                            urlarg=urlarg,
                            area=area,
                            request_type=request_type,
                            is_check=True,
                            status="1",
                            action_user=user,
                        )
                        operate_info(request, email, '添加', email, '成功')
                        res = mails.sendregistmail(email, urlarg)
                        if res:
                            error = "添加成功，已向该员工发送邮件"
                        else:
                            error = "添加成功，邮件发送失败，请重试"
            else:
                error = "请检查输入"
        else:
            form = forms.UserRequestForm()
    else:
        error = "请检查权限是否正确"
    return render(request, "formedit.html", {"form": form, "post_url": "useradd", "error": error})


@login_required
@csrf_protect
def user_request_cancle(request):
    user = request.user
    error = ""
    if user.is_superuser:
        regist_id_list = request.POST.get("regist_id_list")
        regist_id_list = json.loads(regist_id_list)
        action = request.POST.get("action")
        for regist_id in regist_id_list:
            userregist = get_object_or_404(models.UserRequest, id=regist_id)
            userregist.status = "2"
            userregist.is_check = True
            userregist.is_use = True
            userregist.save()
            operate_info(request, user, '删除', userregist.email, '成功')
        error = "已禁用"
    else:
        error = "权限错误"
    return JsonResponse({"error": error})


@login_required
@csrf_protect
def user_disactivate(request):
    user = request.user
    error = ""
    if user.is_superuser:
        user_list = request.POST.get("user_list")
        user_list = json.loads(user_list)
        action = request.POST.get("action")
        for user_mail in user_list:
            user_get = get_object_or_404(User, email=user_mail)
            if action == "stop":
                user_get.is_check = True
                user_get.is_active = False
            elif action == "start":
                user_get.is_active = True
            user_get.save()
        error = "已禁用"
    else:
        error = "权限错误"
    return JsonResponse({"error": error})


@login_required
def mfa(request):
    user = request.user
    datas = dict()
    if user.profile.mfa == '开启':
        mfa_button = 'checked'
    else:
        mfa_button = ''
    datas['mfa'] = mfa_button
    datas['fail_num'] = user.profile.fail_num
    datas['time_space'] = user.profile.time_space
    datas['forbid_time_space'] = user.profile.forbid_time_space
    if request.method == "POST":
        if request.POST.get('mfa') == 'on':
            user.profile.mfa = '开启'
        else:
            user.profile.mfa = '关闭'
        user.profile.fail_num = request.POST.get('fail_num')
        user.profile.time_space = request.POST.get('time_space')
        user.profile.forbid_time_space = request.POST.get('forbid_time_space')
        user.save()
    return render(request, "RBAC/MFA.html", {"post_url": "mfa", 'datas': datas})


@login_required
def psd_verify(request):
    error = ''
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username == str(request.user):
            user = auth.authenticate(username=username, password=password)
            if user:
                get_qrcode(request)
                return render(request, 'RBAC/software_Install.html', {'post_url': 'install'})
            else:
                error = '验证失败'
                return render(request, 'RBAC/psd_verify.html', {'post_url': 'psdverify', 'error': error})
        else:
            error = '用户错误'
            return render(request, 'RBAC/psd_verify.html', {'post_url': 'psdverify', 'error': error})
    return render(request, 'RBAC/psd_verify.html', {'post_url': 'psdverify', 'error': error})


@login_required
def software_install(request):
    error = ''
    if request.method == 'POST':
        return render(request, 'RBAC/software_Install.html', {'post_url': 'install', 'error': error})
    return render(request, 'RBAC/software_Install.html', {'post_url': 'install', 'error': error})


def get_qrcode(request):
    secret_key = pyotp.random_base32()
    user = request.user
    filepath = './static/images/MFA/'
    data = pyotp.totp.TOTP(secret_key).provisioning_uri(str(user), issuer_name="WafPlatform")
    qr = QRCode(
        version=1,
        error_correction=constants.ERROR_CORRECT_L,
        box_size=6,
        border=4,
    )
    try:
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image()
        img.save(filepath + str(user) + '.png')  # 保存条形码图片
        user.profile.mfa_key = secret_key
        user.save()
        return True
    except Exception as e:
        return False


@login_required
def approve(request):
    error = ''
    user = request.user
    image = str(user) + '.png'
    secret_key = user.profile.mfa_key
    if request.method == 'POST':
        verifycode = request.POST.get('verifycode')
        result = Google_Verify_Result(secret_key, verifycode)
        if result:
            user.profile.mfa = '开启'
            user.save()
            error = '验证成功,已开启MFA'
        else:
            error = '验证失败,请重试'
        return render(request, 'RBAC/verify.html', {'post_url': 'approve',
                                                    'error': error, 'image': image, 'secret_key': secret_key})
    return render(request, 'RBAC/verify.html', {'post_url': 'approve',
                                                'error': error, 'image': image, 'secret_key': secret_key})


@login_required
def close_mfa(request):
    error = ''
    user = request.user
    secret_key = user.profile.mfa_key
    if request.method == 'POST':
        verifycode = request.POST.get('verifycode')
        result = Google_Verify_Result(secret_key, verifycode)
        if result:
            user.profile.mfa = '关闭'
            user.profile.mfa_key = ''
            user.save()
            error = '已关闭MFA'
        else:
            error = '验证失败,请重试'
        return render(request, 'RBAC/close_mfa.html', {'post_url': 'close_mfa',
                                                       'error': error, 'secret_key': secret_key})
    return render(request, 'RBAC/close_mfa.html', {'post_url': 'close_mfa',
                                                   'error': error, 'secret_key': secret_key})


@login_required
def update_mfa(request):
    error = ''
    user = request.user
    secret_key = user.profile.mfa_key
    if request.method == 'POST':
        verifycode = request.POST.get('verifycode')
        result = Google_Verify_Result(secret_key, verifycode)
        if result:
            return render(request, 'RBAC/psd_verify.html', {'post_url': 'psdverify'})
        else:
            error = '验证失败,请重试'
        return render(request, 'RBAC/close_mfa.html',
                      {'post_url': 'update_mfa', 'error': error, 'secret_key': secret_key})
    return render(request, 'RBAC/close_mfa.html',
                  {'post_url': 'update_mfa', 'error': error, 'secret_key': secret_key})


@login_required
def user_data(request):
    user = request.user
    phone = user.profile.mobilephone
    if phone:
        phone = phonelist(phone)
    mail = user.email
    if mail:
        mail = emaillist(mail)
    is_active = user.is_active
    if is_active:
        is_active = '启用'
    else:
        is_active = '禁用'
    role = user.profile.roles.all()
    roles = [item.title for item in role][0]

    return render(request, "RBAC/user_info.html",
                  {'mail': mail, 'phone': phone, 'is_active': is_active, 'roles': roles})


@login_required
def station_manage(request):
    return render(request, "SettingManage/stationlist.html")


@login_required
def data_backups(request):
    return render(request, "SettingManage/backups.html")


@login_required
def plan_task(request):
    return render(request, "SettingManage/planlist.html")


@login_required
def certificate_manage(request):
    return render(request, "SettingManage/certificate.html")


@login_required
def monitoring_manage(request):
    uptime = os.popen('uptime').readlines()
    uptime = [i.split() for i in uptime][0]

    uname = os.popen('uname -a').readlines()
    uname = [i.split() for i in uname][0]
    data = {}
    data['uptime'] = uptime[2]
    data['second'] = uptime[4].strip(',')
    data['version'] = uname[0] + '' + uname[2]
    data['host'] = uname[1]
    data['percent'] = psutil.disk_usage('/').percent
    data['total'] = int(psutil.disk_usage('/').total)//1024//1024000
    data['used'] = int(psutil.disk_usage('/').used)//1024//1024000
    data['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    return render(request, "SettingManage/monitoring.html", {'data': data})


@login_required
def node_manage(request):
    return render(request, "SettingManage/nodelist.html")


@login_required
def userregistlist(request):
    error = ''
    users_data = dict()
    user = request.user
    targets = Node_group.objects.all()
    if request.method == "POST":
        username = request.POST.get('names')
        nickname = request.POST.get('nickname')
        title = request.POST.get('function')
        status = request.POST.get('status')
        mail = request.POST.get('mails')
        phone = request.POST.get('phone')
        remark = request.POST.get('remark')
        mfa = request.POST.get('mfa')
        target = request.POST.get('target')
        random.seed()
        chars = string.ascii_letters + string.digits
        password = ''.join([random.choice(chars) for _ in range(16)])
        user_create = User.objects.filter(username=username)
        if user_create:
            error = "用户已存在"
        else:
            if checkmail(mail) and checkpone(phone):
                operate_info(request, username, '添加', username, '成功')
                user_create = User.objects.create_user(
                    username=username,
                    password=password,
                    email=mail,
                )
                user_create.is_active = status
                user_create.profile.roles.add(int(title))
                user_create.profile.mfa = mfa
                user_create.profile.user_target = target
                user_create.profile.user_nickname = nickname
                user_create.profile.mobilephone = phone
                user_create.profile.description = remark
                user_create.save()
                error = '添加成功'
                mails.sendmails(username, mail, password)
            else:
                error = '输入正确手机邮箱'
            users_data['username'] = username
            users_data['nickname'] = nickname
            users_data['title'] = title
            users_data['status'] = status
            users_data['mails'] = mail
            users_data['phone'] = phone
            users_data['remark'] = remark
            if mfa == '开启':
                users_data['on'] = 'checked'
            else:
                users_data['off'] = 'checked'
            return render(request, "RBAC/add_user.html",
                          {"post_url": "userregistview", 'error': error, 'users_data': users_data,
                           'targets': targets})
    else:
        return render(request, "RBAC/add_user.html",
                      {"post_url": "userregistview", 'error': error, 'users_data': users_data, 'targets': targets})
    return render(request, "RBAC/add_user.html", {"post_url": "userregistview", 'error': error, 'targets': targets})


@login_required
def user_update(request, user_name):
    user_create = User.objects.filter(username=user_name).first()

    role = user_create.profile.roles.all()
    roles = [item.id for item in role]
    error = ''
    users_data = dict()
    users_data['username'] = user_create.username
    users_data['status'] = user_create.is_active
    users_data['nickname'] = user_create.profile.user_nickname
    users_data['mails'] = user_create.email
    users_data['phone'] = user_create.profile.mobilephone
    users_data['title'] = user_create.profile.user_target
    users_data['remark'] = user_create.profile.description
    users_data['roles'] = str(roles[0])
    if user_create.profile.mfa == '开启':
        users_data['on'] = 'checked'
    else:
        users_data['off'] = 'checked'
    targets = Node_group.objects.all()
    if request.method == "POST":
        username = request.POST.get('names')
        nickname = request.POST.get('nickname')
        title = request.POST.get('function')
        status = request.POST.get('status')
        mail = request.POST.get('mails')
        phone = request.POST.get('phone')
        remark = request.POST.get('remark')
        mfa = request.POST.get('mfa')
        target = request.POST.get('target')
        random.seed()
        operate_info(request, username, '更新', username, '成功')
        user_create.username = username
        user_create.email = mail
        user_create.is_active = status
        user_create.profile.roles.remove(1, 2, 3)
        user_create.profile.roles.add(int(title))
        user_create.profile.mfa = mfa
        user_create.profile.user_target = target
        user_create.profile.user_nickname = nickname
        user_create.profile.mobilephone = phone
        user_create.profile.description = remark
        user_create.save()
        error = '更新成功'
        users_data['username'] = username
        users_data['nickname'] = nickname
        users_data['title'] = title
        users_data['status'] = status
        users_data['mails'] = mail
        users_data['phone'] = phone
        users_data['remark'] = remark
        if mfa == '开启':
            users_data['on'] = 'checked'
        else:
            users_data['off'] = 'checked'
        return render(request, "RBAC/user_update.html",
                      {"post_url": "userupdate", 'error': error, 'users_data': users_data, 'targets': targets})
    return render(request, "RBAC/user_update.html",
                  {"post_url": "userupdate", 'error': error, 'targets': targets, 'users_data': users_data})


@login_required
def user_del(request, user_name):
    error = '已删除'
    User.objects.filter(username=user_name).delete()
    return JsonResponse({'提示': error}, json_dumps_params={'ensure_ascii': False})


@login_required
def mails_manage(request):
    mails = models.User_mails.objects.last()
    if mails:
        mails_data = dict()
        mails_data['smtp_name'] = mails.smtp_name
        mails_data['smtp_ip'] = mails.smtp_ip
        mails_data['smtp_port'] = mails.smtp_port
        mails_data['ssl_use'] = mails.ssl_use
        mails_data['overtime'] = mails.overtime
        mails_data['mails'] = mails.mails
        mails_data['mails_psd'] = mails.mails_psd
        mails_data['mails_test'] = mails.mails_test
        mails_data['smtp_content'] = mails.smtp_content
        mails_data['ding_key'] = mails.ding_key
        mails_data['ding_token'] = mails.ding_token
        mails_data['es_address'] = mails.es_address
       #  mails_data['es_index'] = mails.es_index
    else:
        mails_data = dict()
    if request.method == "POST":
        models.User_mails.objects.create(
            smtp_name=request.POST.get('smtp_name'),
            smtp_ip=request.POST.get('smtp_ip'),
            smtp_port=request.POST.get('smtp_port'),
            ssl_use=request.POST.get('ssl_use'),
            overtime=request.POST.get('overtime'),
            mails=request.POST.get('mails'),
            mails_psd=request.POST.get('mails_psd'),
            mails_test=request.POST.get('mails_test'),
            smtp_content=request.POST.get('smtp_content'),
            ding_key=request.POST.get('ding_key'),
            ding_token=request.POST.get('ding_token'),
            es_address=request.POST.get('es_address'),
           #  es_index=request.POST.get('es_index'),
        )

        mails_data = dict()
        mails_data['smtp_name'] = request.POST.get('smtp_name')
        mails_data['smtp_ip'] = request.POST.get('smtp_ip')
        mails_data['smtp_port'] = request.POST.get('smtp_port')
        mails_data['ssl_use'] = request.POST.get('ssl_use')
        mails_data['overtime'] = request.POST.get('overtime')
        mails_data['mails'] = request.POST.get('mails')
        mails_data['mails_psd'] = request.POST.get('mails_psd')
        mails_data['mails_test'] = request.POST.get('mails_test')
        mails_data['smtp_content'] = request.POST.get('smtp_content')
        mails_data['ding_key'] = request.POST.get('ding_key')
        mails_data['ding_token'] = request.POST.get('ding_token')
        mails_data['es_address'] = request.POST.get('es_address')
        # mails_data['es_index'] = request.POST.get('es_index')
        return render(request, "RBAC/mails.html", {"post_url": "mails", 'datas': mails_data})
    return render(request, "RBAC/mails.html", {"post_url": "mails", 'datas': mails_data})


@login_required
def setting_manage(request):
    lists = ['移动APP', 'IT与软件开发', '新闻媒体', '通讯社交', '游戏', '电子商务', '音视频', '金融', '教育',
             '旅游', '物联网', '汽车业/车联网', 'o2o', '电力/新能源', '交通运输', '建筑/地产', '政府/事业单位', '生产制造', '基因',
             '新零售/烟草业', '物流邮政', '运营商', '能源重工', '公共事业/城市服务']
    list_time = ['7天', '一个月', '一年']

    setting = models.User_setting.objects.last()

    if setting:
        setting_data = dict()
        setting_data['applyname'] = setting.applyname
        setting_data['del_time'] = setting.del_time
        setting_data['username'] = setting.username
        setting_data['phone'] = setting.phone
        setting_data['nickname'] = setting.nickname
        if setting.mfa == '开启':
            setting_data['on'] = 'checked'
        else:
            setting_data['off'] = 'checked'
        if setting.alarm_use == '开启':
            setting_data['ons'] = 'checked'
        else:
            setting_data['offs'] = 'checked'
        setting_data['loginnum'] = setting.loginnum
        setting_data['time'] = setting.time
        setting_data['stoptime'] = setting.stoptime
    else:
        setting_data = dict()
    if request.method == "POST":
        models.User_setting.objects.create(
            applyname=request.POST.get('applyname'),
            del_time=request.POST.get('del_time'),
            username=request.POST.get('username'),
            phone=request.POST.get('phone'),
            nickname=request.POST.get('nickname'),
            mfa=request.POST.get('mfa'),
            alarm_use=request.POST.get('alarm_use'),
            loginnum=request.POST.get('loginnum'),
            time=request.POST.get('time'),
            stoptime=request.POST.get('stoptime'),
        )

        setting_data = dict()
        setting_data['applyname'] = request.POST.get('applyname')
        setting_data['del_time'] = request.POST.get('del_time')
        setting_data['username'] = request.POST.get('username')
        setting_data['phone'] = request.POST.get('phone')
        setting_data['nickname'] = request.POST.get('nickname')
        if request.POST.get('mfa') == '开启':
            setting_data['on'] = 'checked'
        else:
            setting_data['off'] = 'checked'
        if request.POST.get('alarm_use') == '开启':
            setting_data['ons'] = 'checked'
        else:
            setting_data['offs'] = 'checked'
        setting_data['loginnum'] = request.POST.get('loginnum')
        setting_data['time'] = request.POST.get('time')
        setting_data['stoptime'] = request.POST.get('stoptime')
        return render(request, "RBAC/dingding.html",
                      {"post_url": "settingmanage", 'datas': setting_data, 'lists': lists, 'list_time': list_time})

    return render(request, "RBAC/dingding.html", {"post_url": "settingmanage", 'datas': setting_data, 'lists': lists, 'list_time': list_time})


# 图片上传
def image_upload(files, dir_name, user):
    # 允许上传文件类型
    allow_suffix = ['jpg', 'png', 'jpeg', 'gif', 'bmp']
    file_suffix = files.name.split(".")[-1]
    if file_suffix not in allow_suffix:
        return {"error": 1, "message": "图片格式不正确"}
    path = './static/images/photos/'
    if not os.path.exists(path):  # 如果目录不存在创建目录
        os.makedirs(path)
    file_name = str(user) + "." + file_suffix
    path_file = os.path.join(path, file_name)
    file_url = settings.MEDIA_URL + dir_name + file_name
    open(path_file, 'wb').write(files.file.read())  # 保存图片
    return file_url


@csrf_exempt
@login_required
def upload_image(request):
    user = request.user
    dir_name = 'imgs'
    result = {
        "code": 0
        , "msg": ""
        , "data": {
            "src": ""
            , "title": ""
        }
    }
    if user.is_superuser:
        files = request.FILES.get("file", None)
        if files:
            url = image_upload(files, dir_name, user)
            if url:
                result['msg'] = '上传成功'
                result['data']['src'] = url
            else:
                result['code'] = 1
                result['msg'] = '上传失败'
        else:
            result['code'] = 1
            result['msg'] = '未发现文件'

    else:
        result['code'] = 1
        result['msg'] = '权限错误'
    return JsonResponse(result)


@login_required
@csrf_protect
def certificate_add(request):
    error = ""
    if request.method == "POST":
        uid = uuid.uuid1()
        form = CertificateForm(request.POST)
        if form.is_valid():
            certificate_name = form.cleaned_data["certificate_name"]
            name_get = Certificate.objects.filter(certificate_name=certificate_name)
            if name_get:
                error = "证书已存在"
            else:
                certificate_key = form.cleaned_data["certificate_key"]
                certificate_des = form.cleaned_data["certificate_des"]
                certificate_public = form.cleaned_data["certificate_public"]
                try:
                    scanner = Node.objects.all()
                    data = {
                        "certificate_uuid": str(uid),
                        "certificate_pem": certificate_public,
                        "certificate_key": certificate_key,
                    }
                    time_list = []
                    for scan in scanner:
                        times = waf_manage.cert_add(data, scan.node_des)
                        time_list.append(times)
                    if time_list[0]['status'] == 200 or time_list[0]['status'] == '200':
                        certificate = Certificate.objects.create(
                            certificate_id=uid,
                            certificate_public=certificate_public,
                            certificate_des=certificate_des,
                            certificate_key=certificate_key,
                            certificate_name=certificate_name,
                        )
                        certificate.impower_time = time_list[0]['data']['expiration_time']
                        certificate.save()
                        error = '添加成功'
                        operateinfo(request, str(request.user), '添加', '证书' + certificate_name, '成功')
                    else:
                        operateinfo(request, str(request.user), '添加', '证书' + certificate_name, '失败')
                        error = time_list[0]['msg']
                except Exception as e:
                    error = '证书推送失败,{0}'.format(e)
        else:
            error = "请检查输入"
    else:
        form = CertificateForm()
    return render(request, "formedit.html", {"form": form, "post_url": "certificateadd", "error": error})


@login_required
@csrf_protect
def certificate_update(request, certificate_id):
    user = request.user
    error = ''
    if user.is_superuser:
        certificate = get_object_or_404(Certificate, certificate_id=certificate_id)
    else:
        certificate = get_object_or_404(Certificate, certificate_id=certificate_id)
    if request.method == 'POST':
        form = CertificateForm(request.POST, instance=certificate)
        if form.is_valid():
            form.save()
            scanner = Node.objects.all()
            data = {
                "certificate_uuid": certificate.certificate_id,
                "certificate_pem": certificate.certificate_public,
                "certificate_key": certificate.certificate_key,
            }
            time_list = []
            for scan in scanner:
                times = waf_manage.cert_add(data, scan.node_des)
                time_list.append(times)
            if time_list[0]['status'] == 200 or time_list[0]['status'] == '200':
                certificate.impower_time = time_list[0]['data']['expiration_time']
                certificate.save()
                error = '修改成功'
            else:
                error = time_list[0]['msg']
        else:
            error = '请检查输入'
    else:
        form = CertificateForm(instance=certificate)
    return render(request, 'formupdate.html',
                  {'form': form, 'post_url': 'certificateupdate', 'argu': certificate, 'error': error})


@login_required
@csrf_protect
def certificate_bind(request, certificate_id):
    station = Station.objects.filter(certificate_ids=certificate_id).all()
    return render(request, 'WafChartManage/detail.html', {'station': station})


@login_required
def certificate_del(request, certificate_id):
    error = '已删除'
    certificate = Certificate.objects.filter(certificate_id=certificate_id).first()
    operateinfo(request, str(request.user), '删除', certificate.certificate_name, '成功')
    certificate.delete()
    try:
        scanner = Node.objects.all()
        for scan in scanner:
            waf_manage.cert_delete(certificate_id, scan.node_des)
    except Exception as e:
        print(e)
    return JsonResponse({'提示': error}, json_dumps_params={'ensure_ascii': False})


@login_required
@csrf_protect
def station_add(request):
    certificate = Certificate.objects.all()
    if request.method == "POST":
        station_name = request.POST.get('station_name')
        certificate_ids = request.POST.get('certificate')
        if request.POST.get('cache'):
            proxy_cache = 'on'
        else:
            proxy_cache = 'off'
        if request.POST.get('logs'):
            site_logs = 'on'
        else:
            site_logs = 'off'
        if request.POST.get('cache_time'):
            proxy_cache_time = request.POST.get('cache_time')
        else:
            proxy_cache_time = 1
        name_get = Station.objects.filter(station_name=station_name)
        if name_get:
            error = "站点已存在"
        else:
            if not request.POST.get('HTTP') and not request.POST.get('HTTPS'):
                error = "未选择协议"
            else:
                uid = uuid.uuid1()
                station_agreement = []
                if request.POST.get('HTTP'):
                    station_agreement.append('http')
                if request.POST.get('HTTPS'):
                    station_agreement.append('https')
                data = {
                    "site_uuid": str(uid),
                    "domain_name": request.POST.get('station_url').strip().replace(',', '\n').replace('\r\n', '\n').split('\n'),
                    "protocol_type": station_agreement,
                    "certificate_uuid": certificate_ids,
                    "upstream_url": request.POST.get('upstream_url').strip().replace(',', '\n').replace('\r\n', '\n').split('\n'),
                    "proxy_cache": proxy_cache,
                    "site_logs": site_logs,
                    "proxy_cache_time": proxy_cache_time

                }
                try:
                    scanner = Node.objects.all()
                    info = []
                    for scan in scanner:
                        datas = waf_manage.site_add(data, scan.node_des)
                        info.append(datas)
                    if info[0]['status'] == 200 or info[0]['status'] == '200':
                        error = '添加成功'
                        Station.objects.create(
                            station_name=station_name,
                            station_id=uid,
                            station_des=request.POST.get('station_des'),
                            station_agreement=station_agreement,
                            station_url=request.POST.get('station_url'),
                            upstream_url=request.POST.get('upstream_url'),
                            logs=site_logs,
                            cache=proxy_cache,
                            cache_time=request.POST.get('cache_time'),
                            certificate_ids=certificate_ids)
                        operateinfo(request, str(request.user), '添加', '站点' + station_name, '成功')
                    else:
                        operateinfo(request, str(request.user), '添加', '站点' + station_name, '失败')
                        error = info[0]['msg']
                except Exception as e:
                    error = '添加失败'
                    print(e)

                station_data = dict()
                station_data['station_name'] = station_name
                station_data['station_des'] = request.POST.get('station_des')
                station_data['station_id'] = uid
                station_data['station_agreement'] = request.POST.get('station_agreement')
                station_data['station_url'] = request.POST.get('station_url')
                station_data['upstream_url'] = request.POST.get('upstream_url')
                station_data['logs'] = MAPPING[site_logs]
                station_data['cache'] = MAPPING[proxy_cache]
                station_data['cache_time'] = request.POST.get('cache_time')
                return render(request, "SettingManage/station.html",
                              {'error': error, 'station_data': station_data, 'certificate': certificate,
                               "post_url": "stationadd", })
        return render(request, "SettingManage/station.html",
                      {'error': error, 'certificate': certificate, "post_url": "stationadd", })
    return render(request, "SettingManage/station.html", {'certificate': certificate, "post_url": "stationadd"})


MAPPING = {
    'on': 'check',
    '': '',
    'off': '',
    None: '',
}


@login_required
@csrf_protect
def station_update(request, station_id):
    error = ''
    scan = Node.objects.first()
    try:
        logs = waf_manage.site_view(station_id, scan.node_des)['data']['site_conf_data']
    except Exception as e:
        logs = ''
        print(e)
    if request.method == "POST":
        conf = request.POST.get('conf')
        try:
            waf_manage.site_update(station_id, conf, scan.node_des)
            error = '修改配置成功'
        except Exception as e:
            error = '修改配置失败'
            print(e)
        return render(request, 'SettingManage/edit_details.html', {'log': conf, 'error': error})
    return render(request, 'SettingManage/edit_details.html', {'log': logs, 'error': error})


@login_required
@csrf_protect
def station_reload(request):
    scanner = Node.objects.all()
    try:
        for scan in scanner:
            waf_manage.site_reload(scan.node_des)
        error = "重新加载成功"
        operateinfo(request, str(request.user), '重新加载', '站点', '成功')
    except Exception as e:
        error = "重新加载失败"
        operateinfo(request, str(request.user), '重新加载', '站点', '失败')
        print(e)
    return JsonResponse({"error": error})


@login_required
@csrf_protect
def rule_reload(request):
    url = ''
    try:
        waf_manage.site_reload(request, url)
        error = "重新加载成功"
        operateinfo(request, str(request.user), '重新加载', '规则库', '成功')
    except Exception as e:
        error = "重新加载失败"
        operateinfo(request, str(request.user), '重新加载', '规则库', '失败')
        print(e)
    return JsonResponse({"error": error})


@login_required
@csrf_protect
def station_view(request, station_id):
    certificate = Certificate.objects.all()

    station = Station.objects.filter(station_id=station_id).first()

    station_data = dict()
    station_data['station_name'] = station.station_name
    station_data['station_des'] = station.station_des
    station_data['station_url'] = station.station_url
    station_data['upstream_url'] = station.upstream_url
    station_data['logs'] = station.logs
    station_data['certificate_ids'] = str(station.certificate_ids)

    station_data['cache_time'] = station.cache_time
    if station.cache:
        if station.cache == 'on':
            station_data['cache'] = 'checked'
        else:
            station_data['cache'] = ''
    else:
        station_data['cache'] = ''
    if station.logs:
        if station.logs == 'on':
            station_data['logs'] = 'checked'
        else:
            station_data['logs'] = ''
    else:
        station_data['logs'] = ''

    station_data['http'] = ''
    station_data['https'] = ''
    if station.station_agreement:
        if 'http' in station.station_agreement:
            station_data['http'] = 'checked'
        if 'https' in station.station_agreement:
            station_data['https'] = 'checked'

    return render(request, "SettingManage/station_view.html",
                  {'station_data': station_data, 'certificate': certificate,
                   "post_url": "stationadd", })


@login_required
def station_del(request, station_id):
    error = '已删除'
    station = Station.objects.filter(station_id=station_id).first()
    station.delete()
    try:
        scanner = Node.objects.all()
        for scan in scanner:
            waf_manage.site_delete(station_id, scan.node_des)
        operateinfo(request, str(request.user), '删除', station.station_name, '成功')
    except Exception as e:
        error = '删除站点失败'
        operateinfo(request, str(request.user), '删除', station.station_name, '失败')
        print(e)

    return JsonResponse({'提示': error}, json_dumps_params={'ensure_ascii': False})


@login_required
@csrf_protect
def Node_add(request):
    error = ""
    if request.method == "POST":
        form = NodeForm(request.POST)
        if form.is_valid():
            try:
                num_id = Node.objects.latest('id').id
            except:
                num_id = 0
            num_id += 1
            node_name = form.cleaned_data["node_name"]
            manager_address = form.cleaned_data["manager_address"]
            node_group = form.cleaned_data["node_group"]
            name_get = Node.objects.filter(node_name=node_name)
            if name_get:
                error = "节点已存在"
            elif node_group == None:
                error = '请先添加节点标签'
            else:
                node_des = form.cleaned_data["node_des"]
                try:
                    node_groups = Node_group.objects.filter(group_name=node_group).first()
                    waf_manage.nodelable_updata(node_groups.group_target, node_des, manager_address)
                    try:
                        r = waf_manage.license_view(node_des)
                        if r['status'] == 200 or r['status'] == '200':
                            node = Node.objects.create(
                                node_id=num_id,
                                node_name=node_name,
                                node_des=node_des,
                                manager_address=manager_address,
                                node_group=node_group,
                                node_license=r['data']['license']
                            )
                            node.node_impowertime = r['data']['expiration_time']
                            node.node_version = r['data']['waf_version']
                            node.save()
                            error = '添加成功'
                            operateinfo(request, str(request.user), '添加', '节点' + node_name, '成功')
                        else:
                            operateinfo(request, str(request.user), '添加', '节点' + node_name, '失败')
                            error = '添加失败'
                    except Exception as e:
                        print(e)
                        error = '添加失败'
                except Exception as e:
                    error = '添加失败'
                    print(e)
        else:
            error = "请检查输入"
    else:
        form = NodeForm()
    return render(request, "formedit.html", {"form": form, "post_url": "nodeadd", "error": error})


@login_required
@csrf_protect
def Nodegroup_add(request):
    error = ""
    if request.method == "POST":
        form = NodegroupForm(request.POST)
        if form.is_valid():
            try:
                num_id = Node_group.objects.latest('id').id
            except:
                num_id = 0
            num_id += 1
            group_name = form.cleaned_data["group_name"]
            name_get = Node_group.objects.filter(group_name=group_name)
            if name_get:
                error = "标签已存在"
            else:
                group_target = ''
                name_list = lazy_pinyin(group_name)
                for i in name_list:
                    group_target += i
                Node_group.objects.get_or_create(
                    group_id=num_id,
                    group_name=group_name,
                    group_target=group_target + str(num_id),
                )
                error = '添加成功'
        else:
            error = "请检查输入"
    else:
        form = NodegroupForm()
    return render(request, "formedits.html", {"form": form, "post_url": "nodegroupadd", "error": error})


@login_required
@csrf_protect
def Node_update(request, node_id):
    user = request.user
    error = ''
    if user.is_superuser:
        node = get_object_or_404(Node, node_id=node_id)
    else:
        node = get_object_or_404(Node, node_id=node_id)
    if request.method == 'POST':
        form = NodeForm(request.POST, instance=node)
        if form.is_valid():
            try:
                node_groups = Node_group.objects.filter(group_name=node.node_group).first()
                waf_manage.nodelable_updata(node_groups.group_target, node.node_des, node.manager_address)
                try:
                    r = waf_manage.license_view(node.node_des)
                    if r['status'] == 200 or r['status'] == '200':
                        node.node_impowertime = r['data']['expiration_time']
                        node.node_version = r['data']['waf_version']
                        node.save()
                        error = '更改成功'
                    else:
                        error = '更改失败'
                except Exception as e:
                    error = '添加失败'
            except Exception as e:
                error = '添加失败'
                print(e)
            form.save()
        else:
            error = '请检查输入'
    else:
        form = NodeForm(instance=node)
    return render(request, 'formupdate.html',
                  {'form': form, 'post_url': 'nodeupdate', 'argu': node, 'error': error})


@login_required
@csrf_protect
def impowertime_update(request):
    error = ""
    if request.method == "POST":
        form = ImpowertimeForm(request.POST)
        if form.is_valid():
            impowertime = form.cleaned_data["node_license"]
            scanner = Node.objects.all()
            if scanner == None:
                error = "请先添加节点"
            else:
                try:
                    name = ''
                    for scan in scanner:
                        scan.node_license = impowertime
                        r = waf_manage.license_updata(impowertime, scan.node_des)
                        name = scan.node_name
                        scan.node_impowertime = r['data']['expiration_time']
                        scan.node_version = r['data']['waf_version']
                        scan.save()
                    error = '更新授权成功'
                    operateinfo(request, str(request.user), '更新授权', name, '成功')
                except Exception as e:
                    print(e)
                    error = '更新授权失败'
                    operateinfo(request, str(request.user), '更新授权', '节点', '失败')
        else:
            error = "请检查输入"
    else:
        form = ImpowertimeForm()
    return render(request, "formedit.html", {"form": form, "post_url": "impowertimeupdate", "error": error})


@login_required
def Node_del(request, node_id):
    error = '已删除'
    node = Node.objects.filter(node_id=node_id).first()
    operateinfo(request, str(request.user), '删除', node.node_name, '成功')
    node.delete()
    return JsonResponse({'提示': error}, json_dumps_params={'ensure_ascii': False})


@login_required
@csrf_protect
def regulations(request):
    try:
        version = Node.objects.first().node_version
        license = Node.objects.first().node_license
    except:
        version = ''
        license = ''

    return render(request, "SettingManage/regulations.html", {'version': version, 'license': license})


@csrf_protect
def photo_update(request):
    user = request.user
    head = request.POST.get('id')
    try:
        if head:
            userdata = User.objects.filter(username=user).first()
            userdata.profile.user_head = head
            userdata.save()
    except:
        pass
    return JsonResponse({'msg': '修改成功'})


@login_required
@csrf_protect
def photoview(request):
    return render(request, "RBAC/profile_photo.html")
