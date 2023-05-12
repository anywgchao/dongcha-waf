# coding:utf-8

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.models import User
from SeMFSetting.views import paging
from django.http import JsonResponse
from RBAC.models import UserLog
from . import models, forms


@login_required
@csrf_protect
def OfficialView(request):
    return render(request, 'RuleManage/cc_rulelist.html')


@login_required
@csrf_protect
def CustomView(request):
    return render(request, 'RuleManage/custom_rulelist.html')


def operate_info(request, user, action, rule):  # 修改网站访问量和访问ip等信息
    try:
        num_id = UserLog.objects.latest('id').id
    except:
        num_id = 0
    if 'HTTP_X_FORWARDED_FOR' in request.META:  # 获取ip
        client_ip = request.META['HTTP_X_FORWARDED_FOR']
        client_ip = client_ip.split(",")[0]  # 所以这里是真实的ip
    else:
        client_ip = request.META['REMOTE_ADDR']  # 这里获得代理ip
    if action == '添加':
        des = '添加了规则'
    elif action == '修改':
        des = '修改了规则'
    else:
        des = '删除了规则'

    UserLog.objects.create(
        uesr_logid=num_id,
        user_name=user,
        user_ip=client_ip,
        log_type='成功',
        user_action=action,
        action_description=user + des + str(rule),
    )


@login_required
@csrf_protect
def rules_create(request):
    error = ''
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    if request.method == 'POST':
        form = forms.Rule_create_form(request.POST)
        if form.is_valid():
            try:
                num_id = models.Rules_group.objects.latest('id').id
            except:
                num_id = 0
            num_id += 1
            rules_id = form.cleaned_data['rules_id']
            rules_details = form.cleaned_data['rules_details']
            detection = form.cleaned_data['detection']
            rules_use = form.cleaned_data['rules_use']
            rules_version = form.cleaned_data['rules_version']
            models.Rules_group.objects.get_or_create(
                rules_id=rules_id,
                rules_details=rules_details,
                detection=detection,
                rules_use=rules_use,
                rules_version=rules_version,
                rulegroup_user=user,
            )
            error = '添加成功'
        else:
            error = '非法输入或规则已存在'
        return render(request, 'formedit.html', {'form': form, 'post_url': 'rulescreate', 'error': error})
    else:
        form = forms.Rule_create_form()
    return render(request, 'formedit.html', {'form': form, 'post_url': 'rulescreate'})


@login_required
@csrf_protect
def ruledetailcreate(request, rules_id):
    error = ''
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    if request.method == 'POST':
        form = forms.Rule_detail_form(request.POST)
        if form.is_valid():
            extra = {}
            try:
                num_id = models.Rules.objects.latest('id').id
            except:
                num_id = 0
            num_id += 1
            rule_group = get_object_or_404(models.Rules_group, rules_id=rules_id, rulegroup_user=str(user))
            rule_id = form.cleaned_data['rule_id']
            rule_detail = form.cleaned_data['rule_detail']
            kind = form.cleaned_data['kind']
            rule_use = request.POST.get('rule_use')
            log = request.POST.get('log')
            level = form.cleaned_data['level']
            handle = form.cleaned_data['handle']
            parameter_select = request.POST.getlist('check_box_list1')
            parameter_handle = request.POST.getlist('check_box_list2')
            match_pattern = form.cleaned_data['match_pattern']
            parameter_match = form.cleaned_data['parameter_match']
            resulr_negation = request.POST.get('resulr_negation')
            for i in parameter_select:
                if len(request.POST.getlist(i)) == 1:
                    extra[i] = "['']"
                elif request.POST.getlist(i) == []:
                    pass
                else:
                    extra[i] = str(request.POST.getlist(i))
            ids = models.Rules.objects.filter(rule_id=rule_id, rule_group__rules_id=rule_group,
                                              rule_user=str(user)).first()
            print(ids)
            if rule_id:
                if ids:
                    error = 'id已存在,如仍需使用该id,请前往更新'
                else:
                    models.Rules.objects.get_or_create(
                        rule_id=rule_id,
                        rule_detail=rule_detail,
                        kind=kind,
                        rule_use=rule_use,
                        log=log,
                        level=level,
                        handle=handle,
                        extra=extra,
                        parameter_select=parameter_select,
                        parameter_handle=parameter_handle,
                        match_pattern=match_pattern,
                        parameter_match=parameter_match,
                        resulr_negation=resulr_negation,
                        rule_group=rule_group,
                        rule_user=user,
                    )
                    error = '添加成功'
                    operate_info(request, str(request.user), '添加', rule_detail)
            else:
                error = '请输入规则'
        else:
            error = '非法输入或规则已存在'
    else:
        form = forms.Rule_detail_form()
    return render(request, 'RuleManage/custom_edit.html',
                  {'form': form, 'post_url': 'ruledetailscreate', 'argu': rules_id, 'error': error})


@login_required
@csrf_protect
def rule_update(request, rule_id):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    error = ''
    cc_check = models.Rules.objects.filter(rule_id=rule_id, rule_user=str(user)).first()
    cc_check1 = eval(cc_check.parameter_select)
    cc_check2 = eval(cc_check.parameter_handle)
    if cc_check.extra:
        cc_extra = eval(cc_check.extra)
    else:
        cc_extra = {}
    select_check, handle_check, extra = {}, {}, {}
    if cc_check1:
        for key in cc_check1:
            select_check[key] = 'checked'
    if cc_check2:
        for key in cc_check2:
            handle_check[key] = 'checked'

    for key, value in cc_extra.items():
        k = {}
        if value == "['']":
            k['all'] = 'checked'
        else:
            k[eval(value)[0]] = 'checked'
            k['input'] = eval(value)[1]
        extra[key] = k

    radios = {}
    radios['rule_use'] = CKECK[cc_check.rule_use]
    radios['log'] = CKECK[cc_check.log]
    radios['resulr_negation'] = CKECK[cc_check.resulr_negation]

    rule = get_object_or_404(models.Rules, rule_id=rule_id, rule_user=str(user))
    if request.method == 'POST':
        form = forms.Rule_detail_form(request.POST, instance=rule)
        if form.is_valid():
            new_select = request.POST.getlist('check_box_list1')
            new_handle = request.POST.getlist('check_box_list2')
            rule_use = request.POST.get('rule_use')
            log = request.POST.get('log')
            resulr_negation = request.POST.get('resulr_negation')
            new_extra = {}
            for i in new_select:
                if len(request.POST.getlist(i)) == 1:
                    new_extra[i] = "['']"
                elif request.POST.getlist(i) == []:
                    pass
                else:
                    new_extra[i] = str(request.POST.getlist(i))

            id_list = []
            c = cc_check.rule_group
            b = models.Rules.objects.filter(rule_group__rules_id=c, rule_user=str(user)).all().values_list('rule_id')
            for i in b:
                id_list.append(i[0])

            rule.parameter_handle = new_handle
            rule.parameter_select = new_select
            rule.extra = new_extra
            rule.rule_use = rule_use
            rule.log = log
            rule.resulr_negation = resulr_negation
            rule.save()
            form.save()

            if rule.rule_id not in id_list:
                b = models.Rules.objects.filter(rule_id=rule.rule_id, rule_user=str(user)).first()
                b.save()
            elif rule_id != rule.rule_id and rule.rule_id in id_list:
                id = rule.id
                b = models.Rules.objects.filter(rule_group__rules_id=c, rule_user=str(user)).exclude(id=id).all()
                for i in b:
                    if int(i.rule_id) >= int(rule.rule_id):
                        i.rule_id = str(int(i.rule_id) + 1)
                        i.save()
            else:
                pass
            error = '修改成功'
            operate_info(request, str(request.user), '修改', cc_check.rule_detail)
        else:
            error = '请检查输入'
    else:
        form = forms.Rule_detail_form(instance=rule)
    return render(request, 'RuleManage/custom_edit.html',
                  {'form': form, 'post_url': 'ruleupdate', 'argu': rule, 'error': error, 'select_check': select_check,
                   'handle_check': handle_check, 'extra': extra, 'radios': radios})


@login_required
@csrf_protect
def rulegrop_update(request, rules_id):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    error = ''
    rules = get_object_or_404(models.Rules_group, rules_id=rules_id, rulegroup_user=str(user))
    if request.method == 'POST':
        form = forms.Rule_create_form(request.POST, instance=rules)
        if form.is_valid():
            form.save()
            error = '修改成功'
        else:
            error = '请检查输入'
    else:
        form = forms.Rule_create_form(instance=rules)
    return render(request, 'formupdate.html',
                  {'form': form, 'post_url': 'rulesupdate', 'argu': rules, 'error': error})


DETECTION_STATUS = {
    '0': '请求阶段',
    '1': '响应阶段',
}
CC_DETECTION_STATUS = {
    '0': 'cc防护',
}
RULE_USE = {
    '0': '是',
    '1': '否',
}

CKECK = {
    '1': 'checked',
    '0': '',
}

HANDLE = {
    'deny': '阻断请求',
    'pass': '不处理该规则',
    'inject_js': '插入js/html代码',
    'rewrite': '重写整个页面',
    'replace': '替换匹配内容',
    'allow': '放行请求(跳过所有后续规则,resp阶段不适用)',
    'redirect': '重定向请求(resp阶段不适用)',
}

LEVEL = {
    'low': '低',
    'middle': '中',
    'high': '高',
}

KIND = {
    '0': '通用基础',
    '1': 'SQL注入',
    '2': 'XSS攻击',
    '3': '命令注入',
    '4': '代码执行',
    '5': '上传漏洞',
    '6': '信息泄露',
    '7': '逻辑漏洞',
    '8': '权限绕过',
    '9': '文件读取',
    '10': '其他',
}
ACTION = {
    'limit_req_rate': '速率检测',
    'limit_req_count': '单位时间数量检测',
    'limit_req_pass': '放行请求',
}


# 规则组详情
@login_required
@csrf_protect
def rulestablelist(request):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')

    name = request.POST.get('name')
    if not name:
        name = ''
    key = request.POST.get('key')

    if not key:
        key = ''

    ruleslist = models.Rules_group.objects.filter(
        rulegroup_user=str(user),
        rules_id__icontains=key
    ).order_by('rules_id')

    total = ruleslist.count()
    ruleslist = paging(ruleslist, rows, page)
    data = []
    for rule_item in ruleslist:
        dic = {}
        num = models.Rules.objects.filter(rule_group__rules_id=rule_item.rules_id, rule_user=str(user)).count()
        dic['rules_id'] = rule_item.rules_id
        dic['rules_details'] = rule_item.rules_details
        dic['detection'] = DETECTION_STATUS[rule_item.detection]
        dic['rules_use'] = RULE_USE[rule_item.rules_use]
        dic['rules_num'] = num
        dic['rules_version'] = rule_item.rules_version
        dic['rules_updatetime'] = str(rule_item.rules_updatetime).split('.')[0]
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "用户列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


@login_required
def rule_del(request, rule_id):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    error = '已删除'
    rule = models.Rules.objects.filter(rule_id=rule_id, rule_user=user).first()
    operate_info(request, str(request.user), '删除', rule.rule_detail)
    rule.delete()
    return JsonResponse({'提示': error}, json_dumps_params={'ensure_ascii': False})


@login_required
def rulesdetailsview(request, rules_id):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    rules_id = get_object_or_404(models.Rules_group, rules_id=rules_id, rulegroup_user=user)
    return render(request, 'RuleManage/custom_details.html', {'rules_id': rules_id})


# 规则详情
@login_required
@csrf_protect
def rulesdetaillist(request, rules_id):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    resultdict = dict()
    page = request.POST.get('page')
    rows = request.POST.get('limit')

    name = request.POST.get('name')
    if not name:
        name = ''
    key = request.POST.get('key')
    if not key:
        key = ''

    ruleslist = models.Rules.objects.filter(
        rule_group__rules_id=rules_id,
        rule_user=str(user)
    ).order_by('rule_id')

    total = ruleslist.count()
    ruleslist = paging(ruleslist, rows, page)
    data = []
    for rule_item in ruleslist:
        dic = {}
        dic['rule_id'] = rule_item.rule_id
        dic['rule_detail'] = rule_item.rule_detail
        dic['kind'] = KIND[rule_item.kind]
        dic['handle'] = rule_item.handle
        dic['log'] = RULE_USE[rule_item.log]
        dic['rule_use'] = RULE_USE[rule_item.rule_use]
        dic['level'] = LEVEL[rule_item.level]
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "用户列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


# cc 规则组
@login_required
@csrf_protect
def ccgroup_create(request):
    error = ''
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    if request.method == 'POST':
        form = forms.CC_create_form(request.POST)
        if form.is_valid():
            try:
                num_id = models.CC_group.objects.latest('id').id
            except:
                num_id = 0
            num_id += 1
            ccgroup_id = form.cleaned_data['ccgroup_id']
            ccgroup_details = form.cleaned_data['ccgroup_details']
            detection = form.cleaned_data['detection']
            ccgroup_use = form.cleaned_data['ccgroup_use']
            ccgroup_version = form.cleaned_data['ccgroup_version']
            models.CC_group.objects.get_or_create(
                ccgroup_id=ccgroup_id,
                ccgroup_details=ccgroup_details,
                detection=detection,
                ccgroup_use=ccgroup_use,
                ccgroup_version=ccgroup_version,
                ccgroup_user=user,
            )
            error = '添加成功'
        else:
            error = '非法输入或规则已存在'
        return render(request, 'formedit.html', {'form': form, 'post_url': 'ccgroupcreate', 'error': error})
    else:
        form = forms.CC_create_form()
    return render(request, 'formedit.html', {'form': form, 'post_url': 'ccgroupcreate'})


@login_required
@csrf_protect
def ccdetail_create(request, ccgroup_id):
    error = ''
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    if request.method == 'POST':
        form = forms.CC_detail_form(request.POST)
        if form.is_valid():
            extra = {}
            try:
                num_id = models.CC_rule.objects.latest('id').id
            except:
                num_id = 0
            num_id += 1
            cc_group = get_object_or_404(models.CC_group, ccgroup_id=ccgroup_id, ccgroup_user=user)
            cc_id = form.cleaned_data['cc_id']
            cc_detail = form.cleaned_data['cc_detail']
            rule_use = request.POST.get('rule_use')
            log = request.POST.get('log')
            delay = request.POST.get('delay')
            global_defend = request.POST.get('global_defend')
            rate_or_count = form.cleaned_data['rate_or_count']
            burst_or_time = form.cleaned_data['burst_or_time']
            handle = form.cleaned_data['handle']
            parameter_sign = request.POST.getlist('check_box_list')
            parameter_select = request.POST.getlist('check_box_list1')
            parameter_handle = request.POST.getlist('check_box_list2')
            match_pattern = form.cleaned_data['match_pattern']
            parameter_match = form.cleaned_data['parameter_match']
            resulr_negation = request.POST.get('resulr_negation')
            for i in parameter_select:
                if len(request.POST.getlist(i)) == 1:
                    extra[i] = "['']"
                elif request.POST.getlist(i) == []:
                    pass
                else:
                    extra[i] = str(request.POST.getlist(i))
            ids = models.CC_rule.objects.filter(cc_id=cc_id, cc_group__ccgroup_id=cc_group, cc_user=str(user)).first()
            if cc_id:
                if ids:
                    error = 'id已存在,如仍需使用该id,请前往更新'
                else:
                    models.CC_rule.objects.get_or_create(
                        cc_id=cc_id,
                        cc_detail=cc_detail,
                        rule_use=rule_use,
                        log=log,
                        delay=delay,
                        global_defend=global_defend,
                        rate_or_count=rate_or_count,
                        burst_or_time=burst_or_time,
                        handle=handle,
                        extra=extra,
                        parameter_sign=parameter_sign,
                        parameter_select=parameter_select,
                        parameter_handle=parameter_handle,
                        match_pattern=match_pattern,
                        parameter_match=parameter_match,
                        resulr_negation=resulr_negation,
                        cc_group=cc_group,
                        cc_user=user,
                    )
                    error = '添加成功'
                    operate_info(request, str(request.user), '添加', cc_detail)
            else:
                error = '请输入cc规则id'
        else:
            error = '非法输入或规则已存在'
    else:
        form = forms.CC_detail_form()
    return render(request, 'RuleManage/cc_edit.html',
                  {'form': form, 'post_url': 'ccdetailscreate', 'argu': ccgroup_id, 'error': error})


@login_required
@csrf_protect
def cc_update(request, cc_id):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    error = ''
    cc_check = models.CC_rule.objects.filter(cc_id=cc_id, cc_user=str(user)).first()
    cc_check1 = eval(cc_check.parameter_sign)
    cc_check2 = eval(cc_check.parameter_select)
    cc_check3 = eval(cc_check.parameter_handle)
    if cc_check.extra:
        cc_extra = eval(cc_check.extra)
    else:
        cc_extra = {}
    select_check, handle_check, sign_check, extra = {}, {}, {}, {}
    if cc_check1:
        for key in cc_check1:
            sign_check[key] = 'checked'

    if cc_check2:
        for key in cc_check2:
            select_check[key] = 'checked'

    if cc_check3:
        for key in cc_check3:
            handle_check[key] = 'checked'
    for key, value in cc_extra.items():
        k = {}
        if value == "['']":
            k['all'] = 'checked'
        else:
            k[eval(value)[0]] = 'checked'
            k['input'] = eval(value)[1]
        extra[key] = k
    radios = {}
    radios['rule_use'] = CKECK[cc_check.rule_use]
    radios['log'] = CKECK[cc_check.log]
    radios['delay'] = CKECK[cc_check.delay]
    radios['global_defend'] = CKECK[cc_check.global_defend]
    radios['resulr_negation'] = CKECK[cc_check.resulr_negation]

    cc = get_object_or_404(models.CC_rule, cc_id=cc_id, cc_user=str(user))
    if request.method == 'POST':
        form = forms.CC_detail_form(request.POST, instance=cc)
        if form.is_valid():
            new_select = request.POST.getlist('check_box_list1')
            new_handle = request.POST.getlist('check_box_list2')
            new_sign = request.POST.getlist('check_box_list')
            rule_use = request.POST.get('rule_use')
            log = request.POST.get('log')
            delay = request.POST.get('delay')
            global_defend = request.POST.get('global_defend')
            resulr_negation = request.POST.get('resulr_negation')
            new_extra = {}

            for i in new_select:
                if len(request.POST.getlist(i)) == 1:
                    new_extra[i] = "['']"
                elif request.POST.getlist(i) == []:
                    pass
                else:
                    new_extra[i] = str(request.POST.getlist(i))

            id_list = []
            c = cc_check.cc_group
            b = models.CC_rule.objects.filter(cc_group__ccgroup_id=c, cc_user=str(user)).all().values_list('cc_id')
            for i in b:
                id_list.append(i[0])

            cc.parameter_handle = new_handle
            cc.parameter_select = new_select
            cc.parameter_sign = new_sign
            cc.rule_use = rule_use
            cc.log = log
            cc.delay = delay
            cc.global_defend = global_defend
            cc.resulr_negation = resulr_negation
            cc.extra = new_extra
            cc.save()
            form.save()

            if cc.cc_id not in id_list:
                b = models.CC_rule.objects.filter(cc_id=cc.cc_id, cc_user=str(user)).first()
                b.save()
            elif cc_id != cc.cc_id and cc.cc_id in id_list:
                id = cc.id
                b = models.CC_rule.objects.filter(cc_group__ccgroup_id=c, cc_user=str(user)).exclude(id=id).all()
                for i in b:
                    if int(i.cc_id) >= int(cc.cc_id):
                        i.cc_id = str(int(i.cc_id) + 1)
                        i.save()
            else:
                pass
            error = '修改成功'
            operate_info(request, str(request.user), '修改', cc_check.cc_detail)
        else:
            error = '请检查输入'
    else:
        form = forms.CC_detail_form(instance=cc)
    return render(request, 'RuleManage/cc_edit.html',
                  {'form': form, 'post_url': 'ccupdate', 'argu': cc, 'error': error, 'select_check': select_check,
                   'handle_check': handle_check, 'sign_check': sign_check, 'extra': extra, 'radios': radios})


@login_required
@csrf_protect
def ccgroup_update(request, ccgroup_id):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    error = ''

    ccgroup = get_object_or_404(models.CC_group, ccgroup_id=ccgroup_id, ccgroup_user=str(user))
    if request.method == 'POST':
        form = forms.CC_create_form(request.POST, instance=ccgroup)
        if form.is_valid():
            form.save()
            error = '修改成功'
        else:
            error = '请检查输入'
    else:
        form = forms.CC_create_form(instance=ccgroup)
    return render(request, 'formupdate.html',
                  {'form': form, 'post_url': 'ccgroupupdate', 'argu': ccgroup, 'error': error})


# 规则组详情
@login_required
@csrf_protect
def ccgrouptablelist(request):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')

    name = request.POST.get('name')
    if not name:
        name = ''
    key = request.POST.get('key')

    if not key:
        key = ''

    cclist = models.CC_group.objects.filter(
        ccgroup_id__icontains=key,
        ccgroup_user=str(user),
    ).order_by('ccgroup_id')

    total = cclist.count()
    ccslist = paging(cclist, rows, page)
    data = []
    for cc_item in ccslist:
        dic = {}
        num = models.CC_rule.objects.filter(cc_group__ccgroup_id=cc_item.ccgroup_id, cc_user=str(request.user)).count()
        dic['ccgroup_id'] = cc_item.ccgroup_id
        dic['ccgroup_details'] = cc_item.ccgroup_details
        dic['detection'] = CC_DETECTION_STATUS[cc_item.detection]
        dic['ccgroup_use'] = RULE_USE[cc_item.ccgroup_use]
        dic['ccgroup_num'] = num
        dic['ccgroup_version'] = cc_item.ccgroup_version
        dic['ccgroup_updatetime'] = str(cc_item.ccgroup_updatetime).split('.')[0]
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "用户列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)


@login_required
def cc_del(request, cc_id):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    error = '已删除'
    cc = models.CC_rule.objects.filter(cc_id=cc_id, cc_user=user).first()
    operate_info(request, str(request.user), '删除', cc.cc_detail)
    cc.delete()
    return JsonResponse({'提示': error})


@login_required
def ccdetailsview(request, ccgroup_id):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    ccgroup_id = get_object_or_404(models.CC_group, ccgroup_id=ccgroup_id, ccgroup_user=user)
    return render(request, 'RuleManage/cc_details.html', {'ccgroup_id': ccgroup_id})


# 规则详情
@login_required
@csrf_protect
def ccdetaillist(request, ccgroup_id):
    user = str(request.user)
    user = User.objects.filter(username=user).first().profile.user_target
    resultdict = {}
    page = request.POST.get('page')
    rows = request.POST.get('limit')

    name = request.POST.get('name')
    if not name:
        name = ''
    key = request.POST.get('key')
    if not key:
        key = ''

    cclist = models.CC_rule.objects.filter(
        cc_group__ccgroup_id=ccgroup_id,
        cc_user=str(user),
    ).order_by('cc_id')

    total = cclist.count()
    cclist = paging(cclist, rows, page)
    data = []
    for cc_item in cclist:
        dic = {}
        dic['cc_id'] = cc_item.cc_id
        dic['cc_detail'] = cc_item.cc_detail
        dic['kind'] = '无'
        dic['handle'] = ACTION[cc_item.handle]
        dic['log'] = RULE_USE[cc_item.log]
        dic['rule_use'] = RULE_USE[cc_item.rule_use]
        dic['level'] = '无'
        data.append(dic)
    resultdict['code'] = 0
    resultdict['msg'] = "用户列表"
    resultdict['count'] = total
    resultdict['data'] = data
    return JsonResponse(resultdict)
