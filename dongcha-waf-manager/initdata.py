#! /usr/bin/python3
# -*- coding:UTF-8 -*-

import django
import os


def initmenu():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'SeMF.settings')
    django.setup()
    from RBAC import models
    menu_list = [
        {'title': '数据看板', 'icon': "&#xe62a;"},
        {'title': 'WAF管理', 'icon': "&#xe649;"},
        {'title': '站点管理', 'icon': "&#xe7ae;"},
        {'title': '证书管理', 'icon': "&#xe857;"},
        {'title': '系统管理', 'icon': "&#xe770;"},
    ]
    for item in menu_list:
        models.Menu.objects.get_or_create(
            title=item['title'],
            icon=item['icon']
        )

    submain_list = [
        {'title': '拦截日志', 'icon': "&#xe629;", 'parent_title': '数据看板'},
        {'title': '访问日志', 'icon': "&#xe615;", 'parent_title': '数据看板'},
        {'title': 'CC规则组', 'icon': "&#xe705;", 'parent_title': 'WAF管理'},
        {'title': '自定义规则组', 'icon': "&#xe705;", 'parent_title': 'WAF管理'},
        {'title': 'WAF全局配置', 'icon': "&#xe716;", 'parent_title': 'WAF管理'},
        {'title': '响应规则模板', 'icon': "&#xe7ae;", 'parent_title': 'WAF管理'},
        {'title': '添加站点', 'icon': "&#xe7ae;", 'parent_title': '站点管理'},
        {'title': '添加证书', 'icon': "&#xe857;", 'parent_title': '证书管理'},
        {'title': '监控', 'icon': "&#xe62c;", 'parent_title': '系统管理'},
        {'title': '基本设置', 'icon': "&#xe614;", 'parent_title': '系统管理'},
        {'title': '告警设置', 'icon': "&#xe678;", 'parent_title': '系统管理'},
        {'title': '计划任务', 'icon': "&#xe655;", 'parent_title': '系统管理'},
        {'title': '数据备份', 'icon': "&#xe60a;", 'parent_title': '系统管理'},
        {'title': '用户列表', 'icon': "&#xe60a;", 'parent_title': '系统管理'},
        # {'title': '新增用户', 'icon': "&#xe60b;", 'parent_title': '系统管理'},
        {'title': '节点管理', 'icon': "&#xe60b;", 'parent_title': '系统管理'},
        {'title': '系统日志', 'icon': "&#xe63c;", 'parent_title': '系统管理'},

    ]

    for item in submain_list:
        models.Menu.objects.get_or_create(
            title=item['title'],
            icon=item['icon'],
            parent=models.Menu.objects.filter(title=item['parent_title']).first(),
        )

    permission_list = [

        {'title': 'CC规则组', 'url': '/rule/official', 'is_menu': True, 'menu_title': 'CC规则组'},
        {'title': '自定义规则组', 'url': '/rule/custom', 'is_menu': True, 'menu_title': '自定义规则组'},

        {'title': 'WAF全局配置', 'url': '/setting/', 'is_menu': True, 'menu_title': 'WAF全局配置'},
        {'title': '响应规则模板', 'url': '/setting/rule', 'is_menu': True, 'menu_title': '响应规则模板'},

        {'title': '拦截日志', 'url': '/waf/', 'is_menu': True, 'menu_title': '拦截日志'},
        {'title': '访问日志', 'url': '/waf/search', 'is_menu': True, 'menu_title': '访问日志'},

        {'title': '添加站点', 'url': '/manage/station', 'is_menu': True, 'menu_title': '添加站点'},

        {'title': '添加证书', 'url': '/manage/certificate', 'is_menu': True, 'menu_title': '添加证书'},

        {'title': '计划任务', 'url': '/manage/plantask', 'is_menu': True, 'menu_title': '计划任务'},

        {'title': '监控', 'url': '/manage/monitoring', 'is_menu': True, 'menu_title': '监控'},

        {'title': '基本设置', 'url': '/manage/mails/', 'is_menu': True, 'menu_title': '基本设置'},
        {'title': '告警设置', 'url': '/manage/dingding/', 'is_menu': True, 'menu_title': '告警设置'},
        {'title': '数据备份', 'url': '/manage/backups/', 'is_menu': True, 'menu_title': '数据备份'},
        {'title': '用户列表', 'url': '/manage/user/', 'is_menu': True, 'menu_title': '用户列表'},
        # {'title': '新增用户', 'url': '/manage/userrequest/', 'is_menu': True, 'menu_title': '新增用户'},
        {'title': '节点管理', 'url': '/manage/node/', 'is_menu': True, 'menu_title': '节点管理'},
        {'title': '系统日志', 'url': '/manage/userlog/', 'is_menu': True, 'menu_title': '系统日志'},

    ]
    for item in permission_list:
        permission_tup = models.Permission.objects.get_or_create(
            title=item['title'],
            url=item['url']
        )
        permission = permission_tup[0]
        if item['is_menu']:
            permission.menu = models.Menu.objects.filter(title=item['menu_title']).first()
            permission.save()


def initrole():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'SeMF.settings')
    django.setup()
    from RBAC.models import Role, Permission
    permissions_list = [
        {'title': '管理员', 'permissions': '拦截日志'},
        {'title': '管理员', 'permissions': '访问日志'},
        {'title': '管理员', 'permissions': 'CC规则组'},
        {'title': '管理员', 'permissions': '自定义规则组'},
        {'title': '管理员', 'permissions': 'WAF全局配置'},
        {'title': '管理员', 'permissions': '响应规则模板'},
        {'title': '管理员', 'permissions': '添加站点'},
        {'title': '管理员', 'permissions': '添加证书'},
        {'title': '管理员', 'permissions': '基本设置'},
        {'title': '管理员', 'permissions': '告警设置'},
        {'title': '管理员', 'permissions': '数据备份'},
        {'title': '管理员', 'permissions': '计划任务'},
        {'title': '管理员', 'permissions': '节点管理'},
        {'title': '管理员', 'permissions': '用户列表'},
        {'title': '管理员', 'permissions': '系统日志'},
        {'title': '管理员', 'permissions': '监控'},

        {'title': '安全员', 'permissions': 'CC规则组'},
        {'title': '安全员', 'permissions': '自定义规则组'},
        {'title': '安全员', 'permissions': 'WAF全局配置'},
        {'title': '安全员', 'permissions': '响应规则模板'},
        {'title': '安全员', 'permissions': '添加站点'},
        {'title': '安全员', 'permissions': '添加证书'},
        {'title': '安全员', 'permissions': '拦截日志'},
        {'title': '安全员', 'permissions': '访问日志'},
        {'title': '安全员', 'permissions': '节点管理'},

        {'title': '审计员', 'permissions': '拦截日志'},
        {'title': '审计员', 'permissions': '访问日志'},
        {'title': '审计员', 'permissions': '数据备份'},
        {'title': '审计员', 'permissions': '计划任务'},
        {'title': '审计员', 'permissions': '系统日志'},

    ]
    for item in permissions_list:
        role_list = Role.objects.get_or_create(title=item['title'])
        role_list[0].permissions.add(Permission.objects.filter(title=item['permissions']).first())
        role_list[0].save()

    print('initrole ok')


def initarea():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'SeMF.settings')
    django.setup()
    from RBAC.models import Area
    area_list = [
        {'name': '华北'},
        {'name': '华南'},
        {'name': '华东'},
        {'name': '华中'},
    ]
    for item in area_list:
        Area.objects.get_or_create(name=item['name'])
    print('initrole ok')


def initsuperuser():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'SeMF.settings')
    django.setup()
    from RBAC.models import Role
    from django.contrib.auth.models import User
    user_manage_list = User.objects.filter(is_superuser=True)
    role = Role.objects.filter(title='管理员').first()
    for user in user_manage_list:
        user.profile.roles.add(role)
        user.save()
    print('initsuperuser ok')


if __name__ == "__main__":
    initmenu()
    initrole()
    initarea()
    initsuperuser()
