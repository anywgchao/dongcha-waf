# coding:utf-8
from django.db import models


TYPE = (
    ('0', 'text/html'),
    ('1', 'application/json'),
)
USE = (
    ('0', '启用'),
    ('1', '未启用'),
)
USES = (
    ('启用', '启用'),
    ('未启用', '未启用'),
)


class Setting_template(models.Model):
    setting_id = models.CharField('设置ID', max_length=50, null=True)
    setting_name = models.CharField('规则名称', max_length=200,null=True, blank=True)
    setting_type = models.CharField('Content-Type', max_length=50, choices=TYPE, default='0' )
    setting_use = models.CharField('是否启用', max_length=50, choices=USE, default='1' )
    setting_content = models.TextField('响应内容', null=True, blank=True)
    setting_updatetime = models.DateTimeField('更新时间', auto_now=True)
    template_user = models.CharField('用户', max_length=50, null=True, blank=True)

    def __str__(self):
        return self.setting_name

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'settingmanage_setting_template'
        verbose_name = 'WAF设置模板'
        verbose_name_plural = 'WAF设置模板'


class Setting_deploy(models.Model):
    deploy_id = models.CharField('设置ID', max_length=50, null=True)
    deploy_data = models.TextField('配置文件',null=True)
    deploy_updatetime = models.DateTimeField('更新时间', auto_now=True)
    deploy_user = models.CharField('用户', max_length=50, null=True, blank=True)
    deploy_alarm = models.CharField('报警', max_length=50, null=True, blank=True)

    class Meta:
        db_table = 'settingmanage_setting_deploy'
        verbose_name = 'WAF全局配置'
        verbose_name_plural = 'WAF全局配置'


class Setting_time(models.Model):
    time_data = models.IntegerField('抓取日志时间(分钟)')
    time_updatetime = models.DateTimeField('更新时间', auto_now=True)
    time_user = models.CharField('用户', max_length=50, null=True, blank=True)

    class Meta:
        db_table = 'settingmanage_setting_time'
        verbose_name = 'WAF日志时间配置'
        verbose_name_plural = 'WAF日志时间配置'


class Setting_uuid(models.Model):
    uuid = models.CharField('uuid', max_length=50,null=True)
    uuid_updatetime = models.DateTimeField('更新时间', auto_now=True)
    uuid_user = models.CharField('用户', max_length=50, null=True, blank=True)

    def __str__(self):
        return self.uuid

    class Meta:
        db_table = 'settingmanage_setting_uuid'
        verbose_name = 'WAF秘钥配置'
        verbose_name_plural = 'WAF秘钥配置'


class OS_info(models.Model):
    os_cpu = models.CharField('os_cpu', max_length=50,null=True)
    os_men = models.CharField('os_men', max_length=50,null=True)
    os_resource = models.CharField('os_resource', max_length=50,null=True)
    os_load = models.CharField('os_load', max_length=50,null=True)
    disk_readio = models.CharField('disk_readio', max_length=50,null=True)
    disk_writeio = models.CharField('disk_writeio', max_length=50,null=True)
    net_sent = models.CharField('net_sent', max_length=50,null=True)
    net_recv = models.CharField('net_recv', max_length=50,null=True)
    updatetime = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'settingmanage_os_info'

