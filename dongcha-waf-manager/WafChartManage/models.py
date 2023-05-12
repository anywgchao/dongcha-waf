# coding:utf-8
from django.db import models

TASK_TYPE = (
    ('数据库备份', '数据库备份'),
    ('审计日志备份', '审计日志备份'),
    ('访问日志备份', '访问日志备份'),
)
TASK_STATUS = (
    ('启用', '启用'),
    ('停止', '停止'),
)


class Waf_log(models.Model):
    log_id = models.CharField('日志id', max_length=30)
    log_type = models.CharField('日志类型', max_length=100, null=True)
    attack_type = models.CharField('攻击类型', max_length=100, null=True)
    request_time = models.CharField('请求时间', max_length=60, null=True)
    attack_origin = models.CharField('攻击来源', max_length=50, null=True)
    target_address = models.CharField('目标地址', max_length=200, null=True)
    uri_address = models.TextField('uri地址', null=True)
    describe = models.CharField('描述', max_length=200, null=True)
    detail = models.TextField('详情', null=True)
    log_user = models.CharField('用户', max_length=50, null=True, blank=True)
    update_data = models.DateTimeField('更新时间', auto_now=True)

    def __str__(self):
        return self.log_id

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'wafchartmanage_waf_log'


class PlanTask(models.Model):
    task_name = models.CharField('*任务名称', max_length=200, null=True)  # 任务名称
    task_target = models.CharField('*任务类型', max_length=30, null=True, choices=TASK_TYPE)  # 任务名称
    task_period = models.CharField('任务周期(小时)', max_length=25, null=True, blank=True)  # 时间周期
    task_starttime = models.CharField('开始时间', max_length=200, null=True, blank=True)  # 任务开始时间
    task_endtime = models.DateTimeField('完成时间', auto_now=True, null=True, blank=True)  # 任务结束时间
    execution = models.CharField('执行状态', max_length=20, null=True, blank=True, choices=TASK_STATUS)


class Backups(models.Model):
    backups_name = models.CharField('备份名称', max_length=200, null=True)  # 任务名称
    backups_target = models.CharField('备份类型', max_length=30, null=True)  # 任务名称
    backups_size = models.CharField('备份大小', max_length=25, null=True, blank=True)  # 时间周期
    task_starttime = models.CharField('开始时间', max_length=200, null=True, blank=True)  # 任务开始时间
    task_endtime = models.DateTimeField('完成时间', auto_now=True, null=True, blank=True)  # 任务结束时间


class Certificate(models.Model):
    certificate_name = models.CharField('证书名称', max_length=200, null=True)  # 任务名称
    certificate_id = models.CharField('证书id', max_length=100, null=True)  # 任务名称
    impower_time = models.CharField('到期时间', max_length=100, null=True)  # 任务名称
    certificate_des = models.TextField('证书描述', null=True)  # 时间周期
    certificate_public = models.TextField('公钥', null=True)
    certificate_key = models.TextField('私钥', null=True)
    task_endtime = models.DateTimeField('完成时间', auto_now=True, null=True, blank=True)  # 任务结束时间

    def __str__(self):
        return self.certificate_id


class Node_group(models.Model):
    group_name = models.CharField('节点标签', max_length=200, null=True)
    group_target = models.CharField('节点标签', max_length=200, null=True)
    group_id = models.CharField('节点id', max_length=30, null=True)
    group_time = models.DateTimeField('完成时间', auto_now=True, null=True, blank=True)

    def __str__(self):
        return self.group_name


class Node(models.Model):
    node_name = models.CharField('节点名称', max_length=200, null=True)
    node_id = models.CharField('节点id', max_length=100, null=True)
    node_des = models.CharField('节点接口', max_length=200, null=True)
    manager_address = models.CharField('管理平台接口', max_length=200, null=True)
    node_version = models.CharField('版本', max_length=200, null=True)
    node_license = models.TextField('license', null=True)
    node_impowertime = models.CharField('时间', max_length=200, null=True)
    node_time = models.DateTimeField('完成时间', auto_now=True, null=True, blank=True)
    node_group = models.ForeignKey(Node_group, verbose_name='节点组', related_name='nodegroup_node_group', null=True,
                                   blank=True,
                                   on_delete=models.CASCADE)

    def __str__(self):
        return str(self.node_id)


class Station(models.Model):
    station_name = models.CharField('站点名称', max_length=200, null=True)
    station_des = models.CharField('站点描述', max_length=200, null=True)
    station_id = models.CharField('站点id', max_length=100, null=True)
    station_agreement = models.CharField('站点协议', max_length=30, null=True)
    upstream_url = models.CharField('上游url', max_length=200, null=True)
    logs = models.TextField('日志', max_length=30, null=True)
    cache = models.CharField('缓存', max_length=30, null=True)
    cache_time = models.CharField('缓存时间', max_length=30, null=True)
    station_url = models.TextField('域名', null=True)
    task_endtime = models.DateTimeField('完成时间', auto_now=True, null=True, blank=True)
    certificate_ids = models.CharField('证书id', max_length=100, null=True)

    def __str__(self):
        return self.station_id


class Wafagent(models.Model):
    agent_name = models.CharField('机器名称', max_length=50)
    agent_id = models.CharField('agent_id', max_length=50)
    agent_key = models.CharField('agent_key', max_length=200)
    agent_url = models.CharField('机器地址', max_length=50)
    agent_version = models.CharField('版本', max_length=50, null=True)
    agent_label = models.CharField('标签', max_length=20, null=True)
    starttime = models.DateTimeField('创建时间', auto_now_add=True)

    def __str__(self):
        return self.agent_name

    class Meta:
        verbose_name = 'WAFAgent'
        verbose_name_plural = 'WAFAgent'
