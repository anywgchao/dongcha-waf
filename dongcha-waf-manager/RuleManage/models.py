# coding:utf-8
from django.db import models


DETECTION_STATUS = (
    ('0', '请求阶段'),
    ('1', '响应阶段'),
)
CC_DETECTION_STATUS = (
    ('0', 'cc防护'),
)

RULE_USE = (
    ('0', '是'),
    ('1', '否'),
)
KIND = (
    ('0', '通用基础'),
    ('1', 'SQL注入'),
    ('2', 'XSS攻击'),
    ('3', '命令注入'),
    ('4', '代码执行'),
    ('5', '上传漏洞'),
    ('6', '信息泄露'),
    ('7', '逻辑漏洞'),
    ('8', '权限绕过'),
    ('9', '文件读取'),
    ('10', '其他'),
)
ACTION = (
    ('limit_req_rate', '速率检测'),
    ('limit_req_count', '单位时间数量检测'),
    ('limit_req_pass', '放行请求'),
)
LEVEL = (
    ('low', '低'),
    ('middle', '中'),
    ('high', '高'),
)
HANDLE = (
    ('deny', '阻断请求'),
    ('pass', '不处理该规则'),
    ('inject_js', '插入js/html代码'),
    ('rewrite', '重写整个页面'),
    ('replace', '替换匹配内容'),
    ('allow', '放行请求(跳过所有后续规则,resp阶段不适用)'),
    ('redirect', '重定向请求(resp阶段不适用)'),
)
PARAMETER_SELECT = (
    ('0', '低'),
    ('1', '中'),
    ('2', '高'),
)
MATCH_PATTERN = (
    ('rx', '正则匹配模式'),
    ('ac', 'AC匹配模式'),
    ('eq', '等于'),
    ('gt', '大于'),
    ('lt', '小于'),
    ('ge', '大于或等于'),
    ('le', '小于或等于'),
    ('detectSQLi', 'SQL注入语义识别'),
    ('detectXSS', 'XSS攻击语义识别'),
)


class Rules_group(models.Model):
    rules_id = models.CharField('规则组ID', max_length=50, null=True, blank=True)
    rules_details = models.CharField('规则描述', max_length=50, null=True, blank=True)
    detection = models.CharField('检测阶段', max_length=50, choices=DETECTION_STATUS, default='0')
    rules_use = models.CharField('是否启用', max_length=50, choices=RULE_USE, default='0')
    rules_num = models.CharField('规则数', max_length=50, null=True, blank=True)
    rules_version = models.CharField('规则版本号', max_length=50, null=True, blank=True)
    rulegroup_user = models.CharField('用户', max_length=50, null=True, blank=True)
    rules_updatetime = models.DateTimeField('更新时间', auto_now=True)

    def __str__(self):
        return self.rules_id

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rulemanage_rules_group'
        verbose_name = '自定义规则组'
        verbose_name_plural = '自定义规则组'


class Rules(models.Model):
    rule_id = models.CharField('规则ID', max_length=50, null=True, blank=True)
    rule_detail = models.CharField('规则详情', max_length=200, null=True, blank=True)
    kind = models.CharField('规则种类', max_length=50, choices=KIND, default='0')
    log = models.CharField('是否有日志', max_length=50, choices=RULE_USE, default='0')
    rule_use = models.CharField('是否启用', max_length=50, choices=RULE_USE, default='0')
    level = models.CharField('严重性', max_length=50, choices=LEVEL, default='0')
    handle = models.CharField('命中处理', max_length=50, choices=HANDLE, default='0')
    extra = models.TextField('补充', null=True,blank=True)
    parameter_select = models.TextField('参数选择', null=True,blank=True)
    parameter_handle = models.TextField('参数处理', null=True,blank=True)
    match_pattern = models.CharField('匹配模式', max_length=50, choices=MATCH_PATTERN, default='0')
    parameter_match = models.TextField('参数匹配', null=True, blank=True)
    resulr_negation = models.CharField('是否取反', max_length=50, choices=RULE_USE, default='1')
    rule_updatetime = models.DateTimeField('更新时间', auto_now=True)
    rule_group = models.ForeignKey(Rules_group, related_name='rule_for_rulegroup', on_delete=models.CASCADE)
    rule_user = models.CharField('用户', max_length=50, null=True, blank=True)

    def __str__(self):
        return self.rule_id

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rulemanage_rules'
        verbose_name = '自定义规则'
        verbose_name_plural = '自定义规则'




class CC_group(models.Model):
    ccgroup_id = models.CharField('规则组ID', max_length=50, null=True, blank=True)
    ccgroup_details = models.CharField('规则描述', max_length=50, null=True, blank=True)
    detection = models.CharField('检测阶段', max_length=50, choices=CC_DETECTION_STATUS, default='0')
    ccgroup_use = models.CharField('是否启用', max_length=50, choices=RULE_USE, default='0')
    ccgroup_num = models.CharField('规则数', max_length=50, null=True, blank=True)
    ccgroup_version = models.CharField('规则版本号', max_length=50, null=True, blank=True)
    ccgroup_updatetime = models.DateTimeField('更新时间', auto_now=True)
    ccgroup_user = models.CharField('用户', max_length=50, null=True, blank=True)

    def __str__(self):
        return self.ccgroup_id

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rulemanage_cc_group'
        verbose_name = 'cc规则组'
        verbose_name_plural = 'cc规则组'


class CC_rule(models.Model):
    cc_id = models.CharField('规则ID', max_length=50, null=True, blank=True)
    cc_detail = models.CharField('规则详情', max_length=200, null=True, blank=True)
    rule_use = models.CharField('是否启用', max_length=50, choices=RULE_USE, default='0')
    log = models.CharField('是否有日志', max_length=50, choices=RULE_USE, default='0')
    delay = models.CharField('延迟请求', max_length=50, choices=RULE_USE, default='0')
    global_defend = models.CharField('全局防护', max_length=50, choices=RULE_USE, default='0')
    rate_or_count = models.CharField('rate_or_count', max_length=50, null=True, blank=True)
    burst_or_time = models.CharField('burst_or_time', max_length=50, null=True, blank=True)
    handle = models.CharField('命中处理', max_length=50, choices=ACTION, default='0')
    extra = models.TextField('补充', null=True,blank=True)
    parameter_sign = models.TextField('标识参数', null=True,blank=True)
    parameter_select = models.TextField('参数选择', null=True,blank=True)
    parameter_handle = models.TextField('参数处理', null=True,blank=True)
    match_pattern = models.CharField('匹配模式', max_length=50, choices=MATCH_PATTERN, default='0')
    parameter_match = models.TextField('参数匹配', null=True, blank=True)
    resulr_negation = models.CharField('是否取反', max_length=50, choices=RULE_USE, default='1')
    cc_updatetime = models.DateTimeField('更新时间', auto_now=True)
    cc_group = models.ForeignKey(CC_group, related_name='cc_for_ccgroup', on_delete=models.CASCADE)
    cc_user = models.CharField('用户', max_length=50, null=True, blank=True)

    def __str__(self):
        return self.cc_id

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rulemanage_cc_rule'
        verbose_name = 'cc规则'
        verbose_name_plural = 'cc规则'


class remote_rule(models.Model):
    remote_id = models.CharField('规则ID', max_length=50, null=True, blank=True)
    remote_use = models.CharField('是否启用', max_length=50, choices=RULE_USE, default='0')

    remote_details = models.TextField('参数匹配', null=True, blank=True)
    remote_updatetime = models.DateTimeField('更新时间', auto_now=True)
    remote_user = models.CharField('用户', max_length=50, null=True, blank=True)

    def __str__(self):
        return self.remote_id

