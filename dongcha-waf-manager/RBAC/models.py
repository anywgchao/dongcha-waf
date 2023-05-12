# coding:utf-8
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
import django.utils.timezone as timezone


class Area(models.Model):
    name = models.CharField('属地信息', max_length=90, unique=True)
    parent = models.ForeignKey('self', verbose_name='父级属地', related_name='assetarea_area', null=True, blank=True,
                               on_delete=models.CASCADE)

    def __str__(self):
        # 显示层级菜单
        title_list = [self.name]
        p = self.parent
        while p:
            title_list.insert(0, p.name)
            p = p.parent
        return '-'.join(title_list)

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rbac_area'
        verbose_name = '地区管理'
        verbose_name_plural = '地区管理'


# 设置菜单
class Menu(models.Model):
    title = models.CharField(u'菜单标题', max_length=25, unique=True)
    icon = models.CharField(u'菜单图标', max_length=50)
    parent = models.ForeignKey('self', verbose_name=u'父菜单', related_name='menu_menu', null=True, blank=True,
                               on_delete=models.CASCADE)

    def __str__(self):
        # 显示层级菜单
        title_list = [self.title]
        p = self.parent
        while p:
            title_list.insert(0, p.title)
            p = p.parent
        return '-'.join(title_list)

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rbac_menu'
        verbose_name = '菜单管理'
        verbose_name_plural = '菜单管理'


# 设置访问链接
class Permission(models.Model):
    title = models.CharField(u'权限标题', max_length=50, unique=True)
    is_menu = models.BooleanField('菜单显示', default=False)
    url = models.CharField(max_length=128)
    menu = models.ForeignKey(Menu, null=True, verbose_name=u'权限菜单', related_name='permission_menu',
                             on_delete=models.CASCADE)

    def __str__(self):
        return '{menu}--{permission}'.format(menu=self.menu, permission=self.title)

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rbac_permission'
        verbose_name = '权限管理'
        verbose_name_plural = '权限管理'


# 设置角色和权限
class Role(models.Model):
    title = models.CharField(u'角色名称', max_length=25, unique=True)
    permissions = models.ManyToManyField(Permission, verbose_name=u'权限菜单', related_name='role_permission')

    def __str__(self):
        return self.title

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rbac_role'
        verbose_name = '角色管理'
        verbose_name_plural = '角色管理'


REQUEST_STATUS = (
    ('0', '待审批'),
    ('1', '审批通过'),
    ('2', '审批拒绝'),
)

TYPE = (
    ('关闭', '关闭'),
    ('开启', '开启'),
)


# 注册有审批时使用
class UserRequest(models.Model):
    email = models.EmailField('申请邮箱')
    urlarg = models.CharField('注册参数', max_length=50)
    status = models.CharField('审批状态', max_length=50, default='0', choices=REQUEST_STATUS)
    is_check = models.BooleanField('是否审批', default=False)
    is_use = models.BooleanField('是否使用', default=False)
    request_type = models.ForeignKey(Role, verbose_name=u'账号权限', related_name='userrequest_role',
                                     on_delete=models.CASCADE)
    starttime = models.DateTimeField('申请时间', auto_now_add=True)
    updatetime = models.DateTimeField('审批时间', auto_now=True)

    area = models.ForeignKey(Area, verbose_name='所属区域', related_name='userrequest_area', null=True,
                             on_delete=models.CASCADE, limit_choices_to={'parent__isnull': True})
    action_user = models.ForeignKey(User, related_name='regist_for_actionuser', on_delete=models.CASCADE, null=True)

    def __str__(self):
        return self.email

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rbac_userrequest'
        verbose_name = '用户请求'
        verbose_name_plural = '用户请求'


# 重置密码时使用
class UserResetpsd(models.Model):
    email = models.EmailField('申请邮箱')
    urlarg = models.CharField('重置参数', max_length=50)
    is_check = models.BooleanField('是否使用', default=False)
    updatetime = models.DateField('更新时间', auto_now=True)

    def __str__(self):
        return self.email

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rbac_userresetpsd'


class captcha(models.Model):
    captcha_name = models.CharField('验证', max_length=20, null=True)

    def __str__(self):
        return self.captcha_name

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rbac_captcha'


# 用户操作记录
class UserLog(models.Model):
    uesr_logid = models.CharField('编号', max_length=50, null=True)
    user_name = models.CharField('用户名', max_length=50, null=True)
    user_ip = models.CharField('来源ip', max_length=50, null=True)
    log_type = models.CharField('日志类型', max_length=50, null=True)
    user_action = models.CharField('操作内容', max_length=50, null=True)
    action_description = models.TextField('操作描述', null=True)
    updatetime = models.DateTimeField('时间', auto_now=True)

    def __str__(self):
        return self.user_name

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rbac_userlog'
        verbose_name = '用户操作记录'
        verbose_name_plural = '用户操作记录'


class User_mails(models.Model):
    smtp_name = models.CharField('smtp名称', max_length=100, null=True, blank=True)
    smtp_ip = models.CharField('smtp服务主机名', max_length=100, null=True, blank=True)
    smtp_port = models.CharField('smtp端口', max_length=50, null=True, blank=True)
    ssl_use = models.CharField('是否启用', max_length=50, null=True, blank=True)
    overtime = models.CharField('超时时间', max_length=50, null=True, blank=True)
    mails = models.CharField('邮箱账号', max_length=50, null=True, blank=True)
    mails_psd = models.CharField('邮箱密码', max_length=50, null=True, blank=True)
    mails_test = models.CharField('测试邮箱', max_length=50, null=True, blank=True)
    ding_token = models.CharField('dingtoken', max_length=200, null=True, blank=True)
    ding_key = models.CharField('dingkey', max_length=200, null=True, blank=True)
    es_address = models.CharField('es地址', max_length=200, null=True, blank=True)
    # es_index = models.CharField('es索引', max_length=200, null=True, blank=True)
    smtp_content = models.TextField('描述', null=True, blank=True)
    setting_updatetime = models.DateTimeField('更新时间', auto_now=True)

    def __str__(self):
        return self.smtp_name

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        verbose_name = '邮箱设置'
        verbose_name_plural = '邮箱设置'


class User_setting(models.Model):
    applyname = models.CharField('行业应用', max_length=100, null=True, blank=True)
    username = models.CharField('系统负责人', max_length=100, null=True, blank=True)
    phone = models.CharField('联系电话', max_length=50, null=True, blank=True)
    nickname = models.CharField('系统别名', max_length=50, null=True, blank=True)
    del_time = models.CharField('删除时间', max_length=50, null=True, blank=True)
    alarm_use = models.CharField('是否告警', max_length=50, null=True, blank=True)
    mfa = models.CharField('mfa', max_length=50, null=True, blank=True)
    loginnum = models.CharField('限制登录失败次数', max_length=50, null=True, blank=True)
    time = models.CharField('登录时间间隔', max_length=50, null=True, blank=True)
    stoptime = models.CharField('禁止登录时间间隔', max_length=50, null=True, blank=True)
    setting_updatetime = models.DateTimeField('更新时间', auto_now=True)

    def __str__(self):
        return self.applyname


# 用户附加属性
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    user_num = models.CharField(u'员工编号', max_length=50, null=True, blank=True)
    user_nickname = models.CharField(u'账号昵称', max_length=50, null=True, blank=True)
    user_target = models.CharField(u'员工标签', max_length=200, null=True, blank=True)
    user_head = models.CharField(u'员工头像', max_length=200, default='/static/images/head/little_boy.png')
    title = models.CharField(u'角色', max_length=50)

    telephone = models.CharField(u'座机号码', max_length=50, null=True, blank=True)
    mobilephone = models.CharField(u'手机号', max_length=100)
    es_address = models.CharField(u'es地址', max_length=100, null=True, blank=True)
    description = models.TextField(u'备注')
    mfa = models.CharField(u'MFA认证', max_length=50, null=True, blank=True)
    mfa_key = models.CharField(u'MFA秘钥', max_length=200, null=True, blank=True)
    error_count = models.IntegerField(u'错误登陆', default=0)
    lock_time = models.DateTimeField(u'锁定时间', default=timezone.now)

    parent_email = models.EmailField('上级邮箱', null=True, blank=True)
    parent = models.ForeignKey(User, verbose_name='上级汇报', related_name='user_parent', null=True, blank=True,
                               on_delete=models.CASCADE)
    area = models.ForeignKey(Area, verbose_name='所属区域', related_name='user_area', null=True, on_delete=models.CASCADE,
                             limit_choices_to={'parent__isnull': True})

    roles = models.ManyToManyField(Role, verbose_name=u'所属角色', related_name='user_role')

    def __str__(self):
        return self.user.username

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rbac_profile'
        verbose_name = '用户附加属性'
        verbose_name_plural = '用户附加属性'


# 用户操作记录
class MFA(models.Model):
    is_check = models.CharField('开启mfa功能', max_length=50, choices=TYPE, default='关闭')

    # updatetime = models.DateTimeField('时间', auto_now=True)

    def __str__(self):
        return self.is_check

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'rbac_mfa'
        verbose_name = '启用mfa认证'
        verbose_name_plural = '启用mfa认证'


# 同步保存信息
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.get_or_create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()
