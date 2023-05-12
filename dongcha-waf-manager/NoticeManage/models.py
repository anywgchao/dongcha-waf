#coding:utf-8

from django.db import models
from django.contrib.auth.models import User
import django.utils.timezone as timezone

NOTICE_TYPE = (
                ('notice','安全通告'),
                ('inform','任务通知'),
               )

class Notice(models.Model):
    notice_title = models.CharField('通知标题',max_length = 30)
    notice_body = models.TextField('通知内容')
    notice_status = models.BooleanField('阅读状态',default = False)
    notice_url = models.CharField('父链接',max_length = 50,null=True)
    notice_type = models.CharField('通知类型',max_length = 30,choices=NOTICE_TYPE)
    notice_time = models.DateTimeField('通知时间',default = timezone.now)
    
    notice_user = models.ForeignKey(User,related_name='notice_for_user',verbose_name=u'所属用户',on_delete=models.CASCADE)
    
    def __str__(self):
        return self.notice_title


class os_notice(models.Model):
    cup_notice = models.CharField('cpu', max_length=50, null=True)
    mem_notice = models.CharField('mem', max_length=50, null=True)
    disk_notice = models.CharField('disk', max_length=50, null=True)
    updatetime = models.DateTimeField('更新时间', auto_now=True)

    def __str__(self):
        return self.cup_notice
