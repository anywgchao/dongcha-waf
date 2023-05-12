# coding:utf-8

from django.db import models
from django.contrib.auth.models import User
from django.utils.html import format_html

FILE_TYPE = (
    ('网络设备', '网络设备'),
    ('业务系统', '业务系统'),
    ('漏洞列表', '漏洞列表'),
)


class files(models.Model):
    name = models.CharField('名称', max_length=50, null=True)
    file_type = models.CharField('类型', max_length=50, choices=FILE_TYPE)
    file = models.FileField('批量文件', upload_to='files/')
    update_data = models.DateField("更新日期", auto_now=True)

    action_user = models.ForeignKey(User, related_name='asset_files_user', on_delete=models.CASCADE, null=True,
                                    blank=True)

    def __str__(self):
        return self.name

    class Meta:
        # 设置模型的名字，但是记得复数形式也要设置，否则有些地方就变成 verbose_name + s 了
        db_table = 'semfsetting_files'
        verbose_name = '文件管理'
        verbose_name_plural = '文件管理'

