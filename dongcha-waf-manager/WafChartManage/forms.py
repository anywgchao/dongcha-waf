# coding:utf-8

from . import models
from django.forms import ModelForm, widgets


class WafLogForm(ModelForm):
    class Meta:
        model = models.Waf_log
        fields = ['detail']
        widgets = {
            'detail': widgets.Textarea(
                attrs={'class': 'form-control', 'placeholder': '日志详情', 'style': 'height: 600px'}),
        }


class PlanForm(ModelForm):
    class Meta:
        model = models.PlanTask
        fields = ['task_name', 'task_target', 'execution']
        widgets = {
            'task_name': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '任务名称'}),
            'task_target': widgets.Select(attrs={'class': 'form-control'}),
            'execution': widgets.Select(attrs={'class': 'form-control'}),
        }


class CertificateForm(ModelForm):
    class Meta:
        model = models.Certificate
        fields = ['certificate_name', 'certificate_des', 'certificate_public', 'certificate_key']
        widgets = {
            'certificate_public': widgets.Textarea(attrs={'class': 'form-control', 'placeholder': '公钥'}),
            'certificate_key': widgets.Textarea(attrs={'class': 'form-control', 'placeholder': '私钥'}),
            'certificate_name': widgets.TextInput(attrs={'class': 'layui-input', 'placeholder': '唯一证书名称'}),
            'certificate_des': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '证书描述'}),
        }


class NodeForm(ModelForm):
    class Meta:
        model = models.Node
        fields = ['node_name', 'node_des', 'manager_address', 'node_group']
        widgets = {
            'node_name': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '节点名称'}),
            'node_des': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '节点接口'}),
            'manager_address': widgets.TextInput(
                attrs={'class': 'form-control', 'placeholder': '项目管理平台接口'}),
            'node_group': widgets.Select(attrs={'class': 'form-control'}),
        }


class NodegroupForm(ModelForm):
    class Meta:
        model = models.Node_group
        fields = ['group_name']
        widgets = {
            'group_name': widgets.TextInput(
                attrs={'class': 'form-control', 'placeholder': '提示：节点标签最多能添加10个，标签名称限制20个中文字符，基本已经能够满足大部分需求。'}),
        }


class ImpowertimeForm(ModelForm):
    class Meta:
        model = models.Node
        fields = ['node_license']
        widgets = {
            'node_license': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': 'license授权信息'}),
        }
