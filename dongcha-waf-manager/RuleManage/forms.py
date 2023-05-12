#coding:utf-8

from django.forms import ModelForm
from . import models
from django.forms import widgets


class Rule_create_form(ModelForm):
    class Meta:
        model = models.Rules_group
        fields = [ 'rules_id','rules_details', 'rules_use', 'detection', 'rules_version']
        widgets = {
            'rules_id': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '请输入10000以上的数'}),
            'rules_details': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '规则详情'}),
            'rules_use': widgets.RadioSelect(),
            'detection': widgets.Select(attrs={'class': 'form-control', 'placeholder': '资产类型'}),
            'rules_version': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '规则组版本'}),
        }






class Rule_detail_form(ModelForm):
    class Meta:
        model = models.Rules
        fields = ['rule_id', 'rule_detail', 'kind', 'level', 'handle',
                  'match_pattern', 'parameter_match']
        widgets = {
            'rule_id': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '规则id'}),
            'rule_detail': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '规则详情'}),
            'kind': widgets.Select(),
            'level': widgets.Select(),
            'handle': widgets.Select(),
            'match_pattern': widgets.Select(attrs={'class': 'form-control'}),
            'parameter_match': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '规则'}),

        }


class CC_create_form(ModelForm):
    class Meta:
        model = models.CC_group
        fields = [ 'ccgroup_id','ccgroup_details', 'ccgroup_use', 'detection', 'ccgroup_version']
        widgets = {
            'ccgroup_id': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '请输入10000以上的数'}),
            'ccgroup_details': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '规则详情'}),
            'ccgroup_use': widgets.RadioSelect(),
            'detection': widgets.Select(attrs={'class': 'form-control', 'placeholder': '资产类型'}),
            'ccgroup_version': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '规则组版本'}),
        }


class CC_detail_form(ModelForm):
    class Meta:
        model = models.CC_rule
        fields = ['cc_id', 'cc_detail',  'rate_or_count', 'burst_or_time',
                  'handle','match_pattern', 'parameter_match']
        widgets = {
            'cc_id': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '规则id'}),
            'cc_detail': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '规则详情'}),
            'rate_or_count': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': ''}),
            'burst_or_time': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': ''}),
            'handle': widgets.Select(),
            'match_pattern': widgets.Select(attrs={'class': 'form-control'}),
            'parameter_match': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': '规则'}),

        }
