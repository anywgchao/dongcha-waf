# coding:utf-8

from django import forms
from . import models
from django.forms import ModelForm
from django.forms import widgets


class UserRequestForm(ModelForm):
    class Meta:
        model = models.UserRequest
        fields = ['email', 'area', 'request_type']
        widgets = {
            'email': widgets.TextInput(attrs={'class': 'layui-input', 'placeholder': '邮箱地址'}),
            'area': widgets.Select(attrs={'class': 'layui-input', 'placeholder': '所属区域'}),
            'request_type': widgets.Select(attrs={'class': 'layui-input', 'placeholder': '账号类型'}),
        }


class ResetpsdRequestForm(forms.Form):
    email = forms.CharField(label='邮箱', max_length=50,
                            widget=forms.TextInput(attrs={'class': 'layui-input', 'placeholder': '邮箱地址'}))


class ResetpsdForm(forms.Form):
    email = forms.CharField(label='邮箱', max_length=50,
                            widget=forms.TextInput(attrs={'class': 'layui-input', 'placeholder': '邮箱地址'}))
    password = forms.CharField(label='新密码', max_length=25,
                               widget=forms.PasswordInput(attrs={'class': 'layui-input', 'placeholder': '新密码'}))
    repassword = forms.CharField(label='新密码', max_length=25,
                                 widget=forms.PasswordInput(attrs={'class': 'layui-input', 'placeholder': '新密码'}))


class SigninForm(forms.Form):
    username = forms.CharField(label='账号', max_length=75,
                               widget=forms.TextInput(attrs={'class': 'layui-input', 'placeholder': '用户名/邮箱前缀'}))
    password = forms.CharField(label='密码', max_length=25,
                               widget=forms.PasswordInput(attrs={'class': 'layui-input', 'placeholder': '密码'}))


class Account_Reset_Form(forms.Form):
    firstname = forms.CharField(label='姓', max_length=75,
                                widget=forms.TextInput(attrs={'class': 'layui-input', 'placeholder': '姓'}))
    lastname = forms.CharField(label='名', max_length=75,
                               widget=forms.TextInput(attrs={'class': 'layui-input', 'placeholder': '名'}))
    email = forms.CharField(label='邮箱', max_length=75,
                            widget=forms.TextInput(attrs={'class': 'layui-input', 'placeholder': '邮箱'}))
    password = forms.CharField(label='密码', max_length=25,
                               widget=forms.PasswordInput(attrs={'class': 'layui-input', 'placeholder': '密码'}))
    repassword = forms.CharField(label='重复密码', max_length=25,
                                 widget=forms.PasswordInput(attrs={'class': 'layui-input', 'placeholder': '重复密码'}))


class ChangPasswdForm(forms.Form):
    old_password = forms.CharField(label='原密码', max_length=25,
                                   widget=forms.PasswordInput(attrs={'class': 'layui-input', 'placeholder': '原密码'}))
    new_password = forms.CharField(label='新密码', max_length=25,
                                   widget=forms.PasswordInput(attrs={'class': 'layui-input', 'placeholder': '新密码'}))
    re_new_password = forms.CharField(label='确认新密码', max_length=25,
                                      widget=forms.PasswordInput(attrs={'class': 'layui-input', 'placeholder': '新密码'}))


class UserInfoForm(ModelForm):
    class Meta:
        model = models.Profile
        fields = ['user_nickname', 'mobilephone', 'description']
        widgets = {
            'user_nickname': widgets.TextInput(attrs={'class': 'layui-input', 'placeholder': '昵称'}),
            'mobilephone': widgets.TextInput(
                attrs={'class': 'layui-input', 'placeholder': '手机号码', 'lay-verify': 'phone', 'autocomplete': 'off',
                       'type': 'tel'}),
            'description': widgets.TextInput(attrs={'class': 'layui-input', 'placeholder': '员工介绍'}),
        }
