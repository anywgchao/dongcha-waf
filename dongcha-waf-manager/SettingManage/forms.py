#coding:utf-8

from django.forms import ModelForm
from . import models
from django.forms import widgets


class Setting_template_form(ModelForm):
    class Meta:
        model = models.Setting_template
        fields = ['setting_name', 'setting_type', 'setting_use', 'setting_content']
        widgets = {
            'setting_name': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': 'name of the response'}),
            'setting_type': widgets.Select(),
            'setting_use': widgets.Select(),
            'setting_content': widgets.Textarea(attrs={'class': 'form-control', 'placeholder': 'http esponse body'}),
        }
