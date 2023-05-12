#coding:utf-8


from django.urls import path
from SeMFSetting.Functions import mysql_base
from . import views


urlpatterns = [
    path('', views.SettingView, name='settingView'),

    path('rule/', views.rule_template, name='rule_template'),

    path('getrule/', views.get_rule, name='get_rule'),
    path('getsetting/', views.get_setting, name='get_setting'),

    path('manage/station/list', mysql_base.stationlist, name='stationlist'),
    path('manage/certificate/list', mysql_base.certificatelist, name='certificatelist'),
    path('manage/node/list', mysql_base.nodelist, name='nodelist'),
    path('manage/node/grouplist', mysql_base.nodegrouplist, name='nodegrouplist'),
    path('manage/node/groupdel/<str:group_name>/', mysql_base.nodegroupdel, name='nodegroupdel'),

    path('templatelist/', views.templatelist, name='templatelist'),
    path('templatelists/', views.test, name='templatelists'),
    path('setting_update/<str:setting_id>/', views.setting_update, name='settingupdate'),

    path('settingdel/<str:setting_id>/', views.setting_del, name='settingdel'),

]