#coding:utf-8


from django.urls import path

from . import views
from django.conf import settings
from django.conf.urls.static import static
from WafChartManage.views import plantask_add, plantask_update, plantask_del
from SettingManage.views import host_view
from SeMFSetting.Functions.mysql_base import backupslist, planlist, download


urlpatterns = [
    path('view/', views.login, name='login'),
    path('view/mfa/', views.mfa_verify, name='mfa_verify'),
    path('view/init_approve/', views.init_approve, name='init_approve'),
    path('view/pc-geetest/register', views.pcgetcaptcha, name='pcgetcaptcha'),
    path('view/pc-geetest/validate', views.pcvalidate, name='pcvalidate'),

    path('view/check_code/', views.check_code, name='check_code'),

    path('view/pc-geetest/ajax_validate', views.pcajax_validate, name='pcajax_validate'),
    path('view/global_config', views.deploy, name='deploy'),
    path('view/security_rules', views.rules, name='rules'),
    path('view/imgupload/', views.upload_image, name='imgupload'),

    path('view/regist/<str:argu>/', views.regist, name='regist'),
    path('view/resetpsd/<str:argu>/', views.resetpasswd, name='resetpsds'),
    path('user/', views.dashboard, name='dashboard'),
    path('user/main/', views.main, name='main'),
    path('user/logout/', views.logout, name='logout'),
    path('user/changepsd/', views.changepsd, name='changepsd'),
    path('user/info/', views.userinfo, name='userinfo'),
    path('user/changeinfo/', views.changeuserinfo, name='changeuserinfo'),

    path('manage/station/', views.station_manage, name='station'),
    path('manage/station/add', views.station_add, name='stationadd'),
    path('manage/station/stationreload/', views.station_reload, name='stationreload'),
    path('manage/station/rulereload/', views.rule_reload, name='rulereload'),
    path('manage/station/stationupdate/<str:station_id>/', views.station_update, name='stationupdate'),
    path('manage/station/stationview/<str:station_id>/', views.station_view, name='stationview'),
    path('manage/station/stationdel/<str:station_id>/', views.station_del, name='stationdel'),

    path('manage/certificate/', views.certificate_manage, name='certificate'),
    path('manage/certificate/add/', views.certificate_add, name='certificateadd'),
    path('manage/certificate/certificateupdate/<str:certificate_id>/', views.certificate_update, name='certificateupdate'),
    path('manage/certificate/certificatebind/<str:certificate_id>/', views.certificate_bind, name='certificatebind'),
    path('manage/certificate/certificatedel/<str:certificate_id>/', views.certificate_del, name='certificatedel'),

    path('manage/monitoring/', views.monitoring_manage, name='monitoring'),
    path('manage/monitoring/resource/', host_view, name='hostview'),

    path('manage/mails/', views.setting_manage, name='settingmanage'),

    path('manage/dingding/', views.mails_manage, name='dingding'),

    path('manage/backups/', views.data_backups, name='backups'),

    path('manage/backups/list', backupslist, name='backupslist'),
    path('manage/backups/download/<str:log_id>/', download, name='backupdownload'),

    path('manage/plantask/list', planlist, name='planlist'),

    path('manage/plantask/', views.plan_task, name='plantask'),
    path('manage/plantask/add/', plantask_add, name='plantask_add'),
    path('manage/plantask/update/<str:task_name>/', plantask_update, name='plantaskupdate'),
    path('manage/plantask/del/<str:task_name>/', plantask_del, name='plantaskdel'),

    path('manage/user/', views.userlist, name='userview'),
    path('manage/user/list/', views.userlisttable, name='userlist'),
    path('manage/user/add/', views.user_add, name='useradd'),
    path('manage/user/update/<str:user_name>/', views.user_update, name='userupdate'),
    path('manage/user/del/<str:user_name>/', views.user_del, name='userdel'),
    path('manage/user/disactivate/', views.user_disactivate, name='userdisactivate'),

    path('manage/user/userrequest/', views.userregistlist, name='userregistview'),
    path('manage/user/userrequest/list/', views.userregisttable, name='userregistlist'),
    path('manage/user/userrequest/action/', views.userregistaction, name='userregistaction'),
    path('manage/user/userrequest/stop/', views.user_request_cancle, name='userregiststop'),

    path('manage/node/', views.node_manage, name='usernode'),
    path('manage/node/nodeadd', views.Node_add, name='nodeadd'),
    path('manage/node/nodegroupadd', views.Nodegroup_add, name='nodegroupadd'),
    path('manage/node/impowertimeupdate', views.impowertime_update, name='impowertimeupdate'),
    path('manage/node/nodeupdate/<str:node_id>/', views.Node_update, name='nodeupdate'),
    path('manage/node/nodedel/<str:node_id>/', views.Node_del, name='nodedel'),

    path('manage/userlog/', views.userlog, name='userlog'),
    path('manage/userlog/userloglist', views.userloglist, name='userloglist'),


    path('user/mfa/', views.mfa, name='mfa'),
    path('user/approve/', views.approve, name='approve'),
    path('user/psdverify/', views.psd_verify, name='psdverify'),
    path('user/install/', views.software_install, name='install'),
    path('user/close_mfa/', views.close_mfa, name='close_mfa'),
    path('user/update_mfa/', views.update_mfa, name='update_mfa'),
    path('user/user_data/', views.user_data, name='user_data'),
    path('user/regulations', views.regulations, name='regulations'),


    path('user/photo_update', views.photo_update, name='photo_update'),
    path('user/photoview', views.photoview, name='photoview'),



]+static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)