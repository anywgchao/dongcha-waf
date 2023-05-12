# coding:utf-8
from apscheduler.schedulers.background import BackgroundScheduler
from SeMF.settings import TMP_PATH
from .views import creates, waflog_del
from SettingManage.views import host_info
from SeMFSetting.Functions.mysql_base import run_backup, backup, log_backup, remove_files
from .models import PlanTask
import atexit
import fcntl
from django.urls import path
from . import views

urlpatterns = [
    path('', views.chartview, name='chartview'),
    path('search/', views.datasearch, name='datasearch'),
    path('create/', views.create, name='create'),
    path('waflogmail/', views.waf_mail, name='waflogmail'),
    path('wafsearch/', views.waflogsearch, name='wafsearch'),

    path('log_list/', views.loglist, name='loglist'),
    path('log_detail/<str:log_id>/', views.log_details, name='logsdetails'),

    path('getsecond_data/', views.logdatesecond, name='wafgetdatesecond'),
    path('attacktype_data/', views.logattacktype, name='wafattacktype'),
    path('attacktypeorigin/', views.logattackorigin, name='wafattackorigin'),
    path('logtargetaddress/', views.logtargetaddress, name='logtargetaddress'),

    path('acceslogip/', views.acceslogiporigin, name='acceslogiporigin'),
    path('acceslogurl/', views.acceslogurlorigin, name='acceslogurlorigin'),
    path('acceslogstatus/', views.acceslogstatus, name='acceslogstatus'),

    path('logcount_data/', views.logcount, name='logcount'),
    path('log_details/<str:log_id>/', views.log_detail, name='logsdetail'),
    path('log_details/del', views.log_del, name='logdel'),
]


def get_time():
    result_null = ['1', '1', '1', '1', '1', '2020-02-20 17:20:40', '2060-04-20 17:20:40']
    try:
        tasks = PlanTask.objects.filter(task_target='数据库备份', execution='启用').last()
        if tasks:
            times = tasks.task_starttime.split('/')
            backup = tasks.task_period.split(' ')
            backup = [backup[0], backup[1], backup[2], backup[3], backup[4], times[0], times[1]]
        else:
            backup = result_null

        log_backup = PlanTask.objects.filter(task_target='审计日志备份', execution='启用').last()
        if log_backup:
            times = log_backup.task_starttime.split('/')
            log_backup = log_backup.task_period.split(' ')
            log_backup = [log_backup[0], log_backup[1], log_backup[2], log_backup[3], log_backup[4], times[0], times[1]]
        else:
            log_backup = result_null

        logs_backup = PlanTask.objects.filter(task_target='访问日志备份', execution='启用').last()
        if log_backup:
            times = logs_backup.task_starttime.split('/')
            logs_backup = logs_backup.task_period.split(' ')
            logs_backup = [logs_backup[0], logs_backup[1], logs_backup[2], logs_backup[3], logs_backup[4], times[0], times[1]]
        else:
            logs_backup = result_null
        return [backup, log_backup, logs_backup]
    except:
        return [result_null, result_null, result_null]


f = open(TMP_PATH + '/' + "scheduler.lock", "wb")


def actions():
    get_times = get_time()
    scheduler = BackgroundScheduler()

    scheduler.add_job(run_backup, 'cron', month=get_times[0][3], week=get_times[0][4], day=get_times[0][2],
                      hour=get_times[0][1], minute=get_times[0][0], second=30,
                      start_date=get_times[0][5], end_date=get_times[0][6])
    scheduler.add_job(backup, 'cron', month=get_times[1][3], week=get_times[1][4], day=get_times[1][2],
                      hour=get_times[1][1], minute=get_times[1][0], second=30,
                      start_date=get_times[1][5], end_date=get_times[1][6])
    scheduler.add_job(log_backup, 'cron', month=get_times[2][3], week=get_times[2][4], day=get_times[2][2],
                      hour=get_times[2][1], minute=get_times[2][0], second=30,
                      start_date=get_times[2][5], end_date=get_times[2][6])
    scheduler.add_job(waflog_del, 'cron', day_of_week='5', hour=22, minute=50, second=10)
    scheduler.add_job(remove_files, 'cron', day_of_week='0-6', hour=23, minute=50, second=10)
    scheduler.add_job(host_info, 'interval', seconds=60)
    scheduler.add_job(creates, 'interval', seconds=60)
    scheduler.start()


try:
    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
except:
    pass
else:
    actions()


def unlock():
    fcntl.flock(f, fcntl.LOCK_UN)
    f.close()


atexit.register(unlock)
