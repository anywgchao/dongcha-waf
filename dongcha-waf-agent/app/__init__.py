"""
@Author: Daboluo
@Date: 2018-12-19 15:38:52
@LastEditTime: 2020-03-18 11:56:22
@LastEditors: Do not edit
"""
# -*- coding: utf-8 -*-
import sys
from flask import Flask
from configs import settings
from app.libs.sonLogs import logs
# from flask_wtf import CSRFProtect
import atexit
import fcntl
from flask_apscheduler import APScheduler
from configs.settings import APP_SCHEDULER_LOCK
import traceback
from apscheduler.schedulers.background import BackgroundScheduler


def configure_blueprints(app):
    """在视图中配置的蓝图"""
    from app.views import default_blueprints
    blueprints = default_blueprints
    if blueprints:
        for blueprint in blueprints:
            # csrf.exempt(blueprint)
            app.register_blueprint(blueprint)


# 加载配置
try:
    app = Flask(__name__)
    app.config.from_object(settings)
    # csrf = CSRFProtect(app)
except Exception as e:
    logs.error('[!] Load the configuration Err: {}'.format(e))
    sys.exit()


def register_scheduler():
    """
    注册定时任务
    """
    f = open(APP_SCHEDULER_LOCK, "wb")
    # noinspection PyBroadException
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except:
        pass
    else:
        # 启动计划任务
        scheduler = APScheduler()
        scheduler.init_app(app)
        scheduler.start()

    def unlock():
        """解锁"""
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()

    atexit.register(unlock)


def create_app():
    """加载蓝图路由"""
    try:
        # 启用蓝图结构化
        configure_blueprints(app)
    except Exception as e:
        logs.error('[!] startServer blueprints Err: {}'.format(e))
        sys.exit()

    register_scheduler()

    # 返回app实例，让外部模块继续使用
    return app
