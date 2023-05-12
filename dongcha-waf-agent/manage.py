"""
@Author: Daboluo
@Date: 2019-04-09 14:46:41
@LastEditTime: 2020-08-03 21:55:56
@LastEditors: Do not edit
"""
# -*- coding: utf8 -*-

import os
from flask_script import Manager, Server
from app import create_app
from configs.settings import HOST, PORT
app = create_app()
# 创建命令行管理
manager = Manager(app, with_default_commands=True)
manager.add_command("runserver", Server(
    host=HOST, port=PORT))


# 添加测试命令
@manager.command
def test():
    """Run the unit tests."""
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)


@manager.command
def update():
    # 自动更新需求库
    print('output requirements file.....')
    os.system('pip freeze > requirements.txt')


# 添加自动生成生产环境配置命令
@manager.command
def config():
    """根据配置自动生成 生产环境配置，只支持nginx uwsgi"""
    if not os.path.exists('logs'):
        os.mkdir('logs')
    """
    # 利用bash命令删除所有的xml 和 conf文件，这些就是nginx和uwsgi的配置文件
    os.system('rm *-nginx.conf')
    os.system('rm *-uwsgi.xml')
    # 执行数据迁移和更新
    os.system('python manage.py db migrate')
    os.system('python manage.py db upgrade')
    """


# 启动主进程
if __name__ == '__main__':
    manager.run()
