"""
@Author: Daboluo
@Date: 2018-12-24 19:49:04
@LastEditTime: 2020-08-03 22:02:15
@LastEditors: Do not edit
"""
# -*- coding: utf-8 -*-

import os
import signal
import psutil

from app.libs.sub_process import SubProcess
from app.libs.sonLogs import logs


def kill_child_processes(parent_pid, sig=signal.SIGTERM):
    """
    :param parent_pid: 子进程ID
    :param sig: 信号指示
    :return:
    """
    try:
        p = psutil.Process(parent_pid)
    except psutil.NoSuchProcess:
        return
    child_pid = p.children(recursive=True)
    for pid in child_pid:
        os.kill(pid.pid, sig)


def waf_script(waf_ops):
    """
    :param waf_ops: WAF 命令执行
    :return:
    """
    manager_process = SubProcess(waf_ops).run()

    if manager_process["proc"].returncode == 0:
        return True
    else:
        logs.info(
            "nginx: configuration file nginx.conf test failed exit code: {}".format(
                manager_process["proc"].returncode))
        return False
    # if manager_process["status"] == 1:
        # process = manager_process["proc"]
        # logs.info("process {} is timeout,terminating.".format(process.pid))

        # 任务超时结束任务
        # kill_child_processes(process.pid)
        # process.kill()
        # process.wait()
        # return False
