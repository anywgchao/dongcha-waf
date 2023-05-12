"""
@Author: Daboluo
@Date: 2019-06-20 19:20:32
@LastEditTime: 2020-03-17 18:53:23
@LastEditors: Do not edit
"""
# -*- coding:utf-8 -*-

import logging
import logging.handlers

from configs.settings import APP_LOGS, BACKUP_COUNT, MAX_BYTES


class Logger:
    """日志记录方法"""

    def __init__(self):
        self.logger = logging.getLogger('syslog')
        hdlr = logging.handlers.RotatingFileHandler(
            APP_LOGS, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT)
        formatter = logging.Formatter(
            '[%(asctime)s] - [%(levelname)s] - %(message)s')
        hdlr.setFormatter(formatter)
        self.logger.addHandler(hdlr)
        self.logger.setLevel(logging.INFO)
        # self.logger.removeHandler(hdlr)

        '''
        ##    日志记录等级
        ##    级别    对应的值
        ##    CRITICAL  50
        ##    ERROR     40
        ##    WARNING   30
        ##    INFO      20
        ##    DEBUG     10
        ##    NOTSET    0
        ##    低于该级别的日志消息将会被忽略， NOTSET相当于全部信息记录。
        '''

    def debug(self, msg):
        self.logger.debug(msg)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)

    def critical(self, msg):
        self.logger.critical(msg)


logs = Logger()
