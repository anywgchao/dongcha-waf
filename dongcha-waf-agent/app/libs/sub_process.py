"""
@Author: Daboluo
@Date: 2018-12-13 11:36:13
@LastEditTime: 2020-02-26 10:31:32
@LastEditors: Do not edit
"""
# -*- coding: utf-8 -*-
from subprocess import Popen, PIPE


class SubProcess(object):
    """Running the process in a separate thread
       and outputting the stdout and stderr simultaneously.
       result dict with status and proc. status = 1 means process not completed.
       status = 0 means process completed successfully.
    """

    def __init__(self, cmd, shell=False):
        self.revoked = True
        self.cmd = cmd
        self.proc = None
        self.shell = shell

    def run(self):
        """

        :return:
        """
        self.proc = Popen(self.cmd, shell=self.shell, stdout=PIPE, stderr=PIPE)
        out, err = self.proc.communicate()
        result = {'proc': self.proc}
        return result
