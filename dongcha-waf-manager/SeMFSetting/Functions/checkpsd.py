# coding:utf-8

import re


def checkpsd(passwd):
    p = re.match(r'^(?=.*?\d)(?=.*?[a-zA-Z])(?=.*?[A-Z]).{8,32}$', passwd)
    if p:
        return True
    else:
        return False


def checkmail(apply_user):
    p = re.match(r'^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){0,4}@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){0,4}$', apply_user)
    if p:
        return True
    else:
        return False


def checkpone(apply_user):
    p = re.match(r'^1((3[\d])|(4[75])|(5[^3|4])|(66)|(7[013678])|(8[\d])|(9[89]))\d{8}$', apply_user)
    if p:
        return True
    else:
        return False


def phonelist(phone):
    list = phone[3:7]
    newphone = phone.replace(list, '****')
    return newphone


def emaillist(email):
    hide_mail_content = email.split('@')
    mail = hide_mail_content[0]
    if len(mail) < 5:
        mail = mail.replace(mail[1:], (len(mail) - 1) * '*')
    else:
        mail = mail.replace(mail[3:], (len(mail) - 3) * '*')
    result = mail + '@' + hide_mail_content[1]
    return result
