# Dongcha-waf

🌍
*[English](/docs/README-en.md) ∙ [简体中文](README.md)*

基于`python3.6.5`和`Django2.0`的waf。

[![Build Status](https://api.travis-ci.org/liangliangyy/DjangoBlog.svg?branch=master)](https://git.frp.secyun.org:8443/chi.zhang/dongcha-waf-manager)[![Requirements Status](https://requires.io/github/liangliangyy/DjangoBlog/requirements.svg?branch=master)](https://git.frp.secyun.org:8443/chi.zhang/dongcha-waf-manager/src/master/requirements.txt)

## 项目介绍：
- 企业WAF安全规则设置。
- 企业WAF安全日志展示。
- 本平台旨在帮助WAF实现更简单的配置方式。


## 软件架构
- 后端系统 python3 + django2 实现。
- 前端显示 layui + bootstarp,使用开源模板 X-admin:http://x.xuebingsi.com/。

## 项目特点
- 分为5个项目模块,自定义规则,cc规则,WAF配置,模板配置,节点站点配置。
- 自定义规则与cc规则,根据业务自行配置相关规则,WAF模板则为拦截后展示页面。

## 项目部署
- 根据业务需求,修改SeMF目录下setting文件配置
- CREATE DATABASE `waf` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;
- grant all on waf.* to xxxxxx@'localhost' identified by 'xxxxxxx';

- python manage.py makemigrations
- python manage.py migrate   初始化数据库

- python manage.py createsuperuser   初始超级用户

- python initdata.py  用户菜单权限

- 根据自身业务修改 (网站跟地址 修改为配置项目地址)

- 详细配置请联系管理员