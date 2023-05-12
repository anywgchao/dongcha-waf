# -*- coding: utf-8 -*-
import app
from flask import Blueprint, request, send_from_directory, render_template, abort
prefix = Blueprint('prefix', __name__, url_prefix='')


@prefix.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, request.path[1:], mimetype='image/vnd.microsoft.icon')


@prefix.route('/', methods=['GET'])
def home():
    return render_template('index.html')


@prefix.route('/robots.txt')
def robots():
    """搜索引擎爬虫协议"""
    return send_from_directory(app.static_folder, request.path[1:])


@prefix.errorhandler(404)
def page_not_found():
    return render_template('404.html'), 404


@prefix.errorhandler(Exception)
def unhandled_exception(error):
    return render_template('500.html'), 500
