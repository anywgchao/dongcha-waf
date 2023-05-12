# -*- coding: utf-8 -*-

import wtforms_json
from wtforms import Form
from wtforms.fields import StringField, IntegerField, FieldList
from wtforms.validators import InputRequired, URL, Length, Optional, Regexp, UUID, NumberRange, AnyOf
wtforms_json.init()


class wafReload(Form):
    """WAF reload 校验"""
    ops_code = IntegerField('ops_code', validators=[
        InputRequired(),
        NumberRange(min=200, max=200, message='状态码不合法')
    ])


class viewLicense(Form):
    """WAF license 校验"""
    ops_code = IntegerField('ops_code', validators=[
        InputRequired(),
        NumberRange(min=200, max=200, message='状态码不合法')
    ])


class updateLicense(Form):
    """WAF license 校验"""
    waf_license = StringField('waf_license', validators=[
        InputRequired(),
        Length(4, 400, 'license信息不合法')
    ])


class updateNodeLabel(Form):
    """Node Label 校验"""
    node_label = StringField('node_label', validators=[
        InputRequired(),
        Length(1, 40, 'Label信息不合法')
    ])

    manager_address = StringField('manager_address', validators=[
        InputRequired(),
        URL('URL信息不合法')
    ])


class wafCertAdd(Form):
    """添加证书"""
    # UUID校验表单
    certificate_uuid = StringField('certificate_uuid', validators=[
        InputRequired(),
        UUID(message='certificate uuid')
    ])

    """
    # 证书文件
    certificate_pem = StringField('certificate_pem', validators=[
        Optional(),
        Length(1000, 5000, '域名长度不合法')
    ])

    # 证书私钥
    certificate_key = StringField('certificate_key', validators=[
        Optional(),
        Length(1000, 5000, '域名长度不合法')
    ])
    """


class wafCertDelete(Form):
    """删除证书"""
    # UUID校验表单
    certificate_uuid = StringField('site_uuid', validators=[
        InputRequired(),
        UUID(message='site uuid')
    ])


class WafAddSite(Form):
    """添加站点"""
    # 站点UUID校验-（必须值）
    site_uuid = StringField('site_uuid', validators=[
        InputRequired(),
        UUID(message='site uuid')
    ])

    # 域名校验 （必须值）
    domain_name = FieldList(
        StringField(
            'domain_name',
            validators=[
                InputRequired(),
                Regexp(
                    r"^([\w\-\*]{1,100}\.){1,8}([\w\-]{1,24}|[\w\-]{1,24}\.[\w\-]{1,24})$",
                    message='domain name')]))

    # 字符串校验 （必须值）
    protocol_type = FieldList(StringField('protocol_type', validators=[
        InputRequired(),
        AnyOf(values=['http', 'https'], message='protocol type')
    ]))

    # 证书UUID 校验 （非必须）
    certificate_uuid = StringField('certificate_uuid', validators=[
        Optional(),
        UUID(message='certificate uuid')
    ])

    # 上游URL （必须值）
    upstream_url = FieldList(
        StringField(
            'upstream_url',
            validators=[
                InputRequired(),
                Regexp(
                    r"(?:(?:[0,1]?\d?\d|2[0-4]\d|25[0-5])\.){3}(?:[0,1]?\d?\d|2[0-4]\d|25[0-5]):\d{0,5}",
                    message='upstream url')]))
    # 启用站点log （非必须值）
    site_logs = StringField('site_logs', validators=[
        InputRequired(),
        AnyOf(values=['on', 'off'], message='protocol type')
    ])

    # 启用站点缓存 （非必须值）
    proxy_cache = StringField('proxy_cache', validators=[
        InputRequired(),
        AnyOf(values=['on', 'off'], message='protocol type')
    ])

    # 站点缓存时间（非必须值）
    proxy_cache_time = IntegerField('proxy_cache_time', validators=[
        InputRequired(),
        NumberRange(min=1, max=7200, message='proxy cache time')
    ])


class WafDeleteSite(Form):
    """删除站点"""
    site_uuid = StringField('site_uuid', validators=[
        InputRequired(),
        UUID(message='site uuid')
    ])


class WafUpdateSite(Form):
    """更新站点"""
    # 站点UUID校验-（必须值）
    site_uuid = StringField('site_uuid', validators=[
        InputRequired(),
        UUID(message='site uuid')
    ])

    # 站点配置内容
    site_conf_data = StringField('site_conf_data', validators=[
        Optional(),
        Length(4, 8000, '站点配置文件内容不合法')
    ])
