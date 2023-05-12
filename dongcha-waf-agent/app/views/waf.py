# -*- coding: utf-8 -*-
import os
import json
import base64
import shutil
from flask import Blueprint, jsonify, request
from app import utils
from app.auth import key_required
from app.libs.formauth.validate_waf import wafReload, wafCertAdd, wafCertDelete, WafAddSite, WafDeleteSite, \
    WafUpdateSite, viewLicense, updateLicense, updateNodeLabel
from app.tasks.waf_script import waf_script
from app.libs.sonLogs import logs
from app.libs.sites import Sites
from configs.settings import WAF_CERT, WAF_VHOST, WAF_RELOAD, WAF_CONF_CHECK, WAF_VHOST_BACK, OPENWAF_CONFIG
from OpenSSL import crypto
from dateutil import parser
from urllib.parse import urlparse, urljoin

import traceback

waf = Blueprint("waf", __name__, url_prefix="/waf/v1")


@waf.route("/reload", methods=["POST"])
@key_required
def waf_task_reload():
    """重加载WAF服务
        :return code
        200     正确返回
        400     request Body 非JSON
        550     表单验证失败
        554     WAF 重载失败
    """
    input_data = request.get_json(force=True)

    # 表单验证
    form = wafReload.from_json(input_data)
    if not form.validate():
        return jsonify(utils.all_return(550, form.errors, "表单验证错误"))

    # 输入200则重载服务
    if waf_script(WAF_RELOAD):
        return jsonify(utils.all_return(200, "", "重新加载成功"))
    else:
        return jsonify(utils.all_return(554, "重新加载失败"))


'''
@waf.route("/restart", methods=["POST"])
@key_required
def waf_task_restart():
    """重启WAF服务"""
    input_data = request.get_json(force=True)

    # 表单验证
    form = wafReload.from_json(input_data)
    if not form.validate():
        return jsonify(utils.all_return(form.errors, "jsonFrom Error"))

    # 输入200则重启服务
    if waf_script(WAF_RELOAD):
        return jsonify(utils.all_return(200, "", "Reload Success"))
    else:
        return jsonify(utils.all_return(551 "", "Reload Failure"))
'''


@waf.route("/cert/add", methods=["POST"])
@key_required
def waf_certificate_add():
    """添加证书 证书更新覆盖
        :return code
        200     正确返回
        400     request Body 非JSON
        550     表单验证失败
        551     pem证书错误
        552     key证书错误
        553     证书存储路径未找到
        554     添加证书失败
    """
    input_data = request.get_json(force=True)
    """
    {
        "certificate_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c02",
        "certificate_pem": "xxxxxx",
        "certificate_key": "xxxxxx",
    }
    """
    # 表单验证
    form = wafCertAdd.from_json(input_data)
    if not form.validate():
        return jsonify(utils.all_return(550, form.errors, "表单验证错误"))

    cert_uuid = form.certificate_uuid.data
    try:
        cert = crypto.load_certificate(
            crypto.FILETYPE_PEM,
            input_data.get("certificate_pem"))
        datetime_struct = parser.parse(cert.get_notAfter().decode("UTF-8"))
        certificate_exp_time = datetime_struct.strftime('%Y-%m-%d %H:%M:%S')
    except crypto.Error as e:
        logs.error("[!] Add Certificate_pem : %s." % e)
        return jsonify(utils.all_return(551, "", "pem证书格式错误"))

    try:
        crypto.load_privatekey(
            crypto.FILETYPE_PEM,
            input_data.get("certificate_key"))
    except crypto.Error as e:
        logs.error("[!] Add Certificate_key : %s." % e)
        return jsonify(utils.all_return(552, "", "key证书格式错误"))

    try:
        if os.path.isdir(WAF_CERT):
            cert_pem = os.path.join(WAF_CERT, cert_uuid + '.pem')
            cert_key = os.path.join(WAF_CERT, cert_uuid + '.key')
        else:
            return jsonify(
                utils.all_return(553, "", "证书存储路径未找到"))
        # 写入certificate文件
        with open(cert_pem, "w") as f:
            f.write(input_data.get("certificate_pem"))
        # 写入certificate_key文件
        with open(cert_key, "w") as f:
            f.write(input_data.get("certificate_key"))
        data = {
            "expiration_time": certificate_exp_time
        }
        return jsonify(utils.all_return(200, data, "添加证书成功"))
    except Exception as e:
        logs.error("[!] Add Certificate_pem : %s." % e)
        return jsonify(utils.all_return(554, "", "添加证书失败"))


@waf.route("/cert/delete", methods=["DELETE"])
@key_required
def waf_certificate_delete():
    """删除证书
        :return code
        200     正确返回
        400     request Body 非JSON
        550     表单验证失败
        554     证书删除失败
    """
    input_data = request.get_json(force=True)
    """
    {
        "certificate_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c02",
    }
    """
    # 表单验证
    form = wafCertDelete.from_json(input_data)
    if not form.validate():
        return jsonify(utils.all_return(550, form.errors, "表单验证错误"))

    cert_uuid = form.certificate_uuid.data
    try:
        cert_pem = os.path.join(WAF_CERT, cert_uuid + '.pem')
        cert_key = os.path.join(WAF_CERT, cert_uuid + '.key')

        # 删除certificate文件
        if os.path.isfile(cert_pem):
            os.remove(cert_pem)
        # 删除certificate_key文件
        if os.path.isfile(cert_key):
            os.remove(cert_key)
        return jsonify(utils.all_return(200, "", "删除证书成功"))
    except Exception as e:
        logs.error("[!] Delete Certificate_pem: %s." % e)
        return jsonify(utils.all_return(551, "", "删除证书失败"))


@waf.route("/site/add", methods=["POST"])
@key_required
def waf_site_add():
    """添加站点-更新站点则覆盖
        :return code
        200     正确返回
        550     表单验证失败
        551     新增站点配置后，无法重载服务
        552     站点域名存在重复
        553     站点存储路径未找到
        554     添加站点失败
        555     开启HTTPS，但是证书文件不存在
    """
    input_data = request.get_json(force=True)
    # 表单验证
    form = WafAddSite.from_json(input_data)
    if not form.validate():
        return jsonify(utils.all_return(550, form.errors, "表单验证错误"))
    """
        {
          "site_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c03",  //站点uuid
          "domain_name": [                                      // 域名列表
            "aaa.daboluo.me",
            "bbb.daboluo.me"
          ],
          "protocol_type": [                                    // 支持协议
            "http",
            "https"
          ],
          "certificate_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c02",   // 证书uuid
          "upstream_url": [                                                 // 上游URL
            "192.168.1.1",
            "192.168.1.1"
          ],
          "site_logs": "off",
          "proxy_cache": "on",                                          // 是否开启proxy
          "cache_time": 1                                               // 缓存时间，单位（分钟 1-720）
        }
    """
    site_uuid = form.site_uuid.data
    domain_name = form.domain_name.data
    protocol_type = form.protocol_type.data
    certificate_uuid = form.certificate_uuid.data
    upstream_url = form.upstream_url.data
    site_logs = form.site_logs.data
    proxy_cache = form.proxy_cache.data
    proxy_cache_time = form.proxy_cache_time.data

    try:
        # 载入sites 类
        wafsite = Sites(site_uuid,
                        domain_name,
                        protocol_type,
                        certificate_uuid,
                        upstream_url,
                        site_logs,
                        proxy_cache,
                        proxy_cache_time)
        result = wafsite.create_site()

        if result["status"] == 201:
            if waf_script(WAF_CONF_CHECK):
                # 成功后是否触发reload操作
                return jsonify(utils.all_return(200, "", "添加站点成功"))
            else:
                # nginx -t 遇到错误还原文件
                os.remove(os.path.join(WAF_VHOST, site_uuid + ".conf"))
                return jsonify(utils.all_return(551, "", "添加站点错误，还原配置"))
        else:
            return jsonify(result)
    except Exception as e:
        logs.error("[!] Add waf_site : %s." % e)
        os.remove(os.path.join(WAF_VHOST, site_uuid + ".conf"))
        return jsonify(utils.all_return(554, "", "添加站点失败"))


@waf.route("/site/delete", methods=["DELETE"])
@key_required
def waf_site_delete():
    """删除站点
        :return code
        200     正确返回
        550     表单验证失败
        551     删除站点后，无法重载服务
        554     删除站点失败
    """
    input_data = request.get_json(force=True)
    """
        {
          "site_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c03",  //站点uuid
        }
    """
    # 表单验证
    form = WafDeleteSite.from_json(input_data)
    if not form.validate():
        return jsonify(utils.all_return(550, form.errors, "表单验证错误"))

    site_uuid = form.site_uuid.data
    site_conf = os.path.join(WAF_VHOST, site_uuid + ".conf")

    try:
        # 删除waf站点文件
        if os.path.isfile(site_conf):
            os.remove(site_conf)

        if waf_script(WAF_CONF_CHECK):
            # 成功后是否触发reload操作
            return jsonify(utils.all_return(200, "", "删除站点成功"))
        else:
            return jsonify(utils.all_return(551, "", "删除站点后，无法重载服务"))
    except Exception as e:
        logs.error("[!] Delete waf_site: %s." % e)
        return jsonify(utils.all_return(554, "", "删除站点失败"))


@waf.route("/site/view", methods=["POST"])
@key_required
def waf_site_view():
    """查看站点-server.conf配置文件内容
        :return code
        200     正确返回
        550     表单验证失败
        551     站点文件不存在
        554     查看站点配置失败
    """
    input_data = request.get_json(force=True)
    """
        {
          "site_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c03",  //站点uuid
        }
    """
    # 表单验证
    form = WafDeleteSite.from_json(input_data)
    if not form.validate():
        return jsonify(utils.all_return(550, form.errors, "表单验证错误"))

    site_uuid = form.site_uuid.data
    site_conf = os.path.join(WAF_VHOST, site_uuid + ".conf")

    try:
        # 查看站点配置文件
        if os.path.isfile(site_conf):
            with open(site_conf, "r") as f:
                site_conf_data = f.read()
            data = {
                "site_uuid": site_uuid,
                "site_conf_data": site_conf_data
            }
            return jsonify(utils.all_return(200, data, "查看站点配置成功"))
        else:
            return jsonify(utils.all_return(551, "", "站点信息不存在"))
    except Exception as e:
        logs.error("[!] View waf_site : %s." % e)
        return jsonify(utils.all_return(554, "", "查看站点配置失败"))


@waf.route("/site/update", methods=["POST"])
@key_required
def waf_site_update():
    """server.conf配置文件内容，方式更新站点
        :return code
        200     正确返回
        550     表单验证失败
        551     站点文件不存在
        201     站点配置内容错误，还原回之前配置
        554     更新站点配置失败
    """
    input_data = request.get_json(force=True)
    """
        {
          "site_uuid": "5bb2d573-d9ff-4a28-b14b-5ab5ec855c03",  // 站点uuid
          "site_conf_data": "xxxxxxxx"                          // 站点原内容
        }
    """
    # 表单验证
    form = WafUpdateSite.from_json(input_data)
    if not form.validate():
        return jsonify(utils.all_return(550, form.errors, "表单验证错误"))

    site_uuid = form.site_uuid.data
    site_conf_data = form.site_conf_data.data
    site_conf = os.path.join(WAF_VHOST, site_uuid + ".conf")
    site_conf_bak = os.path.join(WAF_VHOST_BACK, site_uuid + ".conf")

    try:
        # 查看站点配置文件
        if os.path.isfile(site_conf):
            # 备份正常文件
            shutil.copy(site_conf, site_conf_bak)
            with open(site_conf, "w") as f:
                f.write(site_conf_data)

            if waf_script(WAF_CONF_CHECK):
                return jsonify(utils.all_return(200, "", "更新站点配置成功"))
            else:
                # nginx -t 遇到错误还原文件
                shutil.copy(site_conf_bak, site_conf)
                return jsonify(utils.all_return(201, "", "站点配置内容错误，还原回之前配置"))
        else:
            return jsonify(utils.all_return(551, "", "站点配置不存在"))
    except Exception as e:
        logs.error("[!] Add waf_site : %s." % e)
        return jsonify(utils.all_return(554, "", "更新站点配置失败"))


@waf.route("/license/view", methods=["POST"])
@key_required
def license_view():
    """查看license信息
        :return code
        200     正确返回
        550     表单验证失败
        551     license文件不存在
        554     查看license信息失败

        返回：
        {
          "license": "36720358b0248d1f78ebb231c3d749a3f87ae1e0ac994962a0a67310b676e6b6026bcc3983e2954362a00ac4c83336f6",
          "expiration_time": "2020-08-27 19:48:57"
          "node_version": "v1.1.2"
        }
    """
    input_data = request.get_json(force=True)

    # 表单验证
    form = viewLicense.from_json(input_data)
    if not form.validate():
        return jsonify(
            utils.all_return(550, form.errors, "表单验证错误"))

    try:
        # 查看站点配置文件
        if os.path.isfile(OPENWAF_CONFIG):
            with open(OPENWAF_CONFIG) as f:
                conf_data = json.load(f)
            waf_license = conf_data.get("waf_license")
            waf_version = conf_data.get("waf_version")
            results = base64.b64decode(waf_license).decode('ascii').split('#')
            data = {
                "license": results[0],
                "expiration_time": results[1],
                "waf_version": waf_version
            }
            return jsonify(utils.all_return(200, data, "查看license信息成功"))
        else:
            return jsonify(utils.all_return(551, "", "license文件不存在"))
    except Exception as e:
        logs.error("[!] View License Error: %s.", traceback.print_exc())
        return jsonify(utils.all_return(554, "", "查看license信息失败"))


@waf.route("/license/update", methods=["POST"])
@key_required
def license_update():
    """查看license信息
        :return code
        200     正确返回
        550     表单验证失败
        551     license文件不存在
        554     查看license信息失败
        {
          "license": "MzY3MjAzNThiMDI0OGQxZjc4ZWJiMjMxYzNkNzQ5YTNmODdhZTFlMGFjOTk0OTYyYTBhNjczMTBiNjc2ZTZiNjAyNmJjYzM5ODNlMjk1NDM2MmEwMGFjNGM4MzMzNmY2IzIwMjAtMDgtMjcgMTk6NDg6NTc=",
        }
    """
    input_data = request.get_json(force=True)

    # 表单验证
    form = updateLicense.from_json(input_data)
    if not form.validate():
        return jsonify(utils.all_return(550, form.errors, "表单验证失败"))

    waf_license = form.waf_license.data
    try:
        # 查看站点配置文件
        if os.path.isfile(OPENWAF_CONFIG):
            with open(OPENWAF_CONFIG) as f:
                conf_data = json.load(f)
            conf_data['waf_license'] = waf_license
            with open(OPENWAF_CONFIG, 'w') as f:
                json.dump(conf_data, f, indent=4)

            # 返回最新license信息
            waf_version = conf_data.get("waf_version")
            results = base64.b64decode(waf_license).decode('ascii').split('#')
            data = {
                "license": results[0],
                "expiration_time": results[1],
                "waf_version": waf_version
            }

            return jsonify(utils.all_return(200, data, "License更新成功"))
        else:
            return jsonify(utils.all_return(551, "", "License文件不存在"))
    except Exception as e:
        logs.error("[!] Update License Error: %s.", traceback.print_exc())
        return jsonify(utils.all_return(554, "", "License更新错误"))


@waf.route("/nodelabel/update", methods=["POST"])
@key_required
def nodelabel_update():
    """更新node label
        :return code
        200     正确返回
        550     表单验证失败
        551     节点配置文件不存在
        554     更新节点配置错误
        {
          "node_label": "daboluo",
        }
    """
    input_data = request.get_json(force=True)

    # 表单验证
    form = updateNodeLabel.from_json(input_data)
    if not form.validate():
        return jsonify(utils.all_return(550, form.errors, "表单验证失败"))

    try:
        node_label = form.node_label.data
        manager_address = form.manager_address.data
        parts = urlparse(manager_address)
        manager_address = parts.scheme + '://' + parts.netloc

        # 查看站点配置文件
        if os.path.isfile(OPENWAF_CONFIG):
            with open(OPENWAF_CONFIG) as f:
                conf_data = json.load(f)
            conf_data['waf_platform_tag'] = node_label
            conf_data['base_rule_update_website'] = manager_address.strip('/') + '/view/security_rules'
            conf_data['global_rule_update_website'] = manager_address.strip('/') + '/view/global_config'

            with open(OPENWAF_CONFIG, 'w') as f:
                json.dump(conf_data, f, indent=4)

            return jsonify(utils.all_return(200, "", "更新节点配置成功"))
        else:
            return jsonify(utils.all_return(551, "", "节点配置文件不存在"))
    except Exception as e:
        logs.error("[!] Update NodeLabel Error: %s.", traceback.print_exc())
        return jsonify(utils.all_return(554, "", "更新节点配置错误"))
