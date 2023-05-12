"""
@Author: Daboluo
@Date: 2019-06-24 20:05:38
@LastEditTime: 2020-02-26 15:14:48
@LastEditors: Do not edit
"""
# -*- coding:utf-8 -*-
import os
import re
from app import utils
from app.libs.sonLogs import logs
from configs.settings import WAF_VHOST, TEMPLATE_FOLDER, WAF_CERT, P_WAF_CERT, WAF_SITE_LOGS

class Sites:
    """
        WAF站点配置生成方法
    """

    def __init__(
            self,
            site_uuid,
            domain_name,
            protocol_type,
            certificate_uuid,
            upstream_url,
            site_logs,
            proxy_cache,
            proxy_cache_time):
        self.site_uuid = site_uuid
        self.domain_name = domain_name
        self.protocol_type = protocol_type
        self.certificate_uuid = certificate_uuid
        self.upstream_url = upstream_url
        self.site_logs = site_logs
        self.proxy_cache = proxy_cache
        self.proxy_cache_time = proxy_cache_time

    # 添加网站
    def create_site(self):
        """
        :type protocol_type: object
        """
        if os.path.isdir(WAF_VHOST):
            if self.domain_exists():
                return utils.all_return(552, "", "站点域名存在重复")
        else:
            return utils.all_return(553, "", "站点存储路径未找到")

        # 写入站点conf文件
        try:
            site_conf = os.path.join(WAF_VHOST, self.site_uuid + ".conf")
            generate_conf = self.generate_conf()
            if isinstance(generate_conf, dict):
                if generate_conf["status"] == 201:
                    with open(site_conf, "w") as f:
                        f.write(generate_conf["data"])
                    return utils.all_return(201, "", "Site added successfully")
                else:
                    return utils.all_return(generate_conf["status"], generate_conf["data"], generate_conf["msg"])
        except Exception as e:
            logs.error("[!] Write Site Config : %s." % e)

    # 检查指定域名是否存在
    def domain_exists(self):
        """
        :param domains:
        :return:
        """
        for domain in self.domain_name:
            for root, dirs, files in os.walk(WAF_VHOST):
                for file in files:
                    if file != self.site_uuid + ".conf":
                        f = open(os.path.join(root, file), 'rU')
                        f_content = f.read()
                        f.close()
                        if re.search(domain, f_content, re.M | re.I):
                            return True
        return False

    # 生成配置文件
    def generate_conf(self):
        """
        :return:
        """
        # -----------------------------------------------
        upstream_tpl = os.path.join(TEMPLATE_FOLDER, 'upstream.tpl')
        _upstream_tmp = ""
        if os.path.isfile(upstream_tpl):
            with open(upstream_tpl, 'r') as f:
                _upstream_body = f.read()
                _upstream_body = _upstream_body.replace(
                    "<UPSTREAM_TAG>", self.site_uuid)

            for url in self.upstream_url:
                _upstream_tmp += "        server {} max_fails=3 fail_timeout=60 weight=1;\n".format(
                    url)

            _upstream_body = _upstream_body.replace("<SERVERS>", _upstream_tmp)

        logs_tpl = os.path.join(TEMPLATE_FOLDER, 'logs.tpl')
        _site_logs_body = ""
        if self.site_logs == "on":
            if os.path.isfile(logs_tpl):
                with open(logs_tpl, 'r') as f:
                    _site_logs_body = f.read()
                    _site_logs_body = _site_logs_body.replace(
                        "<SITE_LOGS>", os.path.dirname(WAF_SITE_LOGS))
                    _site_logs_body = _site_logs_body.replace(
                        "<SITE_UUID>", str(self.site_uuid))

        # -----------------------------------------------
        proxy_tpl = os.path.join(TEMPLATE_FOLDER, 'proxy.tpl')
        proxy_cache_off_tpl = os.path.join(
            TEMPLATE_FOLDER, 'proxy_cache_off.tpl')
        proxy_cache_on_tpl = os.path.join(
            TEMPLATE_FOLDER, 'proxy_cache_on.tpl')

        if self.proxy_cache == "on":
            if os.path.isfile(proxy_cache_on_tpl):
                with open(proxy_cache_on_tpl, 'r') as f:
                    _proxy_cache_body = f.read()
                    _proxy_cache_body = _proxy_cache_body.replace(
                        "<PROXY_CACHE_TIME>", str(self.proxy_cache_time))
        elif self.proxy_cache == "off":
            if os.path.isfile(proxy_cache_off_tpl):
                with open(proxy_cache_off_tpl, 'r') as f:
                    _proxy_cache_body = f.read()

        if os.path.isfile(proxy_tpl):
            with open(proxy_tpl, 'r') as f:
                _proxy_body = f.read()
                _proxy_body = _proxy_body.replace(
                    "<PROXY_TAG>", "http://{}".format(self.site_uuid))

        # -----------------------------------------------
        _domain_body = ' '.join(self.domain_name)
        # -----------------------------------------------
        if "https" in self.protocol_type:
            ssl_tpl = os.path.join(TEMPLATE_FOLDER, 'ssl.tpl')
            cert_pem = os.path.join(WAF_CERT, self.certificate_uuid + ".pem")
            cert_key = os.path.join(WAF_CERT, self.certificate_uuid + ".key")

            if os.path.isfile(ssl_tpl) and os.path.isfile(
                    cert_pem) and os.path.isfile(cert_key):
                with open(ssl_tpl, 'r') as f:
                    _ssl_body = f.read()
                    _ssl_body = _ssl_body.replace(
                        "<SSL_CERT_PEM>", os.path.join(
                            P_WAF_CERT, self.certificate_uuid + ".pem"))
                    _ssl_body = _ssl_body.replace(
                        "<SSL_CERT_KEY>", os.path.join(
                            P_WAF_CERT, self.certificate_uuid + ".key"))
            else:
                return utils.all_return(555, "", "SSL_CERT_PEM Not Found")

            # -----------------------------------------------
            https_tpl = os.path.join(TEMPLATE_FOLDER, 'https.tpl')
            if os.path.isfile(https_tpl):
                with open(https_tpl, 'r') as f:
                    _https_body = f.read()

            #  是否开启日志记录
            _https_body = _https_body.replace("<HTTP_LOGS>", _site_logs_body)

            # 替换<UPSTREAM_SERVER>
            _https_body = _https_body.replace("<UPSTREAM_SERVER>", _upstream_body)

            # <HTTPS_SSL>
            _https_body = _https_body.replace("<HTTPS_SSL>", _ssl_body)

            # 替换 <DOMAIN_NAMES>
            _https_body = _https_body.replace("<DOMAIN_NAMES>", _domain_body)

            # 替换 <SITE_UUID>
            _https_body = _https_body.replace("<SITE_UUID>", self.site_uuid)

            # 替换 <PROXY>
            _https_body = _https_body.replace("<PROXY>", _proxy_body)

            # 替换 <PROXY_CACHE>
            _https_body = _https_body.replace("<PROXY_CACHE>", _proxy_cache_body)

            # 最终body内容
            http_body = _https_body

        else:
            http_tpl = os.path.join(TEMPLATE_FOLDER, 'http.tpl')
            if os.path.isfile(http_tpl):
                with open(http_tpl, 'r') as f:
                    _http_body = f.read()

            #  是否开启日志记录
            _http_body = _http_body.replace("<HTTP_LOGS>", _site_logs_body)

            # 替换<UPSTREAM_SERVER>
            _http_body = _http_body.replace("<UPSTREAM_SERVER>", _upstream_body)

            # 替换 <DOMAIN_NAMES>
            _http_body = _http_body.replace("<DOMAIN_NAMES>", _domain_body)

            # 替换 <SITE_UUID>
            _http_body = _http_body.replace("<SITE_UUID>", self.site_uuid)

            # 替换 <PROXY>
            _http_body = _http_body.replace("<PROXY>", _proxy_body)

            # 替换 <PROXY_CACHE>
            _http_body = _http_body.replace("<PROXY_CACHE>", _proxy_cache_body)

            # 最终body内容
            http_body = _http_body

        return utils.all_return(201, http_body, "Site added successfully")
