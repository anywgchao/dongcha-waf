#!/usr/bin/env bash
#

BASE_DIR=$(dirname "$0")
source ${BASE_DIR}/config.conf

function prepare_install() {
    echo -ne "Installation system dependencies \t........................ "
    yum install -y libtool bzip2-devel ncurses-devel \
        readline-devel zip libxml2-devel libxslt-devel gd-devel
}

function start_nginx() {
    systemctl start dongcha-waf
    systemctl enable dongcha-waf
}

function config_nginx() {
    echo -ne "Installation tengine \t........................ "
    useradd -M -s /sbin/nologin dwaf
    cp ${BASE_DIR}/dongcha-waf.service /usr/lib/systemd/system/
}

function main() {
    prepare_install
    if [[ -f /data/semf/openresty/nginx/sbin/nginx ]]; then
        config_nginx
    fi

    if [[ ! "$(systemctl status dongcha-waf | grep Active | grep running)" ]]; then
        start_nginx
    fi
}

main
