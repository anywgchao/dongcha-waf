#!/usr/bin/env bash
#

BASE_DIR=$(dirname "$0")
source ${BASE_DIR}/config.conf

function message() {
    echo ""
    echo -e "dongcha-waf 部署完成"
    echo -ne "请到 $PROJECT_DIR 目录执行"
    echo -ne "\033[33m ./dcsctl start \033[0m"
    echo -e "启动 \n"
}

function prepare_install() {
    if [[ ! "$(rpm -qa | grep epel-release)" ]]; then
        yum install -y epel-release
    fi
    if grep -q 'mirror.centos.org' /etc/yum.repos.d/CentOS-Base.repo; then
        curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
        sed -i -e '/mirrors.cloud.aliyuncs.com/d' -e '/mirrors.aliyuncs.com/d' /etc/yum.repos.d/CentOS-Base.repo
        yum clean all
    fi
    if grep -q 'mirrors.fedoraproject.org' /etc/yum.repos.d/epel.repo; then
        curl -o /etc/yum.repos.d/epel.repo https://mirrors.aliyun.com/repo/epel-7.repo
        sed -i -e '/mirrors.cloud.aliyuncs.com/d' -e '/mirrors.aliyuncs.com/d' /etc/yum.repos.d/epel.repo
        yum clean all
    fi
}

function main() {
    bash ${BASE_DIR}/check_install_env.sh
    if [[ $? != 0 ]]; then
        exit 1
    fi
    prepare_install
    bash ${BASE_DIR}/install_docker.sh
    bash ${BASE_DIR}/install_core.sh
    if [[ $? != 0 ]]; then
        exit 1
    fi
    bash ${BASE_DIR}/install_tengine.sh
    message
}

main