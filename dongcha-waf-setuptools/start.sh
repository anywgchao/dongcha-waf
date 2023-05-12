#!/usr/bin/env bash
#

BASE_DIR=$(dirname "$0")
source ${BASE_DIR}/config.conf

function success() {
    echo ""
    echo -e "dongcha-waf 启动成功! "
    echo -ne "Web 登陆信息: "
    echo -e "\033[32mhttps://$Server_IP:$https_port\033[0m"
    echo -ne "初始用户名密码: "
    echo -e "\033[32madmin 123324aa \033[0m\n"
    echo -e "\033[33m[如果你是云服务器请在安全组放行 $https_port 端口] \n\033[0m"
}

function start_docker() {
    echo -ne "Docker.  Start \t........................ "
    if [[ ! "$(systemctl status docker | grep Active | grep running)" ]]; then
        systemctl start docker
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function start_dongcha-rsyslog() {
    echo -ne "dongcha-rsyslog.   start \t........................ "
    if [[ ! "$(docker ps | grep dongcha-rsyslog)" ]]; then
        docker start dongcha-rsyslog
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function start_dongcha-elk() {
    echo -ne "dongcha-elk   Start \t........................ "
    if [[ ! "$(docker ps | grep dongcha-elk)" ]]; then
        docker start dongcha-elk
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}


function start_dongcha-mysql() {
    echo -ne "dongcha-mysql    Start \t........................ "
    if [[ ! "$(docker ps | grep dongcha-mysql)" ]]; then
        docker start dongcha-mysql
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function start_dongcha-waf-agent() {
    echo -ne "dongcha-waf-agent.    Start \t........................ "
    if [[ ! "$(docker ps | grep dongcha-waf-agent)" ]]; then
        docker start dongcha-waf-agent
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function start_dongcha-waf-manager() {
    echo -ne "dongcha-waf-manager.  Start \t........................ "
    if [[ ! "$(docker ps | grep dongcha-waf-manager)" ]]; then
        docker start dongcha-waf-manager
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function start_dongcha-nginx() {
    echo -ne "dongcha-nginx.  Start \t........................ "
    if [[ ! "$(docker ps | grep dongcha-nginx)" ]]; then
        docker start dongcha-nginx
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function start_dongcha-waf() {
    echo -ne "dongcha-waf    Start \t........................ "
    if [[ ! "$(systemctl status dongcha-waf | grep Active | grep running)" ]]; then
        systemctl start dongcha-waf
        if [[ $? -ne 0 ]];then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function main() {
    start_docker
    start_dongcha-mysql
    start_dongcha-rsyslog
    start_dongcha-elk
    start_dongcha-waf-agent
    start_dongcha-waf-manager
    start_dongcha-nginx
    start_dongcha-waf

    echo ""
    bash ${BASE_DIR}/install_status.sh
    if [[ $? != 0 ]]; then
        exit 1
    fi
    success
}

main
