#!/usr/bin/env bash
#

BASE_DIR=$(dirname "$0")
source ${BASE_DIR}/config.conf

flag=0

function check_docker() {
    echo -ne "docker.  Check \t........................ "
    if [[ ! "$(systemctl status docker | grep Active | grep running)" ]]; then
        echo -e "[\033[31m ERROR \033[0m]"
        flag=1
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function check_dongcha-waf() {
    echo -ne "dongcha-waf   Check \t........................ "
    if [[ ! "$(systemctl status dongcha-waf | grep Active | grep running)" ]]; then
        echo -e "[\033[31m ERROR \033[0m]"
        flag=1
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function check_dongcha-mysql() {
    echo -ne "dongcha-mysql    Check \t........................ "
    if [[ ! "$(docker ps | grep dongcha-mysql)" ]]; then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function check_dongcha-rsyslog() {
    echo -ne "dongcha-rsyslog    Check \t........................ "
    if [[ ! "$(docker ps | grep dongcha-rsyslog)" ]]; then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function check_dongcha-elk() {
    echo -ne "dongcha-elk    Check \t........................ "
    if [[ ! "$(docker ps | grep dongcha-elk)" ]]; then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function check_dongcha-waf-agent() {
    echo -ne "dongcha-waf-agent    Check \t........................ "
    if [[ ! "$(docker ps | grep dongcha-waf-agent)" ]]; then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function check_dongcha-waf-manager() {
    echo -ne "dongcha-waf-manager    Check \t........................ "
    if [[ ! "$(docker ps | grep dongcha-waf-manager)" ]]; then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function check_dongcha-nginx() {
    echo -ne "dongcha-nginx  Check \t........................ "
    if [[ ! "$(docker ps | grep dongcha-nginx)" ]]; then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function main() {
    check_docker
    check_dongcha-mysql
    check_dongcha-rsyslog
    check_dongcha-elk
    check_dongcha-waf-agent
    check_dongcha-waf-manager
    check_dongcha-nginx
    check_dongcha-waf

    if [[ ${flag} -eq 1 ]]; then
      echo -e "部分组件出现故障，请查阅上述检测结果[\033[31m ERROR \033[0m]"
      exit 1
    fi
}

main
