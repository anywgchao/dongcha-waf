#!/usr/bin/env bash
#

function stop_dongcha-waf-agent() {
    echo -ne "dongcha-waf-agent    Stop \t........................ "
    docker stop dongcha-waf-agent >/dev/null 2>&1
    if [[ $? -ne 0 ]];then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function stop_dongcha-waf-manager() {
    echo -ne "dongcha-waf-manager    Stop \t........................ "
    docker stop dongcha-waf-manager >/dev/null 2>&1
    if [[ $? -ne 0 ]];then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function stop_dongcha-nginx() {
    echo -ne "dongcha-nginx    Stop \t........................ "
    docker stop dongcha-nginx >/dev/null 2>&1
    if [[ $? -ne 0 ]];then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function stop_dongcha-rsyslog() {
    echo -ne "dongcha-rsyslog    Stop \t........................ "
    docker stop dongcha-rsyslog >/dev/null 2>&1
    if [[ $? -ne 0 ]];then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function stop_dongcha-elk() {
    echo -ne "dongcha-elk  Stop \t........................ "
    docker stop dongcha-elk >/dev/null 2>&1
    if [[ $? -ne 0 ]];then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function stop_dongcha-mysql() {
    echo -ne "dongcha-mysql  Stop \t........................ "
    docker stop dongcha-mysql >/dev/null 2>&1
    if [[ $? -ne 0 ]];then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function stop_dongcha-waf() {
    echo -ne "dongcha-waf    Stop \t........................ "
    systemctl stop dongcha-waf
    if [[ $? -ne 0 ]];then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function main() {
    stop_dongcha-nginx
    stop_dongcha-waf-agent
    stop_dongcha-waf-manager
    stop_dongcha-waf
    stop_dongcha-rsyslog
    stop_dongcha-elk
    stop_dongcha-mysql
    echo ""
}

main
