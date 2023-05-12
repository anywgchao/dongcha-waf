#!/usr/bin/env bash
#

BASE_DIR=$(dirname "$0")
source ${BASE_DIR}/config.conf

function all_uninstall() {
    echo -e "\033[33m 开始卸载 tengine \n\033[0m"
    if [[ "$(systemctl status dongcha-waf | grep Active | grep running)" ]]; then
        systemctl stop dongcha-waf
    fi
    rm -f /etc/systemd/system/dongcha-waf.service
    userdel dwaf

    echo -e "\033[33m 开始卸载容器镜像 \n\033[0m"
    if [[ "$(systemctl status docker | grep Active | grep running)" ]]; then
        echo -e "Docker.  Delete network \t........................ "
        docker network rm ${docker_network_name}

        echo -e "Docker.  Stop APP \t........................ "
        docker stop dongcha-nginx dongcha-waf-manager dongcha-waf-agent dongcha-rsyslog dongcha-elk dongcha-mysql

        echo -e "Docker.  Delete APP \t........................ "
        docker rm dongcha-nginx dongcha-waf-manager dongcha-waf-agent dongcha-rsyslog dongcha-elk dongcha-mysql

        echo -e "Docker.  Delete image \t........................ "
        docker rmi dongcha-mysql:5.7 dongcha-rsyslog:8.36.0-3.7 dongcha-elk:v1.0 dongcha-nginx:1.18.0 dongcha-waf-manager:v1.0 dongcha-waf-agent:v1.0

        echo -e "Stop Docker.  \t........................ "
        systemctl stop docker
        systemctl stop docker.socket
    fi

    echo -e "\033[33m 开始删除原始文件 \n\033[0m"
    rm -rf ${install_dir}/semf

    echo -e "\033[31m 已经成功清理 dongcha-waf 相关文件 \033[0m"
    echo -e "\033[31m 请自行卸载 docker 服务 \033[0m"
    echo -e "\033[31m yum remove -y docker-ce docker-ce-cli \033[0m"
    echo -e "\033[31m 卸载完成后请重启服务器 \033[0m"
}

function main() {
    echo -e "\033[31m 准备从系统中卸载 dongcha-waf \033[0m"
    read -n1 -p "Do you want to continue [Y/N]?" answer
    echo -e "\n"
    case ${answer} in
    Y | y)
        bash ${BASE_DIR}/stop.sh
        all_uninstall
        ;;
    N | n)
        echo "ok,good bye"
        ;;
    *)
        echo "error 重新选择"
        ;;
    esac
    exit 0
}

main
