#!/usr/bin/env bash
#

BASE_DIR=$(dirname "$0")
source ${BASE_DIR}/config.conf

function prepare_install() {
    yum install -y yum-utils device-mapper-persistent-data lvm2
}

function install_docker() {
    echo ">> Install Docker"
    prepare_install
    yum-config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
    #rpm --import https://mirrors.aliyun.com/docker-ce/linux/centos/gpg
    curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
    yum install -y docker-ce
}

function config_docker {
    mkdir -p /etc/docker/
    cp $BASE_DIR/docker/daemon.json /etc/docker/daemon.json
}

function start_docker {
    systemctl start docker
    systemctl enable docker
}

function create_docker_network {
    echo -ne "Docker.  Create network \t........................ "
    if [[ ! "$(docker network ls |grep ${docker_network_name})" ]]; then
        docker network create --subnet=${docker_network}.0/24 ${docker_network_name}
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function main {
    which docker >/dev/null 2>&1
    if [[ $? -ne 0 ]];then
        install_docker
    fi
    if [[ ! -f "/etc/docker/daemon.json" ]]; then
        config_docker
    fi
    if [[ ! "$(systemctl status docker | grep Active | grep running)" ]]; then
        start_docker
        create_docker_network
    fi
}

main
