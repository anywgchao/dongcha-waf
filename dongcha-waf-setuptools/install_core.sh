#!/usr/bin/env bash
#

BASE_DIR=$(dirname "$0")
TAR_DIR=$(dirname ${BASE_DIR})/tar
source ${BASE_DIR}/config.conf

function set_sellinux() {
    echo -e "Selinux    Well be close \t........................ "
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config && setenforce 0
}

function set_firewall() {
    #firewall-cmd --permanent --add-rich-rule="rule family="ipv4" source address="$Docker_IP" port protocol="tcp" port="8080" accept"
    #firewall-cmd --permanent  --add-port=8838/tcp
    #firewall-cmd --reload
    echo -e "Firewalld    Well be close \t........................ "
    systemctl stop firewalld
    systemctl disable firewalld
}

function install_core() {
    echo -e "mkdir    Work path \t........................ "
    mkdir -p ${install_dir} && tar xf ${TAR_DIR}/semf.tar.gz -C ${install_dir}
}

function load_dongcha-waf-agent() {
    echo -ne "dongcha-waf-agent    Load images \t........................ "
    if [[ ! "$(docker images | grep dongcha-waf-agent)" ]]; then
        docker image load <${TAR_DIR}/dongcha-waf-agent-v1.0.tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function load_dongcha-waf-manager() {
    echo -ne "dongcha-waf-manager    Load images \t........................ "
    if [[ ! "$(docker images | grep dongcha-waf-manager)" ]]; then
        docker image load <${TAR_DIR}/dongcha-waf-manager-v1.0.tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function load_dongcha-rsyslog() {
    echo -ne "dongcha-rsyslog    Load images \t........................ "
    if [[ ! "$(docker images | grep dongcha-rsyslog)" ]]; then
        docker image load <${TAR_DIR}/dongcha-rsyslog-8.36.0-3.7.tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function load_dongcha-elk() {
    echo -ne "dongcha-elk    Load images \t........................ "
    if [[ ! "$(docker images | grep dongcha-elk)" ]]; then
        docker image load <${TAR_DIR}/dongcha-elk-v1.0.tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function load_dongcha-nginx() {
    echo -ne "dongcha-nginx    Load images \t........................ "
    if [[ ! "$(docker images | grep dongcha-nginx)" ]]; then
        docker image load <${TAR_DIR}/dongcha-nginx-1.18.0.tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function load_dongcha-mysql() {
    echo -ne "dongcha-mysql    Load images \t........................ "
    if [[ ! "$(docker images | grep dongcha-mysql)" ]]; then
        docker image load <${TAR_DIR}/dongcha-mysql-5.7.tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function init_dongcha-mysql() {
    echo -ne "dongcha-mysql    First Run images \t........................ "
    if [[ ! "$(docker ps | grep dongcha-mysql)" ]]; then
        docker run -itd --restart=always \
            -v /data/semf/mysql/data:/var/lib/mysql \
            -v /data/semf/mysql/my.cnf:/etc/mysql/mysql.conf \
            -v /data/semf/mysql/logs:/logs \
            -v /etc/localtime:/etc/localtime \
            --net ${docker_network_name} \
            --ip ${docker_network}.5 \
            -e MYSQL_ALLOW_EMPTY_PASSWORD="no" \
            -e MYSQL_ROOT_PASSWORD="jjyy123" \
            -h dongcha-mysql --name dongcha-mysql \
            dongcha-mysql:5.7

        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function init_dongcha-elk() {
    echo -ne "dongcha-elk    First Run images \t........................ "
    if [[ ! "$(docker ps | grep dongcha-elk)" ]]; then
        docker run -itd --restart=always \
            --name dongcha-elk -h dongcha-elk \
            --net ${docker_network_name} \
            --ip ${docker_network}.6 \
            -v /etc/localtime:/etc/localtime \
            -v /data/semf/elk/gohangout:/opt/gohangout \
            dongcha-elk:v1.0
            # -v /data/semf/elk/10-syslog.conf:/etc/logstash/conf.d/10-syslog.conf \

        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function init_dongcha-rsyslog() {
    echo -ne "dongcha-rsyslog    First Run images \t........................ "
    if [[ ! "$(docker ps | grep dongcha-rsyslog)" ]]; then
        docker run -itd --restart=always \
            --name dongcha-rsyslog -h dongcha-rsyslog \
            --net ${docker_network_name} \
            --ip ${docker_network}.10 \
            -v /etc/localtime:/etc/localtime \
            -v /data/semf/config/rsyslog.conf:/etc/rsyslog.conf \
            -v /data/semf/config/rsyslog.d:/etc/rsyslog.d \
            dongcha-rsyslog:8.36.0-3.7

        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function init_dongcha-nginx() {
    echo -ne "dongcha-nginx    First Run images \t........................ "
    if [[ ! "$(docker ps | grep dongcha-nginx)" ]]; then
        docker run -itd --restart=always \
            --name dongcha-nginx -h dongcha-nginx \
            --net ${docker_network_name} \
            --ip ${docker_network}.7 \
            -p 8838:443 \
            -v /etc/localtime:/etc/localtime \
            -v /data/semf/config/nginx/nginx.conf:/etc/nginx/nginx.conf \
            -v /data/semf/config/nginx/ssl:/etc/nginx/ssl \
            -v /data/semf/dongcha-waf-manager/static:/app/static \
            -v /data/semf/logs/nginx:/var/log/nginx \
            dongcha-nginx:1.18.0

        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function init_dongcha-waf-manager() {
    echo -ne "dongcha-waf-manager    First Run images \t........................ "
    if [[ ! "$(docker ps | grep dongcha-waf-manager)" ]]; then
        docker run -itd --restart=always \
            --name dongcha-waf-manager -h dongcha-waf-manager \
            --net ${docker_network_name} \
            --ip ${docker_network}.12 \
            -v /etc/localtime:/etc/localtime \
            -v /data/semf/dongcha-waf-manager:/app \
            dongcha-waf-manager:v1.0

        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function add_agent_authorized() {
    if [[ ! -d "~/.ssh" ]]; then
        mkdir ~/.ssh && chmod 700 ~/.ssh
    fi

    authorized_check=$(grep -i "dongcha-waf-agent" ~/.ssh/authorized_keys)
    if [[ ! "$authorized_check" ]]; then
      cat ${TAR_DIR}/cert/id_rsa.pub >> ~/.ssh/authorized_keys
	    chmod 600 ~/.ssh/authorized_keys
    fi
    docker cp ${TAR_DIR}/cert/id_rsa dongcha-waf-agent:/root/.ssh/id_rsa
    docker cp ${TAR_DIR}/cert/id_rsa.pub dongcha-waf-agent:/root/.ssh/id_rsa.pub
}

function init_dongcha-waf-agent() {
    echo -ne "dongcha-waf-agent    First Run images \t........................ "
    if [[ ! "$(docker ps | grep dongcha-waf-agent)" ]]; then
        docker run -itd --restart=always \
            --name dongcha-waf-agent -h dongcha-waf-agent \
            --net ${docker_network_name} \
            --ip ${docker_network}.13 \
            -p 8839:8839 \
            -v /etc/localtime:/etc/localtime \
            -v /data/semf/dongcha-waf-agent:/app \
            -v /data/semf/config/openresty:/etc/nginx \
            dongcha-waf-agent:v1.0

        if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
        # add authorized_keys to dongcha-waf-agent
        add_agent_authorized
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function init_mysql_data() {
    docker cp ${TAR_DIR}/dongcha_waf.sql dongcha-mysql:/tmp/
    docker exec -it dongcha-mysql /bin/bash -c 'export MYSQL_PWD=jjyy123 && mysql -uroot  dongcha_waf < /tmp/dongcha_waf.sql'
    echo -ne "Mysql    Import dongcha_waf data \t........................ "
    if [[ $? -ne 0 ]]; then
        echo -e "[\033[31m ERROR \033[0m]"
    else
        echo -e "[\033[32m OK \033[0m]"
    fi
}

function init_docker_run() {
    init_dongcha-mysql
    init_dongcha-rsyslog
    init_dongcha-elk
    init_dongcha-waf-agent
    init_dongcha-waf-manager
    init_dongcha-nginx
    init_mysql_data
}

function load_docker_images() {
    load_dongcha-mysql
    load_dongcha-nginx
    load_dongcha-elk
    load_dongcha-rsyslog
    load_dongcha-waf-manager
    load_dongcha-waf-agent
}

function add_kernel_option() {
    vm_max=$(sysctl -p|grep -i vm.max_map_count |awk -F'=' '{print $2}'| sed s/^[\ \t]*//g)
    if [[ ${vm_max} -lt 655360  ]]; then
         echo "vm.max_map_count=655360" >> /etc/sysctl.conf
         sysctl -p
         if [[ $? -ne 0 ]]; then
            echo -e "[\033[31m ERROR \033[0m]"
        else
            echo -e "[\033[32m OK \033[0m]"
        fi
    fi
}


function main() {
    if [[ ! -d "${install_dir}/semf" ]]; then
        install_core
    fi

    #
    set_sellinux
    set_firewall

    # add kernel_option
    add_kernel_option

    # load docker images
    load_docker_images

    # First start
    init_docker_run
}

main
