#!/bin/sh
set -e

echo "check waf"
#NGINX_CMD="/data/semf/openresty/nginx/sbin/nginx"
#NGINX_CONF="/data/semf/config/openresty/nginx.conf"

#if [[ `ssh -o StrictHostKeyChecking=no root@169.254.1.1 "pgrep nginx | wc -l"` != 0 ]]; then
#    echo "reload waf"
#    ssh -o StrictHostKeyChecking=no root@169.254.1.1 "${NGINX_CMD} -s reload -c ${NGINX_CONF}" || { echo "fail to reload waf, exit code is $?"; exit 1; }
#else
#    echo "start waf"
#    ssh -o StrictHostKeyChecking=no root@169.254.1.1 "${NGINX_CMD} -s start -c ${NGINX_CONF}" || { echo "fail to start waf, exit code is $?"; exit 1; }
#fi

if [[ `ssh -o StrictHostKeyChecking=no root@169.254.1.1 "pgrep nginx | wc -l"` != 0 ]]; then
    echo "reload waf"
    ssh -o StrictHostKeyChecking=no root@169.254.1.1 "systemctl reload dongcha-waf" || { echo "fail to reload waf, exit code is $?"; exit 1; }
else
    echo "start waf"
    ssh -o StrictHostKeyChecking=no root@169.254.1.1 "systemctl start dongcha-waf}" || { echo "fail to start waf, exit code is $?"; exit 1; }
fi
