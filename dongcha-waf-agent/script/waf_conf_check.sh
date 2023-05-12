#!/bin/sh
set -e

echo "check waf"
NGINX_CMD="/data/semf/openresty/nginx/sbin/nginx"
NGINX_CONF="/data/semf/config/openresty/nginx.conf"
ssh -o StrictHostKeyChecking=no root@169.254.1.1 "${NGINX_CMD} -t -c ${NGINX_CONF}" || { echo "Test failed, exit code is $?"; exit 1; }