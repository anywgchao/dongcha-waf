#!/usr/bin/env bash
#

BASE_DIR=$(cd "$(dirname "$0")";pwd)
source ${BASE_DIR}/config.conf
action=$1
target=$2

echo -e "================================================="
echo -e "   System Required: CentOS 7"
echo -e "   Description: dongcha-waf 安装脚本"
echo -e "   Version: \033[33m $Version \033[0m"
echo -e "   Author: secyun.org"
echo -e "   Project: dongcha-waf"
echo -e "================================================="

if [[ ! -f "${BASE_DIR}/config.conf" ]]; then
    echo -e "Error: No config path found."
    exit 1
fi

function usage() {
   echo "dongcha-waf Deployment setup script"
   echo
   echo "Usage: "
   echo "  dcsctl [COMMAND] ..."
   echo "  dcsctl --help"
   echo
   echo "Commands: "
   echo "  install      安装 dongcha-waf"
   echo "  start        启动 dongcha-waf"
   echo "  stop         停止 dongcha-waf"
   echo "  restart      重启 dongcha-waf"
   echo "  status       检查 dongcha-waf"
   echo "  uninstall    卸载 dongcha-waf"
}


function main() {
   case "${action}" in
      install)
         bash ${BASE_DIR}/install.sh
         ;;
      uninstall)
         bash ${BASE_DIR}/uninstall.sh
         ;;
      start)
         bash ${BASE_DIR}/start.sh
         ;;
      stop)
         bash ${BASE_DIR}/stop.sh
         ;;
      restart)
         bash ${BASE_DIR}/stop.sh
         bash ${BASE_DIR}/start.sh
         ;;
      status)
         bash ${BASE_DIR}/install_status.sh
         ;;
      --help)
         usage
         ;;
      -h)
         usage
         ;;
      *)
         echo -e "dcsctl: unknown COMMAND: '$action'"
         echo -e "See 'dcsctl --help' \n"
         usage
    esac
}

main
