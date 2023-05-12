#!/bin/sh
# vim:sw=4:ts=4:et

set -e

if [ "$1" = "dongcha-waf-agent" ]; then
    gunicorn -c configs/gunicorn_conf.py manage:app
fi

exec "$@"
