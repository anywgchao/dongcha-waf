#!/bin/sh
# vim:sw=4:ts=4:et

set -e

if [ "$1" = "dongcha-waf-manager" ]; then
    gunicorn -c SeMF/waf_gunicorn.py SeMF.wsgi:application
fi

exec "$@"
