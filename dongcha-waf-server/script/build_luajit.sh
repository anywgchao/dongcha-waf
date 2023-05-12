#!/bin/bash
###
# @Author: Daboluo
# @Date: 2019-09-19 17:00:03
# @LastEditTime: 2020-08-24 23:31:31
# @LastEditors: Do not edit
###

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS=$(uname -s)
PREBUILT_PLATFORM=$OS-x86_64
if [[ "$OS" == "Darwin" ]]; then
    PREBUILT_PLATFORM=darwin-x86_64
fi

cd $DIR
luajit="/data/semf/openresty/luajit/bin/luajit"
source_path="$DIR/openwaf"
target_path="$DIR/openwaf_out/$PREBUILT_PLATFORM"
rm -f $target_path/*.lua
mkdir -p $target_path

function compile() {
    for file in $1; do
        if test -f $file; then
            echo $file
            $luajit -b $file $target_path/$(basename $file)
        fi
    done
}

compile "$source_path/*.lua"
