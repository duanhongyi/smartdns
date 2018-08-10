#!/bin/bash

set -e

filepath=$(cd "$(dirname "$0")"; pwd)

. $filepath/../../smartdns_env/bin/activate
PYTHON="python"
cd $filepath/../bin
$PYTHON checkconfig.py || { echo "[FATAL]配置检查失败，取消重启"; exit 1; }
$PYTHON sdns.py
