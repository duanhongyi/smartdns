#!/bin/bash
. ../../smartdns_env/bin/activate
PYTHON="python"
cd ../bin
$PYTHON checkconfig.py || { echo "[FATAL]配置检查失败，取消重启"; exit 1; }
$PYTHON sdns.py
