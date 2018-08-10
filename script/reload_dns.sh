#!/bin/bash

set -e

filepath=$(cd "$(dirname "$0")"; pwd)

chmod a+r $filepath/../sdns.pid &>/dev/null
pid=`cat $filepath/../sdns.pid 2>/dev/null`
kill -s HUP ${pid}
