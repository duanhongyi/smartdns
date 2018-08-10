#!/bin/sh

set -e

filepath=$(cd "$(dirname "$0")"; pwd)

cd $filepath/../pkg
tar zxf virtualenv-1.9.1.tar.gz
tar zxf zope.interface-4.0.1.tar.gz
tar jxf Twisted-12.2.0.tar.bz2

cd virtualenv-1.9.1
python virtualenv.py $filepath/../../smartdns_env
. $filepath/../../smartdns_env/bin/activate

cd ../zope.interface-4.0.1
python setup.py install

cd ../Twisted-12.2.0
python setup.py install

cd .. && rm -rf virtualenv-1.9.1 zope.interface-4.0.1 Twisted-12.2.0
 
dnsfilenum=`find $filepath/../../smartdns_env/lib/python*/site-packages/Twisted-12.2.0*/twisted/names -name dns.py | wc -l`
if [ 1 -ne $dnsfilenum ]; then
	echo "cannot find dns.py"
	exit 2
fi
dnsfile=`find $filepath/../../smartdns_env/lib/python*/site-packages/Twisted-12.2.0*/twisted/names -name dns.py`
cp -f $filepath/dns_in_twisted.py $dnsfile

mkdir -p $filepath/../log
cp -rf $filepath/../rootfs/* /
sed -i "s#{smartdns_path}#${filepath}#g" /etc/systemd/system/smartdns.service
systemctl daemon-reload
systemctl enable smartdns
systemctl start smartdns
