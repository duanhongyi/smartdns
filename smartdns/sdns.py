# -*- coding: utf-8 -*-

# version
__version__ = '1.0.1.1'

import socket
import time
import signal
import sys
import os
import yaml
import logging
from os.path import isfile
from zope.interface import implements
from twisted.internet import defer, interfaces
from twisted.python import failure
from twisted.internet.protocol import DatagramProtocol
from twisted.application import service, internet
from twisted.names import dns, server, client, cache, common, resolve
from twisted.internet import reactor
from . import dnsserver, ippool, monitor


logger = logging.getLogger(__name__)


def loadconfig(path):
    if not isfile(path):
        print("[FATAL] can't find config file %s !" % path)
        exit(1)
    with open(path, 'r') as f:
        return yaml.load(f, Loader=yaml.FullLoader)


def get_local_ip():
    import sys
    import socket
    import fcntl
    import array
    import struct
    is_64bits = sys.maxsize > 2**32
    struct_size = 40 if is_64bits else 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    max_possible = 8  # initial value
    while True:
        bytes = max_possible * struct_size
        names = array.array('B', b'\0' * bytes)
        outbytes = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            0x8912,  # SIOCGIFCONF
            struct.pack('iL', bytes, names.buffer_info()[0])
        ))[0]
        if outbytes == bytes:
            max_possible *= 2
        else:
            break
    namestr = names.tostring()
    return [(namestr[i:i+16].split(b'\0', 1)[0],
             socket.inet_ntoa(namestr[i+20:i+24]))
            for i in range(0, outbytes, struct_size)]


def prepare_run(run_env):
        # load main config
    logger.info('start to load %s ......' % run_env['conf'])
    conf = loadconfig(os.path.join(run_env['conf'], 'sdns.yaml'))

    logger.info('start to load A,SOA,NS record ......')
    Amapping = loadconfig(os.path.join(run_env['conf'], 'a.yaml'))
    NSmapping = loadconfig(os.path.join(run_env['conf'], 'ns.yaml'))
    SOAmapping = loadconfig(os.path.join(run_env['conf'], 'soa.yaml'))

    # start monitor
    monitor_config = loadconfig(os.path.join(run_env['conf'], 'monitor.yaml'))
    monitor_mapping = monitor.MonitorMapping(monitor_config, Amapping)
    # load dns record config file
    logger.info('start to init IP pool ......')
    Finder = ippool.IPPool(
        os.path.join(run_env['conf'], 'ip.csv'),
        os.path.join(run_env['conf'], 'a.yaml'),
        monitor_mapping)

    run_env['finder'] = Finder

    listen_tcp_port = conf['listen']['tcp']
    listen_udp_port = conf['listen']['udp']

    # set up a resolver that uses the mapping or a secondary nameserver
    dnsforward = []
    for i in conf['dnsforward_ip']:
        dnsforward.append((i, conf['dnsforward_port']))

    for ifc, ip in get_local_ip():
        # create the protocols
        SmartResolver = dnsserver.MapResolver(
            Finder, Amapping, NSmapping, SOAmapping, servers=dnsforward)
        f = dnsserver.SmartDNSFactory(
            caches=[cache.CacheResolver()], clients=[SmartResolver])
        p = dns.DNSDatagramProtocol(f)
        f.noisy = p.noisy = False
        run_env['tcp'].append([listen_tcp_port, f, ip])
        run_env['udp'].append([listen_udp_port, p, ip])


def main():
    run_env = {'udp': [], 'tcp': [], 'closed': 0,
               'updated': False, 'finder': None}
    if len(sys.argv) > 1:
        run_env['conf'] = sys.argv[1]
    else:
        run_env['conf'] = '/etc/smartdns'
        
    prepare_run(run_env)
    for e in run_env['tcp']:
        reactor.listenTCP(e[0], e[1], interface=e[2])
    for e in run_env['udp']:
        reactor.listenUDP(e[0], e[1], interface=e[2])
    reactor.run()
