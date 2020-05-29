# -*- coding: utf-8 -*-

# version
__version__ = '1.0.1.1'

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
from multiprocessing import cpu_count, Process
from . import dnsserver, ippool, monitor


logger = logging.getLogger(__name__)


def loadconfig(path):
    if not isfile(path):
        print("[FATAL] can't find config file %s !" % path)
        exit(1)
    with open(path, 'r') as f:
        return yaml.load(f, Loader=yaml.FullLoader)


def prepare_run(run_env):
    # load main config
    logger.info('start to load %s ......' % run_env['conf'])
    conf = loadconfig(os.path.join(run_env['conf'], 'sdns.yaml'))
    logger.info('start to load A,SOA,NS record ......')
    a_mapping = loadconfig(os.path.join(run_env['conf'], 'a.yaml'))
    ns_mapping = loadconfig(os.path.join(run_env['conf'], 'ns.yaml'))
    soa_mapping = loadconfig(os.path.join(run_env['conf'], 'soa.yaml'))

    # start monitor
    monitor_config = loadconfig(os.path.join(run_env['conf'], 'monitor.yaml'))
    monitor_mapping = monitor.MonitorMapping(monitor_config, a_mapping)
    # load dns record config file
    logger.info('start to init IP pool ......')
    finder = ippool.CachedIPPool(
        os.path.join(run_env['conf'], 'ip.csv'),
        os.path.join(run_env['conf'], 'a.yaml'),
        monitor_mapping)

    run_env['finder'] = finder

    # set up a resolver that uses the mapping or a secondary nameserver
    dnsforward = []
    for i in conf['dnsforward']:
        dnsforward_ip, dnsforward_port = i.split(":")
        dnsforward.append((dnsforward_ip, int(dnsforward_port)))

    # create the protocols
    for listen_tcp in conf['listen']['tcp']:
        listen_tcp_ip, listen_tcp_port = listen_tcp.split(":")
        f = dnsserver.SmartDNSFactory(
            caches=[cache.CacheResolver()], clients=[
                dnsserver.MapResolver(
                    finder, a_mapping, ns_mapping, soa_mapping, servers=dnsforward)])
        f.noisy = False
        run_env['tcp'].append([int(listen_tcp_port), f, listen_tcp_ip])
    for listen_udp in conf['listen']['tcp']:
        listen_udp_ip, listen_udp_port = listen_udp.split(":")
        p = dns.DNSDatagramProtocol(dnsserver.SmartDNSFactory(
            caches=[cache.CacheResolver()], clients=[
                dnsserver.MapResolver(
                    finder, a_mapping, ns_mapping, soa_mapping, servers=dnsforward)]))
        p.noisy = False
        run_env['udp'].append([int(listen_udp_port), p, listen_udp_ip])
    return conf


def main():
    run_env = {'udp': [], 'tcp': [], 'closed': 0,
               'updated': False, 'finder': None}
    if len(sys.argv) > 1:
        run_env['conf'] = sys.argv[1]
    else:
        run_env['conf'] = '/etc/smartdns'

    conf = prepare_run(run_env)
    for e in run_env['tcp']:
        reactor.listenTCP(e[0], e[1], interface=e[2])
    for e in run_env['udp']:
        reactor.listenUDP(e[0], e[1], interface=e[2])
    workers = []
    for _ in range(conf.get("workers", cpu_count() * 2)):
        process = Process(target=reactor.run)
        process.daemon = True
        process.start()
        workers.append(process)
    [worker.join() for worker in workers]
