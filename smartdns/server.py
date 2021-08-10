# -*- coding: utf-8 -*-
import logging
import random
import re
from twisted.internet import defer
from twisted.names import dns, server, client, common, resolve
from twisted.python import failure

from . import sdns

logger = logging.getLogger(__name__)

typeToMethod = {
    dns.A: 'lookupAddress',
    dns.AAAA: 'lookupIPV6Address',
    dns.A6: 'lookupAddress6',
    dns.NS: 'lookupNameservers',
    dns.CNAME: 'lookupCanonicalName',
    dns.SOA: 'lookupAuthority',
    dns.MB: 'lookupMailBox',
    dns.MG: 'lookupMailGroup',
    dns.MR: 'lookupMailRename',
    dns.NULL: 'lookupNull',
    dns.WKS: 'lookupWellKnownServices',
    dns.PTR: 'lookupPointer',
    dns.HINFO: 'lookupHostInfo',
    dns.MINFO: 'lookupMailboxInfo',
    dns.MX: 'lookupMailExchange',
    dns.TXT: 'lookupText',
    dns.SPF: 'lookupSenderPolicy',

    dns.RP: 'lookupResponsibility',
    dns.AFSDB: 'lookupAFSDatabase',
    dns.SRV: 'lookupService',
    dns.NAPTR: 'lookupNamingAuthorityPointer',
    dns.AXFR: 'lookupZone',
    dns.ALL_RECORDS: 'lookupAllRecords',
}

smartType = ('lookupAddress', 'lookupAuthority')


class FailureHandler:
    def __init__(self, resolver, query, timeout, addr=None, edns=None):
        self.resolver = resolver
        self.query = query
        self.timeout = timeout
        self.addr = addr
        self.edns = edns

    def __call__(self, failure):
        # AuthoritativeDomainErrors should halt resolution attempts
        failure.trap(dns.DomainError, defer.TimeoutError, NotImplementedError)
        return self.resolver(self.query, self.timeout, self.addr, self.edns)


class MapResolver(client.Resolver):
    def __init__(self, finder, a_mapping, ns_mapping, soa_mapping, servers):
        self.finder = finder
        self.a_mapping = a_mapping
        self.ns_mapping = ns_mapping
        self.soa_mapping = soa_mapping
        client.Resolver.__init__(self, servers=servers)

    def query(self, query, timeout=None, addr=None, edns=None):
        try:
            if typeToMethod[query.type] in smartType:
                return self.typeToMethod[query.type](str(query.name), timeout, addr, edns)
            else:
                return self.typeToMethod[query.type](str(query.name), timeout)
        except KeyError as e:
            return defer.fail(failure.Failure(NotImplementedError(str(self.__class__) + " " + str(query.type))))

    def lookupAddress(self, name, timeout=None, addr=None, edns=None):

        def packResult(value, ttl):
            ret = []
            add = []
            for x in value:
                ret.append(dns.RRHeader(name, dns.A, dns.IN, ttl, dns.Record_A(x, ttl), True))

            if edns is not None:
                if edns.rdlength > 8:
                    add.append(dns.RRHeader('', sdns.EDNS, 4096, edns.ttl, edns.payload, True))
                else:
                    add.append(dns.RRHeader('', sdns.EDNS, 4096, 0, sdns.Record_EDNS(None, 0), True))
            return [ret, (), add]

        wildcard = name[name.index("."):] if "." in name else None
        if name in self.a_mapping:
            ttl = self.a_mapping[name]['ttl']
            result = self.finder.findIP(str(addr[0]), name)
            random.shuffle(result)  # 返回的IP数组乱序
            return packResult(result, ttl)
        elif wildcard is not None and wildcard in self.a_mapping:
            ttl = self.a_mapping[wildcard]['ttl']
            result = self.finder.findIP(str(addr[0]), wildcard)
            random.shuffle(result)  # 返回的IP数组乱序
            return packResult(result, ttl)
        else:
            return self._lookup(name, dns.IN, dns.A, timeout)

    def lookupNameservers(self, name, timeout=None):
        if name in self.ns_mapping:
            result = self.ns_mapping[name]
            ttl = result['ttl']
            record = re.split(r',|\s+', result['record'])

            def packResultNS(value):
                ret = []
                for x in value:
                    ret.append(dns.RRHeader(name, dns.NS, dns.IN, ttl, dns.Record_NS(x, ttl), True))
                return [ret, (), ()]

            return packResultNS(record)
        else:
            return self._lookup(name, dns.IN, dns.NS, timeout)

    def lookupAuthority(self, name, timeout=None, addr=None, edns=None):
        if name in self.soa_mapping:
            result = self.soa_mapping[name]
            add = []

            def packResultSOA(value):
                if edns is not None:
                    if edns.rdlength > 8:
                        add.append(dns.RRHeader('', dns.EDNS, 4096, edns.ttl, edns.payload, True))
                    else:
                        add.append(dns.RRHeader('', dns.EDNS, 4096, 0, sdns.Record_EDNS(None, 0), True))

                return [(dns.RRHeader(name, dns.SOA, dns.IN, value['ttl'],
                                      dns.Record_SOA(value['record'], value['email'], value['serial'], value['refresh'],
                                                     value['retry'], value['expire'], value['ttl']), True),),
                        (),
                        add
                        ]

            ret = packResultSOA(result)
            logger.info("SOA\t[domain: %s]\t[return: %s]\t[additional: %s]" % \
                        (name, result, add))
            return ret
        else:
            return self._lookup(name, dns.IN, dns.SOA, timeout)

    def lookupIPV6Address(self, name, timeout=None, addr=None):
        return [(), (), ()]


class SmartResolverChain(resolve.ResolverChain):

    def __init__(self, resolvers):
        # resolve.ResolverChain.__init__(self, resolvers)
        common.ResolverBase.__init__(self)
        self.resolvers = resolvers

    def _lookup(self, name, cls, type, timeout, addr=None, edns=None):
        q = dns.Query(name, type, cls)
        d = defer.fail(failure.Failure(dns.DomainError(name)))
        for r in self.resolvers:
            d = d.addErrback(
                FailureHandler(r.query, q, timeout, addr, edns)
            )
        return d

    def _query(self, query, timeout=None, addr=None, edns=None):
        if typeToMethod[query.type] in smartType:
            return self.typeToMethod[query.type](str(query.name), timeout, addr, edns)
        else:
            return self.typeToMethod[query.type](str(query.name), timeout)

    def query(self, query, timeout=None, addr=None, edns=None):
        try:
            return self._query(query, timeout, addr, edns)
        except KeyError as e:
            return defer.fail(failure.Failure(NotImplementedError(str(self.__class__) + " " + str(query.type))))

    def lookupAddress(self, name, timeout=None, addr=None, edns=None):
        return self._lookup(name, dns.IN, dns.A, timeout, addr, edns)

    def lookupAuthority(self, name, timeout=None, addr=None, edns=None):
        return self._lookup(name, dns.IN, dns.SOA, timeout, addr, edns)

    def lookupIPV6Address(self, name, timeout=None, addr=None, edns=None):
        return self._lookup(name, dns.IN, dns.AAAA, timeout, addr, edns)

    def lookupNameservers(self, name, timeout=None, addr=None, edns=None):
        return self._lookup(name, dns.IN, dns.NS, timeout, addr, edns)


class SmartDNSFactory(server.DNSServerFactory):

    def handleQuery(self, message, protocol, address):

        # if len(message.additional) > 0:
        #    print inspect.getmembers(message.additional[0]
        # 可以支持多个query
        query = message.queries[0]
        edns = None
        cliAddr = address
        if query.type == 43 or typeToMethod[query.type] == 'lookupAllRecords':
            return [(), (), ()]
        if isinstance(protocol, dns.DNSProtocol):
            cliAddr = protocol.transport.client
        elif typeToMethod[query.type] in smartType and \
                len(message.additional) != 0 and \
                message.additional[0].type == 41 and \
                message.additional[0].rdlength > 8:
            if isinstance(message.additional[0].payload, dns.Record_A):
                cliAddr = (message.additional[0].payload.dottedQuad(), 0)
            edns = message.additional[0]
        return self.resolver.query(query, addr=cliAddr, edns=edns).addCallback(
            self.gotResolverResponse, protocol, message, address
        ).addErrback(
            self.gotResolverError, protocol, message, address
        )

    def __init__(self, authorities=None, caches=None, clients=None, verbose=0):
        resolvers = []
        if authorities is not None:
            resolvers.extend(authorities)
        if caches is not None:
            resolvers.extend(caches)
        if clients is not None:
            resolvers.extend(clients)

        self.canRecurse = not not clients
        self.resolver = SmartResolverChain(resolvers)
        self.verbose = verbose
        if caches:
            self.cache = caches[-1]
        self.connections = []
