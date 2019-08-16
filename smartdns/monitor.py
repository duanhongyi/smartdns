from urllib.parse import urlparse
from twisted.web.iweb import IPolicyForHTTPS
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS
from twisted.internet import task, ssl, reactor
from twisted.web.http_headers import Headers
from zope.interface import implementer


@implementer(IPolicyForHTTPS)
class SmartClientContextFactory(object):

    def __init__(self):
        self.default_policy = BrowserLikePolicyForHTTPS

    def creatorForNetloc(self, hostname, port):
        return ssl.CertificateOptions(verify=False)


class Monitor(object):

    def __init__(self, ip_set, monitor):
        self.ip_set = ip_set
        self.monitor = monitor
        self.black_mapping = {}

    def _check(self):
        host = urlparse(self.monitor["url"]).netloc
        for ip in self.ip_set:
            if ip not in self.black_mapping:
                self.black_mapping[ip] = 0
            url = self.monitor['url'].replace(host, ip, 1).encode("utf8")
            agent=Agent(reactor, contextFactory=SmartClientContextFactory(), connectTimeout=30)
            agent.request(b'GET', url, headers=Headers({"host": [host, ]})).addCallbacks(
                BlackMappingRemover(ip, self.black_mapping), BlackMappingAdder(ip, self.black_mapping))

    def check(self, ip):
        return self.black_mapping[ip] < self.monitor["frequency"]

    def start(self):
        task.LoopingCall(self._check).start(self.monitor["interval"])


class BlackMappingRemover(object):

    def __init__(self, ip, black_mapping):
        self.ip = ip
        self.black_mapping = black_mapping

    def __call__(self, *args, **kwargs):
        self.black_mapping[self.ip] = 0


class BlackMappingAdder(object):

    def __init__(self, ip, black_mapping):
        self.ip = ip
        self.black_mapping = black_mapping

    def __call__(self, *args, **kwargs):
        self.black_mapping[self.ip] += 1


class MonitorMapping(object):

    def __init__(self, config, amapping):
        self.config = config
        self.monitor_mapping = self._make_monitor_mapping(amapping)

    def _make_monitor_mapping(self, amapping):
        monitor_mapping = {}
        for name, item in amapping.items():
            if name in self.config:
                ip_set = set()
                monitor = Monitor(ip_set, self.config[name])
                for key, value in item.items():
                    if key == 'ttl':
                        continue
                    else:
                        ip_set.update(value.split(' '))
                monitor.start()
                monitor_mapping[name] = monitor
        return monitor_mapping

    def check(self, name, ip):
        if name in self.monitor_mapping:
            return self.monitor_mapping[name].check(ip)
        return True
