from functools import partial
from twisted.internet import task, ssl, reactor
from twisted.web.client import readBody, Agent, ResponseFailed, BrowserLikePolicyForHTTPS
from twisted.web.http_headers import Headers
from twisted.web.iweb import IPolicyForHTTPS
from twisted.internet.error import TimeoutError, ConnectError, TCPTimedOutError
from urllib.parse import urlparse
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

    def _check(self, host, ip):
        url = self.monitor['url'].replace(host, ip, 1).encode("utf8")
        agent = Agent(reactor, contextFactory=SmartClientContextFactory(), connectTimeout=30)
        agent.request(b'GET', url, headers=Headers({"host": [host, ]})).addCallbacks(
            BlackMappingChecker(
                ip, self.black_mapping), BlackMappingAdder(ip, self.black_mapping))

    def check(self, ip):
        return self.black_mapping[ip] < self.monitor["frequency"]

    def start(self):
        host = urlparse(self.monitor["url"]).netloc.split(":")[0]
        for ip in self.ip_set:
            self.black_mapping[ip] = 0
            task.LoopingCall(partial(self._check, host=host, ip=ip)).start(
                self.monitor["interval"])


class BlackMappingAdder(object):

    def __init__(self, ip, black_mapping):
        self.ip = ip
        self.black_mapping = black_mapping

    def __call__(self, failure):
        self.black_mapping[self.ip] += 1
        failure.trap(ResponseFailed, TimeoutError, ConnectError, TCPTimedOutError)


class BlackMappingChecker(object):

    def __init__(self, ip, black_mapping):
        self.ip = ip
        self.black_mapping = black_mapping

    def __call__(self, response):
        if response.code < 500:
            self.black_mapping[self.ip] = 0
        else:
            self.black_mapping[self.ip] += 1
        finished = readBody(response)
        finished.addCallback(lambda body: None)  # ignore
        return finished


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
