# -*- coding: utf-8 -*-
import re
import yaml
import sys
import os
import time
import bisect
import logging
from os.path import isfile
import socket
import struct

logger = logging.getLogger(__name__)


def ip2long(ip):
    "convert decimal dotted quad string to long integer"
    hexn = ''.join(["%02X" % int(i) for i in ip.split('.')])
    return int(hexn, 16)


def long2ip(num):
    "convert long int to dotted quad string"
    iplist = []
    for n in range(4):
        num,mod = divmod(num,256)
        iplist.insert(0,str(mod))
    return '.'.join(iplist)


class IPPool(object):
    def __init__(self, ipfile, recordfile, monitor_mapping):
        if not isfile(ipfile):
            logger.warning("can't find ip data file: %s" % ipfile)
            # 故意返回数据，另程序退出
            return 1
        self.ipfile = ipfile

        if not isfile(recordfile):
            logger.warning("can't find A record file: %s" % recordfile)
            return 2
        self.recordfile = recordfile
        self.monitor_mapping = monitor_mapping

        # 初始化iplist，用来进行2分查找
        self.iplist = []
        # 初始化iphash，用来检索详细信息
        self.iphash = {}

        # 初始化存储a.yaml配置
        self.record = {}
        # 存储各个域名的地域对于ip信息
        self.locmapip = {}

        # load record data
        self.LoadRecord()

        # load ip data
        self.LoadIP()

        print('Init IP pool finished !')

    def LoadIP(self):
        f = open(self.ipfile, 'r')
        logger.warning("before load: %s" % (time.time()))
        for eachline in f:
            ipstart, ipend, country, province, city, sp = eachline.strip().split(',')
            ipstart = int(ipstart)
            ipend = int(ipend)

            # 如果ip地址为0,忽略
            if 0 == ipstart:
                continue
            self.iplist.append(ipstart)
            if ipstart in self.iphash:
                # print "maybe has same ipstart"
                pass
            else:
                # ipstart, ipend, country, province, city, sp, domain ip hash
                self.iphash[ipstart] = [ipstart, ipend,
                                        country, province, city, sp, {}]
                # 最好合并后再计算
                self.JoinIP(ipstart)
        f.close()
        logger.warning("after load: %s" % (time.time()))
        self.iplist.sort()
        logger.warning("after sort: %s" % (time.time()))

    # 重写LoadRecord和JoinIP，提升启动效率
    def LoadRecord(self):
        Add = [8, 4, 2, 1]
        f = open(self.recordfile, 'r')
        self.record = yaml.load(f, Loader=yaml.FullLoader)
        for fqdn in self.record:
            self.locmapip[fqdn] = {}
            if fqdn.endswith("_template"):
                continue

            for router in self.record[fqdn]:
                if router == 'default' or router == 'ttl':
                    continue
                p = None
                # p = re.match(ur"(.*),(.*),(.*),(.*)", router)
                p = router.strip().split(',')
                if p is None:
                    logger.warning(
                        "maybe record file format error: %s" % self.recordfile)
                    sys.exit(1)
                match = [None, None, None, None]
                weight = 0
                for num in range(0, 4):
                    match[num] = p[num]
                    if p[num] != "":
                        weight += Add[num]

                if match[0] not in self.locmapip[fqdn]:
                    self.locmapip[fqdn][match[0]] = {}
                    self.locmapip[fqdn][match[0]][match[1]] = {}
                    self.locmapip[fqdn][match[0]][match[1]][match[2]] = {}
                    self.locmapip[fqdn][match[0]][match[1]][match[2]][match[3]] = \
                        [self.record[fqdn][router], weight]
                elif match[1] not in self.locmapip[fqdn][match[0]]:
                    self.locmapip[fqdn][match[0]][match[1]] = {}
                    self.locmapip[fqdn][match[0]][match[1]][match[2]] = {}
                    self.locmapip[fqdn][match[0]][match[1]][match[2]][match[3]] = \
                        [self.record[fqdn][router], weight]
                elif match[2] not in self.locmapip[fqdn][match[0]][match[1]]:
                    self.locmapip[fqdn][match[0]][match[1]][match[2]] = {}
                    self.locmapip[fqdn][match[0]][match[1]][match[2]][match[3]] = \
                        [self.record[fqdn][router], weight]
                elif match[3] not in self.locmapip[fqdn][match[0]][match[1]][match[2]]:
                    self.locmapip[fqdn][match[0]][match[1]][match[2]][match[3]] = \
                        [self.record[fqdn][router], weight]
        f.close()
        # logger.warning(self.locmapip)

    def JoinIP(self, ip):
        for fqdnk, fqdnv in self.locmapip.items():
            l1 = []
            l2 = []
            l3 = []
            weight = 0
            #logger.warning("l1 : %s, %s" %(self.iphash[ip][2], fqdnv.keys()))
            if "" in fqdnv and "" != self.iphash[ip][2]:
                l1.append(fqdnv[""])
            if self.iphash[ip][2] in fqdnv:
                l1.append(fqdnv[self.iphash[ip][2]])
            for k in l1:
                #logger.warning("l2 : %s, %s" %(self.iphash[ip][3], k.keys()))
                if "" in k and "" != self.iphash[ip][3]:
                    l2.append(k[""])
                if self.iphash[ip][3] in k:
                    l2.append(k[self.iphash[ip][3]])
            for k in l2:
                #logger.warning("l3 : %s, %s" %(self.iphash[ip][4], k.keys()))
                if "" in k and "" != self.iphash[ip][4]:
                    l3.append(k[""])
                if self.iphash[ip][4] in k:
                    l3.append(k[self.iphash[ip][4]])
            for k in l3:
                #logger.warning("l4 : %s, %s" %(self.iphash[ip][5], k.keys()))
                if "" in k and k[""][1] > weight:
                    self.iphash[ip][6][fqdnk] = k[""]
                    weight = k[""][1]
                if self.iphash[ip][5] in k and k[self.iphash[ip][5]][1] > weight:
                    self.iphash[ip][6][fqdnk] = k[self.iphash[ip][5]]
                    weight = k[self.iphash[ip][5]][1]
            if fqdnk not in self.iphash[ip][6]:
                self.iphash[ip][6][fqdnk] = [self.record[fqdnk]['default'], 0]

    def ListIP(self):
        for key in self.iphash:
            print("ipstart: %s  ipend: %s  country: %s  province: %s  city: %s  sp: %s" % (key, self.iphash[key][1], self.iphash[key][2], self.iphash[key][3], self.iphash[key][4], self.iphash[key][5]))
            for i in self.iphash[key][6]:
                print("[domain:%s   ip: %s]" % (i, self.iphash[key][6][i][0]))

    def SearchLocation(self, ip):
        ipnum = ip2long(ip)
        ip_point = bisect.bisect_right(self.iplist, ipnum)
        i = self.iplist[ip_point - 1]
        if ip_point == self.iplist.__len__():
            j = self.iplist[ip_point - 1]
        else:
            j = self.iplist[ip_point]

        return i, j, ipnum

    def FindIP(self, ip, name):
        i, j, ipnum = self.SearchLocation(ip)
        ip_list = None
        if i in self.iphash:
            ipstart = self.iphash[i][0]
            ipend = self.iphash[i][1]
            country = self.iphash[i][2]
            province = self.iphash[i][3]
            city = self.iphash[i][4]
            sp = self.iphash[i][5]
            if ipstart <= ipnum <= ipend:
                ip_list = [
                    tmp_ip for tmp_ip in re.split(r',|\s+', self.iphash[i][6][name][0]) \
                        if not re.search(r'[^0-9.]', tmp_ip) and self.monitor_mapping.check(name, tmp_ip)]
                logger.info("userip:[%s] domain:[%s] section:[%s-%s] location:[%s,%s,%s,%s] ip_list:%s" % (
                    ip, name, long2ip(ipstart), long2ip(ipend), country, province, city, sp, ip_list))
        if not ip_list or len(ip_list) == 0:
            # maybe something wrong
            tmp_ip_list = [
                tmp_ip for tmp_ip in re.split(r',|\s+', self.record[name]['default']) \
                    if not re.search(r'[^0-9.]', tmp_ip)]
            ip_list = [tmp_ip for tmp_ip in tmp_ip_list if self.monitor_mapping.check(name, tmp_ip)]
            if len(ip_list) == 0:
                logger.warning("no available ip for %s, use default ip" % name)
                return tmp_ip_list
        return ip_list
