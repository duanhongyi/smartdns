import socket
import struct
from zope.interface import implementer
from twisted.names.dns import str2time, tputil, readPrecisely, IRecord, IEncodable

EDNS = 41

@implementer(IEncodable, IRecord)
class Record_EDNS(tputil.FancyEqMixin):
    """
    An EDNS
    """

    compareAttributes = ('address', 'family', 'opt_code', 'opt_length', 'source_nm', 'scope_nm')

    TYPE = EDNS
    address = None
    opt_code = None
    opt_length = None
    family =  None
    source_nm = None
    scope_nm = None

    def __init__(self, address='0.0.0.0', ttl=None):
        if address is not None:
            address = socket.inet_aton(address)
            self.address = address
            self.ttl = str2time(ttl)


    def encode(self, strio, compDict = None):
        if self.address is not None:
            strio.write(struct.pack('!HHHcc', self.opt_code, self.opt_length, self.family, self.source_nm, self.scope_nm))
            strio.write(self.address)

    def decode(self, strio, length = None):
        if length > 8:
            rdata = readPrecisely(strio, 8)
            self.opt_code, self.opt_length, self.family, self.source_nm, self.scope_nm = struct.unpack("!HHHcc", rdata)
            #hack let scope netmask = source netmask
            self.scope_nm = self.source_nm
            self.address = readPrecisely(strio, length - 8)

    def __hash__(self):
        return hash(self.address)


    def __str__(self):
        return '<A address=%s ttl=%s>' % (self.address, self.ttl)
    __repr__ = __str__


    def dottedQuad(self):
        n = 4 - len(self.address)
        return socket.inet_ntoa(self.address + '\x00' * n)