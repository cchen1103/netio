from functools import wraps


# x1=src_mac, x2=dst_mac
_sorted_mac = lambda (x1,x2): (x2,x1) if x1 > x2 else (x1,x2)
# x1=src_mac, x2=dst_mac, y1=src_ip, y2=dst_ip
_sorted_ip = lambda (x1,x2,y1,y2): (x2,y2,x1,y1) if x1 > x2 else (x1,x2,y1,y2)
# x1=src_mac, x2=dst_mac, y1=src_ip, y2=dst_ip, z1=src_port, z2=dst_port
_sorted_tcp_udp = lambda (x1,x2,y1,y2,z1,z2): (x2,y2,z2,x1,y1,z1) if x1 > x2 else (x1,x2,y1,y2,z1,z2)


class AttrCounter:
    def __init__(self, func):
        self.func = func
        self.counter = dict()
    def __call__(self, *args, **kwargs):
        attr = self.func(*args, **kwargs)
        if attr is not None:    # attr of 'None' will be discarded
            if attr in self.counter:
                self.counter[attr] = self.counter[attr] + 1
            else:
                self.counter[attr] = 1
    def clr_count(self, *attrs):
        if not attrs:
            self.counter = dict()   # clear all counters
        else:
            for attr in (x for x in attrs if x in self.counter):
                del self.counter[attr]  # remove listed attributes counter
    @property
    def counters(self):
        return self.counter
    @property
    def total(self):
        return sum(self.counters.values())

from ..decoders import decoder


@AttrCounter
def ethernet_counter(data):
    """
    count on the mac address pairs.
    it does not diffrenciate the src mac and dst mac.
    counter is sorted by mac address.
    """
    try:
        attr = _sorted_mac(decoder.decode_eth(data))
    except decoder.DecodeException:
        attr = None
    return attr


@AttrCounter
def ip_counter(data):
    """
    count on the mac/ip address pairs.
    it does not matter of the directotion of the packets.
    counter is sorted by mac/ip address.
    """
    try:
        attr = _sorted_ip(decoder.decode_ip(data))
    except decoder.DecodeException:
        attr = None
    return attr


@AttrCounter
def tcp_counter(data):
    try:
        attr = _sorted_tcp_udp(decoder.decode_tcp(data)[:6])
    except decoder.DecodeException:
        attr = None
    return attr


@AttrCounter
def udp_counter(data):
    try:
        attr = _sorted_tcp_udp(decoder.decode_udp(data))
    except decoder.DecodeException:
        attr = None
    return attr
