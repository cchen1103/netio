from functools import wraps


"""
lambda function to sort on mac, ip, tcp and udp.
the sorted is used to count number of packets regardless of source and destination
address as packet is communicates between 2 end points.
"""
# x1=src_mac, x2=dst_mac
_sorted_mac = lambda x1,x2: (x2,x1) if x1 > x2 else (x1,x2)
# x1=src_mac, x2=dst_mac, y1=src_ip, y2=dst_ip
_sorted_ip = lambda x1,x2,y1,y2: (x2,x1,y2,y1) if x1 > x2 else (x1,x2,y1,y2)
# x1=src_mac, x2=dst_mac, y1=src_ip, y2=dst_ip, z1=src_port, z2=dst_port
_sorted_tcp_udp = lambda x1,x2,y1,y2,z1,z2: (x2,x1,y2,y1,z2,z1) if x1 > x2 else (x1,x2,y1,y2,z1,z2)


class AttrCounter:
    """
    class of counter decorator.
    it count the number of packets for ethernet frame,
    ip, tcp or udp.

    input:  decoder functions
    attributes:
        .counters   count of packets between 2 end points depends on next_protocol
        .total      total count of packets uses the protocol
    methods:
        .clr_count()    clear all counters, or listed end points counters
    """
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


import time


class TimedAttrCounter(AttrCounter):
    def __init__(self, func):
        """
        interval in seconds to form the timed buckets based on 00:00:00
        default interval value is 300 seconds
        """
        self._interval = 300
        self.bucket = int(time.time()/self.interval)
        self.timed_counter = dict()
        AttrCounter.__init__(self, func)
    def __call__(self, *args, **kwargs):
        new_bucket = int(time.time()/self.interval)
        if self.bucket != new_bucket:
            # snap the time bucket counts from super class
            # reset super class counters
            self.timed_counter[self.bucket] = self.counters
            self.clr_count()
            self.bucket = new_bucket
    @property
    def interval(self):
        return self._interval
    @interval.setter
    def interval(self, val):
        self._interval = val


from ..decoders import decoder


def _attr_ethernet(data):
    """
    count on the mac address pairs.
    it does not diffrenciate the src mac and dst mac.
    counter is sorted by mac address.
    """
    if data:
        try:
            attr = _sorted_mac(*decoder.decode_eth(data))
        except decoder.DecodeException:
            attr = None
        return attr


def _attr_ip(data):
    """
    count on the mac/ip address pairs.
    it does not diffrenciate the src address and dst address.
    counter is sorted by mac/ip address.
    """
    if data:
        try:
            attr = _sorted_ip(*decoder.decode_ip(data))
        except decoder.DecodeException:
            attr = None
        return attr


def _attr_tcp(data):
    """
    count on the mac/ip/port address pairs.
    it does not diffrenciate the src address and dst address.
    counter is sorted by mac/ip/port address.
    """
    if data:
        try:
            attr = _sorted_tcp_udp(*(decoder.decode_tcp(data)[:6]))
        except decoder.DecodeException:
            attr = None
        return attr


def _attr_udp(data):
    """
    count on the mac/ip/port address pairs.
    it does not diffrenciate the src address and dst address.
    counter is sorted by mac/ip/port address.
    """
    if data:
        try:
            attr = _sorted_tcp_udp(*decoder.decode_udp(data))
        except decoder.DecodeException:
            attr = None
        return attr


@AttrCounter
def ethernet_counter(data):
    return _attr_ethernet(data)


@TimedAttrCounter
def ethernet_timed_counter(data):
    return _attr_ethernet(data)


@AttrCounter
def ip_counter(data):
    return _attr_ip(data)


@TimedAttrCounter
def ip_timed_counter(data):
    return _attr_ip(data)


@AttrCounter
def tcp_counter(data):
    return _attr_tcp(data)


@TimedAttrCounter
def tcp_timed_counter(data):
    return _attr_tcp(data)


@AttrCounter
def udp_counter(data):
    return _attr_udp(data)


@TimedAttrCounter
def udp_timed_counter(data):
    return _attr_udp(data)
