import os

is_admin = lambda: os.getuid() == 0

import socket

class sniff_sock:
    """
    create execution on creating socket, listening to network traffic and destroy it
    when the sniffing completes.
    """
    def __init__(self):
        self.s = None
    def __enter__(self):
        """
        create a socket to sniff internet traffic on IP protocol
        """
        self.s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        return self.s
    def __exit__(self, type, value, traceback):
        """
        destroy the socket and free all resources
        """
        if self.s is not None:
            self.s.close()


from .decoders.__packet_headers__ import Tcp
from .decoders.decoders import *
from collections import Counter


class NetStats:
    def __init__(self):
        self._ethernet_enabled = False
        self._ip_enabled = False
        self._tcp_enabled = False
        self._udp_enabled = False
        self._interval = 0
        self.netstats = Counter()
        self.ipstats = Counter()
        self.udpstats = Counter()
        self.tcpstats = Counter()
        self.session_t = dict()
        self._tcp_track = dict()
    @property
    def ethenet_enabled(self):
        return self._eth_enabled
    @property
    def ip_enabled(self):
        return self._ip_enabled
    @property
    def tcp_enabled(self):
        return self._tcp_enabled
    @property
    def udp_enabled(self):
        return self._udp_enabled
    @property
    def interval(self):
        return self._interval
    @ethernet_enabled.setter
    def ethernet_enabled(self, val):
        self._ethernet_enabled = val
    @ip_enabled.setter
    def ip_enabled(self, val):
        self._ip_enabled = val
    @tcp_enabled.setter
    def tcp_enabled(self, val):
        self._tcp_enabled = val
    @udp_enabled.setter
    def udp_enabled(self, val):
        self._udp_enabled = val
    @interval.setter
    def interval(self, val):
        self._interval = val
    def recv_packet(self, data):
        """
        received ethernet packet added into NetStats
        """
        bucket = int(time.time()/self.interval)*self.interval if self.interval > 0 else 0
        if self.ethernet_enabled:
            try:
                *eth_out, proto = decode_eth(data)
                self.netstats.update([(bucket,) + tuple(sorted(eth_out))])
            except DecodeException:
                pass
        if self.ip_enabled:
            try:
                *ip_out, proto = decode_ip(data)
                self.ipstats.update([(bucket,) + tuple(sorted(ip_out))])
            except DecodeException:
                pass
        if self.udp_enabled:
            try:
                *udp_out, proto = decode_udp(data)
                self.udpstats.update([(bucket,) + tuple(sorted(udp_out))])
            except DecodeException:
                pass
        if self.tcp_enabled:
            try:
                *tcp_out, proto = decode_tcp(data)
                dst, st = self._track_tcp_session(*tcp_out)
                if dst is not None:
                    self.tcpstats.update([(bucket,) + (dst, st)])
            except DecodeException:
                pass
    def _track_tcp_session(self, src, dst, flag):
        """
        track tcp sessino status
        't', dst - timeout on tcp connection to dst
        's', dst - tcp syn to dst
        'c', dst - tcp connection established
        'f', dst - tcp connection terminated
        'p', dst - tcp push packets
        'u', dst - tcp urgent packets
        'a', dst - tcp abnormal flagged packets
        """
        find_index = lambda x,y,z: (x,y) if (x,y) in z else (y,x)
        src, dst = find_index(src, dst, self._tcp_track)
        if flag & (Tcp.syn | Tcp.ack) is Tcp.syn:
            if (src, dst) in self._tcp_track and self._tcp_track[(src, dst)] is 's':
                return dst, 't'    # timed out on connection
            elif (src, dst) not in self._tcp_track:
                self._tcp_track[(src, dst)] = 's'   # new tcp setup request
                self._session_t1[(src, dst)] = time.time()  # record the syn timestamp
                if dst not in self.session_t:
                    self.session_t[dst] = []
                return dst, 's'
        if flag & (Tcp.syn | Tcp.ack) is (Tcp.syn | Tcp.ack):
            if (src, dst) in self._tcp_track and self._tcp_track[(src, dst)] is 's':
                self._tcp_track[(src, dst)] = 'c'   # established tcp connection
                return dst, 'c'
        if flag & Tcp.ack and not (flag & (Tcp.fin | Tcp.syn | Tcp.rst)):
            if (src, dst) in self._tcp_track:
                return dst, 'n' # normal traffic
            else:
                return None, None
        if flag & Tcp.rst:
            if (src, dst) in self._tcp_track:
                del(self._tcp_track[(src, dst)])    # server reject tcp connection
                del(self._session_t1[(src, dst)])
                return dst, 'r'
        if flag & (Tcp.fin | Tcp.rst) is Tcp.fin:
            if (src, dst) in self._tcp_track:
                del(self._tcp_track[(src, dst)])  # connection termination
                self.session_t[dst].append(time.time() - self._session_t1[(src, dst)])
                del(self._session_t1[(src, dst)])   # remove the timer
                return dst, 'f'
            else:
                return None, None
        return dst, 'a'


from .decoders import decoder


def main():
    ns = NetStats()
    ns.tcp_enabled = True
    ns.interval = 10
    with sniff_sock() as s:
        for i in range(1000):
            data, addr = s.recvfrom(65535)  # receive all datas from socket
            ns.recv_packet(data)
    print(ns.tcpstats)
    print(ns.session_t)
