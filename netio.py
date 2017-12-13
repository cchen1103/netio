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
from .decoders.decoder import *
from collections import Counter
import time


class NetStats:
    def __init__(self):
        self._interval = 0          # default no timestamp bucket
        self._ethernet_enabled = False
        self._ip_enabled = False
        self._tcp_enabled = False
        self._udp_enabled = False
        self.netstats = Counter()
        self.ipstats = Counter()
        self.udpstats = Counter()
        self.tcpstats = Counter()
        self.session_t = dict()     # tcp session time
        self._tcp_track = dict()    # internal tracking tcp connection status
    @property
    def ethernet_enabled(self):
        return self._ethernet_enabled
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
        """
        set boolean value.

        input: True/False. If true, ethernet frame stats will be collected
        """
        self._ethernet_enabled = val
    @ip_enabled.setter
    def ip_enabled(self, val):
        """
        set boolean value.

        input: True/False. If true, ip packets stats will be collected
        """
        self._ip_enabled = val
    @tcp_enabled.setter
    def tcp_enabled(self, val):
        """
        set boolean value.

        input: True/False. If true, tcp connection status will be collected
        """
        self._tcp_enabled = val
    @udp_enabled.setter
    def udp_enabled(self, val):
        """
        set boolean value.

        input: True/False. If true, udp frame stats will be collected
        """
        self._udp_enabled = val
    @interval.setter
    def interval(self, val):
        """
        input: positive integer. If none zero, stats will be collected in the bucket of time intervals (in seconds)
        """
        if val < 0 or not isinstance(val, int):
            raise ValueError("interval must be non-negative integer")
        self._interval = val
    def recv_packet(self, data):
        """
        received ethernet packet added into NetStats
        """
        bucket = int(time.time()/self.interval)*self.interval if self.interval > 0 else 0   # calculate bucket
        if self.ethernet_enabled:   # ethernet counter
            try:
                *eth_out, proto = decode_eth(data)
                self.netstats.update([(bucket,) + tuple(sorted(eth_out))])
            except DecodeException:
                pass
        if self.ip_enabled: # ip counter
            try:
                *ip_out, proto = decode_ip(data)
                self.ipstats.update([(bucket,) + tuple(sorted(ip_out))])
            except DecodeException:
                pass
        if self.udp_enabled:    # udp counter
            try:
                *udp_out, proto = decode_udp(data)
                self.udpstats.update([(bucket,) + tuple(sorted(udp_out))])
            except DecodeException:
                pass
        if self.tcp_enabled:    # tcp stats
            try:
                *tcp_out, proto = decode_tcp(data)
                dst, st = self._track_tcp_session(*tcp_out) # get tcp status on the destination connection
                if dst is not None: # only add to counter if a valid status is returned
                    self.tcpstats.update([(bucket,) + (dst, st)])
            except DecodeException:
                pass
    def _track_tcp_session(self, src, dst, flag):
        """
        track tcp session status

        input:
        src - source connection of ip:port (return value from decode_tcp)
        dst - destination of ip:dst_port (return value from decode_tcp)
        flag - tcp flag (return value from decode_tcp)

        output:
        dst - server ip:port
        st  - tcp connection status, status value is described as below:
            't', dst - timeout on tcp connection to dst
            's', dst - tcp syn to dst
            'c', dst - tcp connection established
            'f', dst - tcp connection terminated
            'p', dst - tcp push packets
            'u', dst - tcp urgent packets
            'a', dst - tcp abnormal flagged packets
        """
        # find_index, look up in dict, return the swapped order if found in dict, otherwisr, return orignal input order
        find_index = lambda x,y,z: (y,x) if (y,x) in z else (x,y)
        src, dst = find_index(src, dst, self._tcp_track)
        if flag & (Tcp.syn | Tcp.ack) is Tcp.syn:   # syn flag
            if (src, dst) not in self._tcp_track:   # new syn state
                self._tcp_track[(src, dst)] = ['s', time.time()]    # update syn state and record the syn timestamp
                return dst, 's'
            elif self._tcp_track[(src, dst)] is 's':   # already have syn, this is re-send
                return dst, 't'    # timed out on connection
        if flag & (Tcp.syn | Tcp.ack) is (Tcp.syn | Tcp.ack):   # syn/ack flag
            if (src, dst) in self._tcp_track and self._tcp_track[(src, dst)][0] is 's':
                self._tcp_track[(src, dst)][0] = 'c'   # established tcp connection
                return dst, 'c'
        if flag & Tcp.ack and not (flag & (Tcp.fin | Tcp.syn | Tcp.rst)):   # regular ack
            if (src, dst) in self._tcp_track:
                return dst, 'n' # normal traffic
            else:
                return None, None   # tcp connection not found, return none,none for invalid status
        if flag & Tcp.rst:  # rst flag
            if (src, dst) in self._tcp_track:
                del(self._tcp_track[(src, dst)])    # server reject tcp connection
                return dst, 'r'
        if flag & (Tcp.fin | Tcp.rst) is Tcp.fin:   # fin flag
            if (src, dst) in self._tcp_track:
                del(self._tcp_track[(src, dst)])  # connection termination
                t = time.time() - self._tcp_track[(src, dst)][1]
                self.session_t[dst] = self.session_t[dst] + [t] if dst in self.session_t else t
                return dst, 'f'
            else:
                return None, None
        return dst, 'a'


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
