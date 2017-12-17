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
from collections import Counter, deque
import time
import re


class NetStats:
    def __init__(self):
        self._ethernet_enabled = False
        self._ip_enabled = False
        self._tcp_enabled = False
        self._udp_enabled = False
        self._max_session_sample = None   # number of tcp session time reacord stored
        self.netstats = Counter()
        self.ipstats = Counter()
        self.udpstats = Counter()
        self.tcpstats = Counter()
        self.session_t = dict()     # tcp session time
        self._tcp_track = dict()    # internal tracking tcp connection status
        self.addr_filter = []    # list of filter by address (ip or ip:port)
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
    def max_tcp_session_t(self):
        return self._max_session_sample
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
    @max_tcp_session_t.setter
    def max_tcp_session_t(self, val):
        """
        set deque for holding number of tcp rr time

        input: integer, number of sample would module to hold for tcp rr time. None for unbound
        """
        self._max_session_sample = val
    def add_filter(self, *data):
        """
        input:  string of ip port or ip:port.
                - all ip for specific port, use ':port'
                - ip and port, use 'ip:port'
                - ip only, only 'ip'
        """
        for f in data:
            if f not in self.addr_filter:
                self.addr_filter.append(f)
    def remove_filter(self, *data):
        for f in data:
            if f in self.addr_filter:
                del(self.addr_filter[f])
    def _filer_addr(self, src):
        for f in self.addr_filter:
            f="^" + f +"$" if not f.startswith(':') else f + "$"
            for a in src:
                if re.search(f, a):
                    return True
        return False
    def recv_packet(self, data):
        """
        received ethernet packet added into NetStats
        """
        if self.ethernet_enabled:   # ethernet counter
            try:
                *eth_out, proto = decode_eth(data)
                if self._filer_addr(eth_out):
                    self.netstats.update([tuple(sorted(eth_out))])
            except DecodeException:
                pass
        if self.ip_enabled: # ip counter
            try:
                *ip_out, proto = decode_ip(data)
                if self._filer_addr(ip_out):
                    self.ipstats.update([tuple(sorted(ip_out))])
            except DecodeException:
                pass
        if self.udp_enabled:    # udp counter
            try:
                *udp_out, proto = decode_udp(data)
                if self._filer_addr(udp_out):
                    self.udpstats.update([tuple(sorted(udp_out))])
            except DecodeException:
                pass
        if self.tcp_enabled:    # tcp stats
            try:
                *tcp_out, proto = decode_tcp(data)
                if self._filer_addr(tcp_out[:2]):
                    dst, st = self._track_tcp_session(*tcp_out) # get tcp status on the destination connection
                    if dst is not None: # only add to counter if a valid status is returned
                        self.tcpstats.update([(dst, st)])
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
                t = time.time() - self._tcp_track[(src, dst)][1]
                if dst in self.session_t:
                    self.session_t[dst].append(t)
                else:
                    self.session_t[dst] = deque([t], self._max_session_sample)
                del(self._tcp_track[(src, dst)])  # connection termination
                return dst, 'f'
            else:
                return None, None
        return dst, 'a'


def main():
    ns = NetStats()
    ns.tcp_enabled = True
    ns.add_filter(':9000',':80')
    interval = 10
    with sniff_sock() as s:
        for i in range(1000):
            bucket = int(time.time()/interval)*interval if interval > 0 else 0   # calculate bucket
            data, addr = s.recvfrom(65535)  # receive all datas from socket
            ns.recv_packet(data)
    print(ns.tcpstats)
    print(ns.session_t)
