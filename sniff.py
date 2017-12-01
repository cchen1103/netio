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
        self.s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        return self.s

    def __exit__(self, type, value, traceback):
        """
        destroy the socket and free all resources
        """
        if self.s != None:
            self.s.close()


import struct
from netio.utils.header import Header
from netio.utils import decoder

ETHER_H_LEN = 14

class packet_header:
    """
    decode ethernet data into ethernet, ip, and tcp/udp headers,
    payload will be discard.
    """
    def __init__(self):
        self.protocol = Header.ETHERNET

    def __call__(self, data):
        """
        decode data into tcp or udp headers
        """
        split2 = lambda x,y: (x[:y], x[y:])
        eth_h, data = split2(data, ETHER_H_LEN)
        self.protocol = decoder.decode_eth(eth_h)    # decode ethenet
        if self.protocol == Header.IP:
            ip_h, data = split2(data, (data[0] & 0xF) * 4)
            self.protocol, self.src, self.dst, self.ip_ver = decoder.decode_ip(ip_h)
        if self.protocol == Header.TCP:
            pass
        if self.protocol == Header.UDP:
            pass


def tick(proto, address):
    pass
