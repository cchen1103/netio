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

def header(data):
    """
    decode ethernet headers to ethernet, ip and tcp/udp attributes
    return protocol and its attributes
    """
    split2 = lambda x,y: (x[:y], x[y:])

    decoders = {
        Header.ETHERNET: decoder.decode_eth,
        Header.IP: decoder.decode_ip,
        Header.TCP: decoder.decode_tcp,
        Header.UDP: decoder.decode_udp,
        }
    proto = Header.ETHERNET
    attributes = list()
    while proto in decoders:
        protocol = proto    # update protocol if there is more decoding
        attr, proto, data = decoders[proto](data)
        attributes = attributes + list(attr)
    return protocol, tuple(attributes)
    
