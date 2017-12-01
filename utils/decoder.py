import socket
from struct import unpack
from functools import lru_cache
from netio.utils.header import Header

def decode_eth(data):
    """
    can decode MAC address and upper level protocol
    for efficency, do not decode them (dest MAC, src MAC, protocol).
    """
    mac_addr = lambda x: "%.2x" % (ord(x))
    header, data = data[:14], data[14:] # ethernet header - 14 bytes
    eth_header = unpack('!6s6sH', header)
    protocol = socket.ntohs(eth_header[2])
    attributes = (':'.join(map(mac_addr,eth_header[0])), ':'.join(map(mac_addr,eth_header[1])))
    return attributes, protocol, data

def decode_ip(data):
    """
    decode ip headers
    """
    length = (data[0] & 0xf) * 4
    header, data = data[:length], data[length:]
    ip_header = unpack('!BBHHHBBH4s4s', header[:20]) # currently only work on ipv4
    version = ip_header[0] >> 4
    protocol = ip_header[6]
    ip_src, ip_dst = _decode_ip_addr(ip_header[-2])
    attributes = (version, ip_src, ip_dst)
    return attributes, protocol, data

@lru_cache(maxsize=512)
def _decode_ip_addr(header):
    """
    decode ip header with only src, dst, protocol and version fields
    """
    return socket.inet_ntoa(header[0]), socket.inet_ntoa(header[1])

def decode_tcp(data):
    """
    decode tcp packet header including flag
    """
    header, data = data[:20], data[20:]
    tcp_header = unpack('!HHLLBBHHH', header)
    protocol = None
    src_p, dst_p, flag = tcp_header[0], tcp_header[1], tcp_header[5] & 0x3f
    return (src_p, dst_p, flag), protocol, data

def decode_udp(data):
    """
    decode udp header
    """
    header, data = data[:8], data[8:]
    udp_header = unpack('!HHHH', header)
    protocol = None
    src_p, dst_p = udp_header[0], udp_header[1]
    return (src_p, dst_p), protocol, data
