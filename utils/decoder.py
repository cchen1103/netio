import socket
from struct import unpack
from functools import lru_cache
from netio.utils.header import Header

def decode_eth(header):
    """
    can decode MAC address and upper level protocol
    for efficency, do not decode them (dest MAC, src MAC, protocol).
    """
    eth_header = unpack('!6s6sH', header)
    protocol = socket.ntohs(eth_header[2])
    return Header.IP if protocol == Header.IP else Header.ETHERNET   # ip packet

def decode_ip(header):
    """
    decode ip headers
    """
    ip_header = unpack('!BBHHHBBH4s4s', header[:20]) # currently only work on ipv4
    version = ip_header[0] >> 4
    protocol = ip_header[6]
    s_addr, d_addr = _decode_ip_addr(header[-8:])
    return protocol, s_addr, d_addr, version

@lru_cache(maxsize=512)
def _decode_ip_addr(header):
    """
    decode ip header with only src, dst, protocol and version fields
    """
    address = unpack('!4s4s', header) # currently only work on ipv4
    return socket.inet_ntoa(address[0]), socket.inet_ntoa(address[1])
