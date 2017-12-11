import socket
from struct import unpack
from functools import lru_cache, wraps
from .__packet_headers__ import Ethernet, Ip, Tcp, Udp


class DecodeException(Exception):
    def __init__(self, dErrorMessage):
        Exception.__init__(self, "Packets decoder error {0}".format(dErrorMessage))
        self.dErrorMessage = dErrorMessage


split2 = lambda x, y: (x[:y], x[y:])


@lru_cache(maxsize=512)
def decode_eth(header):
    """
    can decode MAC address and upper level protocol
    for efficency, do not decode them (dest MAC, src MAC, protocol).

    input:  ethenet header (14 bytes array)
    return: src_mac, dst_mac, next_protocol
    """
    if len(header) < Ethernet.h_len:
        raise DecodeException('Ethernet header lenth error: (%d)' % len(header))
    eth_header = unpack('!6s6sH', header[:Ethernet.h_len])
    next_proto = socket.ntohs(eth_header[2])
    mac_addr = lambda x: "%.2x" % x
    src_mac = ':'.join(map(mac_addr,eth_header[0]))
    dst_mac = ':'.join(map(mac_addr,eth_header[1]))
    return src_mac, dst_mac, next_proto


@lru_cache(maxsize=512)
def _decode_ip_addr(data):
    """
    decode ip header with lru cache to speed up process

    input:  bytes array for IP v4 header of src address and dst address (8 bytes)
    return: src_ip, dst_ip
    """
    return socket.inet_ntoa(data[0]), socket.inet_ntoa(data[1])


def decode_ip(header):
    """
    decode ip headers

    input:  ethernet header + ip header
    return: src_ip, dst_ip, next_protocol
    """
    ethenet_frame, ip_frame = split2(header, Ethernet.h_len)# ethernet header - 14 bytes
    eth, proto = decode_eth(ethenet_frame)    # decode ethernet frame first
    if proto != Ip.proto:
        raise DecodeException('Not IP packet, protocol number: (%d)' % proto)
    if len(ip_frame) < 20:
        raise DecodeException('IP header length error: (%d)' % len(ip_frame))
    ip_header = unpack('!BBHHHBBH4s4s', ip_frame[:Ip.h_len]) # currently only work on ipv4
    #version = ip_header[0] >> 4    # not IP version is not used at this point
    next_proto = ip_header[6]
    src_ip, dst_ip = decode_ip_addr(ip_header[-2:])
    return src_ip, dst_ip, next_proto


def decode_tcp(header):
    """
    decode tcp packet header including flag

    input:  bytes array of tcp header (20 bytes)
    return: src_ip:port, dst_ip:port, flag, next_protocol
    """
    ip_h_len = (header[Ethernet.h_len] & 0xf) * 4 # ip header first byte high 4 bits * 4 are the IP header length
    ip_frame, tcp_frame = split2(header, Ethernet.h_len + ip_h_len)# ethernet header + ip header length
    ip_src, ip_dst, proto = decode_ip(ip_frame)    # decode ethernet frame first
    if proto != Tcp.protocol:
        raise DecodeException('Not TCP packet, protocol number: (%d)' % proto)
    if len(tcp_frame) < Tcp.h_len:
        raise DecodeException('TCP header length error: (%d)' % len(tcp_frame))
    tcp_header = unpack('!HHLLBBHHH', tcp_frame[:Tcp.h_len])
    next_proto = None   # no next protocol to relay on to decode
    src_port = ':'.join([ip_src, tcp_header[0]])
    dst_port = ':'.join([ip_dst, tcp_header[1]])
    flag = tcp_header[5]
    return src_port, dst_port, flag, next_proto


def decode_udp(header):
    """
    decode udp header

    input:  bytes array of udp header (8 bytes)
    return: src_ip:port, dst_ip:port, next_protocol
    """
    ip_h_len = (header[Ethernet.h_len] & 0xf) * 4 # ip header first byte high 4 bits * 4 are the IP header length
    ip_frame, udp_frame = split2(header, Ethernet.h_len + ip_h_len)# ethernet header + ip header length
    src_ip, dst_ip, proto = decode_ip(ip_frame)    # decode ethernet frame first
    if proto != Udp.protocol:
        raise DecodeException('Not UDP packet, protocol number: (%d)' % proto)
    if len(udp_frame) < Udp.h_len:
        raise DecodeException('UDP header length error: (%d)' % len(udp_frame))
    udp_header = unpack('!HHHH', udp_frame[:Udp.h_len])
    next_proto = None  # no next protocol to relay on to decode
    src_port = ':'.join([src_ip, udp_header[0]])
    dst_port = ':'.join([dst_ip, udp_header[1]])
    return src_port, dst_port, next_proto
