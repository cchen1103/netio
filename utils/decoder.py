import socket
from struct import unpack
from functools import lru_cache, wraps
from netio.utils import headers


class DecodeException(Exception):
    def __init__(self, dErrorMessage):
        Exception.__init__(self, "Packets decoder error {0}".format(dErrorMessage))
        self.dErrorMessage = dErrorMessage


def attribute_only(func):
    """
    wraps to return only packet decoder attributes and cut of net next_protocol
    """
    @wraps(func)
    def inner(*args, **kwargs):
        attr, next_proto = func(*args, **kwargs)
        return attr
    return inner


split2 = lambda x, y: (x[:y], x[y:])


@lru_cache(maxsize=512)
def _decode_eth(header):
    """
    can decode MAC address and upper level protocol
    for efficency, do not decode them (dest MAC, src MAC, protocol).

    input:  ethenet header (14 bytes array)
    return: (src_mac, dst_mac), next_protocol
    """
    if len(header) != 14:
        raise DecodeException('Ethernet header lenth error: (%d)' % len(header))

    eth_header = unpack('!6s6sH', header)
    next_proto = socket.ntohs(eth_header[2])
    mac_addr = lambda x: "%.2x" % x
    attributes = (':'.join(map(mac_addr,eth_header[0])), ':'.join(map(mac_addr,eth_header[1])))

    return attributes, next_proto


@attribute_only
def decode_eth(header):
    """
    run _decode_eth

    input:  ethenet header (14 bytes array)
    return: src_mac, dst_mac
    """

    return _decode_eth(header)


def _decode_ip(header):
    """
    decode ip headers

    input:  ethernet header + ip header
    return: (src_mac, dst_mac, src_ip, dst_ip), next_protocol
    """
    ethenet_frame, ip_frame = split2(header, 14)# ethernet header - 14 bytes
    attributes, protocol = _decode_eth(ethenet_frame)    # decode ethernet frame first

    if protocol != headers.IP:
        raise DecodeException('Not IP packet, protocol number: (%d)' % protocol)
    if len(ip_frame) < 20:
        raise DecodeException('IP header length error: (%d)' % len(ip_frame))

    ip_header = unpack('!BBHHHBBH4s4s', ip_frame[:20]) # currently only work on ipv4
    #version = ip_header[0] >> 4    # not IP version is not used at this point
    next_proto = ip_header[6]
    attributes = attributes + _decode_ip(ip_header[-2:])

    return attributes, next_proto


@attribute_only
def decode_ip(header):
    """
    run _decode_ip

    input:  ethernet header + ip header
    return: src_mac, dst_mac, src_ip, dst_ip
    """

    return _decode_ip(header)


@lru_cache(maxsize=512)
def _decode_ip_(data):
    """
    decode ip header with lru cache to speed up process

    input:  bytes array for IP v4 header of src address and dst address (8 bytes)
    return: src_ip, dst_ip
    """

    return socket.inet_ntoa(data[0]), socket.inet_ntoa(data[1])


def decode_tcp(header):
    """
    decode tcp packet header including flag

    input:  bytes array of tcp header (20 bytes)
    return: src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, flag
    """
    ip_h_len = (header[14] & 0xf) * 4 # ip header first byte high 4 bits * 4 are the IP header length
    ip_frame, tcp_frame = split2(header, 14 + ip_h_len)# ethernet header + ip header length
    attributes, protocol = decode_ip(ip_frame)    # decode ethernet frame first

    if protocol != headers.TCP:
        raise DecodeException('Not TCP packet, protocol number: (%d)' % protocol)
    if len(tcp_frame) < 20:
        raise DecodeException('TCP header length error: (%d)' % len(tcp_frame))

    tcp_header = unpack('!HHLLBBHHH', tcp_frame)
    #next_proto = None   # no next protocol to relay on to decode
    attributes = attributes + (tcp_header[0], tcp_header[1], tcp_header[5] & 0x3f)

    return attributes


def decode_udp(header):
    """
    decode udp header

    input:  bytes array of udp header (8 bytes)
    return: src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port
    """
    ip_h_len = (header[14] & 0xf) * 4 # ip header first byte high 4 bits * 4 are the IP header length
    ip_frame, udp_frame = split2(header, 14 + ip_h_len)# ethernet header + ip header length
    attributes, protocol = decode_ip(ip_frame)    # decode ethernet frame first

    if protocol != headers.UDP:
        raise DecodeException('Not UDP packet, protocol number: (%d)' % protocol)
    if len(tcp_frame) < 8:
        raise DecodeException('UDP header length error: (%d)' % len(udp_frame))

    udp_header = unpack('!HHHH', udp_frame)
    #next_proto = None  # no next protocol to relay on to decode
    attributes = attributes + (udp_header[0], udp_header[1])
    
    return attributes
