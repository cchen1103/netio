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


from .counters import counter
from .decoders import decoder


def main():
    nc = counter.NetCounter()
    tnc = counter.TimedNetCounter()
    tc = counter.TcpCounter()
    ttc = counter.TimedTcpCounter(30)
    st = counter.TcpTimer()
    with sniff_sock() as s:
        tnc.interval = 10
        for i in range(1000):
            data, addr = s.recvfrom(65535)  # receive all datas from socket
            try:
                *eth_out, proto = decoder.decode_eth(data)
                nc.update(*eth_out)
                tnc.update(*eth_out)
            except decoder.DecodeException:
                pass
            try:
                *ip_out, proto = decoder.decode_ip(data)
                nc.update(*ip_out)
                tnc.update(*ip_out)
            except decoder.DecodeException:
                pass
            try:
                *tcp_out, proto = decoder.decode_tcp(data)
                nc.update(*tcp_out[:-1])
                tnc.update(*tcp_out[:-1])
                tc.update(*tcp_out)
                ttc.update(*tcp_out)
            except decoder.DecodeException:
                pass
            try:
                *udp_out, proto = decoder.decode_udp(data)
                nc.update(*udp_out)
                tnc.update(*udp_out)
            except decoder.DecodeException:
                pass
    #print(counter.ethernet_timed_counter.timed_counters)
    #print(counter.ip_timed_counter.timed_counters)
    #print(counter.tcp_timed_counter.timed_counters)
    #print(counter.udp_timed_counter.timed_counters)
    print(nc)
    print(tnc)
    for i in tc:
        print(i, tc[i])
    print(ttc)
