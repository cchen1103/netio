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
            nc.update(decoder_eth(data))
            nc.update(decoder_ip(data))
            nc.update(decoder_tcp(data))
            nc.update(decoder_udp(data))
            tnc.update(decoder_eth(data))
            tnc.update(decoder_ip(data))
            tnc.update(decoder_tcp(data))
            tnc.update(decoder_udp(data))
            tc.update(decoder_tcp(data))
            ttc.update(decoder_tcp(data))
    #print(counter.ethernet_timed_counter.timed_counters)
    #print(counter.ip_timed_counter.timed_counters)
    #print(counter.tcp_timed_counter.timed_counters)
    #print(counter.udp_timed_counter.timed_counters)
    print(nc)
    print(tnc)
    print(tc)
    print(ttc)
