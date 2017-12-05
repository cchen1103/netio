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
from .extension import tcp


def main():
    with sniff_sock() as s:
        counter.ethernet_timed_counter.interval = 10
        counter.ip_timed_counter.interval = 10
        counter.tcp_timed_counter.interval = 10
        counter.udp_timed_counter.interval = 10
        tcp.tcp_timed_conn_counter.interval = 30
        for i in range(1000):
            data, addr = s.recvfrom(65535)  # receive all datas from socket
            counter.ethernet_timed_counter(data)
            counter.ip_timed_counter(data)
            counter.tcp_timed_counter(data)
            counter.udp_timed_counter(data)
            tcp.tcp_conn_counter(data)
            tcp.tcp_timed_conn_counter(data)
    #print(counter.ethernet_timed_counter.timed_counters)
    #print(counter.ip_timed_counter.timed_counters)
    #print(counter.tcp_timed_counter.timed_counters)
    #print(counter.udp_timed_counter.timed_counters)
    print(tcp.tcp_conn_counter.counters)
    print(tcp.tcp_timed_conn_counter.counters)
