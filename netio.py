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
        if self.s != None:
            self.s.close()


from .decoders import decoder


def main():
    with sniff_sock() as s:
        while True:
            data, addr = s.recvfrom(65535)  # receive all datas from socket
            try:
                decoder.decode_eth(data)
            except decoder.DecodeException:
                pass
            try:
                decoder.decode_ip(data)
            except decoder.DecodeException:
                pass
            try:
                decoder.decode_tcp(data)
            except decoder.DecodeException:
                pass
            try:
                decoder.decode_udp(data)
            except decoder.DecodeException:
                pass
