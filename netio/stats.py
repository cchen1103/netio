from collections import Counter
from .decoders.decoder import decode_eth, decode_ip, decode_udp, decode_tcp, DecodeException


def _tcp_udp_conn(src, dst):
    if src.split(':')[1] < dst.split(':')[1]:
        src, dst = dst, src
    src = src.split(':')[0]
    return src, dst


class _Stats:
    def __init__(self, decoder):
        self.src_count = Counter()
        self.dst_count = Counter()
        self.decoder = decoder
    def __call__(self, data):
        try:
            src, dst, *rest = self.decoder(data)
            self.src_count.update([src])
            self.dst_count.update([dst])
        except DecodeException:
            pass
    def reset(self):
        self.src_count.clear()
        self.dst_count.clear()


class EthStats(_Stats):
    def __init__(self):
        super().__init__(decode_eth)


class IpStats(_Stats):
    def __init__(self):
        super().__init__(decode_ip)


class UdpStats(_Stats):
    def __init__(self):
        super().__init__(decode_udp)
    def __call__(self, data):
        try:
            src, dst, *rest = self.decoder(data)
            src, dst = _tcp_udp_conn(src, dst)
            self.src_count.update([src])
            self.dst_count.update([dst])
        except DecodeException:
            pass


class TcpStats(_Stats):
    def __init__(self):
        super().__init__(decode_tcp)
    def __call__(self, data):
        try:
            src, dst, *rest = self.decoder(data)
            src, dst = _tcp_udp_conn(src, dst)
            self.src_count.update([src])
            self.dst_count.update([dst])
        except DecodeException:
            pass


class TcpSessionStats(TcpStats):
    def __call__(self, data):
        try:
            src, dst, flag, *rest = self.decoder(data)
            self.src_count.update([src])
            self.dst_count.update([dst])
        except DecodeException:
            pass
