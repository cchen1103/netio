from collections import Counter
from .decoders.decoder import *


class _Stats:
    def __init__(self, decoder):
        self.src_count = Counter()
        self.dst_count = Counter()
        self.decoder = decoder
    def __call__(self, data):
        try:
            src, dst, proto = self.decoder(data)
            self.src_count.update(src)
            self.dst_count.update(dst)
        except DecodeException:
            pass
    def reset(self):
        self.src_count.clear()
        self.dst_count.clear()
    def abs_src_stats(self):
        return dict(self.src_count.most_common())
    def abs_dst_stats(self):
        return dict(self.dst_count.most_common())
    def abs_stats(self):
        return dict((self.src_count + self.dst_count).most_common())


class Ethstats(_Stats):
    def __init__(self):
        super().__init__(decode_eth)


class Ipstats(_Stats):
    def __init__(self):
        super().__init__(decode_ip)


class Udpstats(_Stats):
    def __init__(self):
        super().__init__(decode_udp)


class Tcpstats(_Stats):
    def __init__(self):
        super().__init__(decode_tcp)
