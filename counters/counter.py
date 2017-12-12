from collections import Counter


class NetCounter(Counter):
    """
    Counters for ethernet, ip and tcp/udp packets.
    Counter does not treat src/dst directions, it only counts two end points.
    """
    def __init__(self):
        pass
    def update(self, src, dst):
        """
        the input is the one of
        src_mac/dst_mac
        src_ip/dst_ip
        src_ip:port/dst_ip:port
        In the counter, we count the packages between two end points,
        regardless of the src or dst.
        """
        super().update([tuple(sorted([src, dst]))])


import time


period = lambda x: int(time.time()/x)*x


class TimedNetCounter(Counter):
    def __init__(self, interval=300):
        """
        interval in seconds to form the timed buckets based on unix time.
        default interval value is 300 seconds
        """
        self._interval = 300
    def update(self, src, dst):
        bucket = period(self._interval)
        super().update([(bucket,) + tuple(sorted([src, dst]))])
    @property
    def interval(self):
        return self._interval
    @interval.setter
    def interval(self, val):
        self._interval = val


from ..decoders.__packet_headers__ import Tcp


class TcpCounter(Counter):
    def __init__(self):
        self._track = dict()
    def update(self, con, st):
        super().update([(con, st)])


class TimedTcpCounter(Counter):
    def __init__(self, interval=300):
        """
        interval in seconds to form the timed buckets based on unix time.
        default interval value is 300 seconds
        """
        self._interval = 300
    def update(self, con, st):
        bucket = period(self._interval)
        super().update([(bucket,) + (con, st)])


class TcpTimer:
    def __init__(self):
        self.track_t = dict()
        self.session_t = dict()
    def update(self, con, st):
        if st is 'c':
            self.track_t[(src, dst)] = time.time()
        elif st is 'f' and (src, dst) in self.track_t:
            if svr in self.session_t:
                self.session_t[svr].append(time.time() - self.track_t[(src, dst)])
            else:
                self.session_t[svr] = [time.time() - self.track_t[(src, dst)]]
            del(self.track_t[(src, dst)])
