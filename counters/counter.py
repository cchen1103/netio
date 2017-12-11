from collections import Counter


class NetCounter(Counter):
    """
    Counters for ethernet, ip and tcp/udp packets.
    Counter does not treat src/dst directions, it only counts two end points.
    """
    def __init__(self):
        super().__init__(self)
    def update(self, args):
        """
        the input is the one of
        src_mac/dst_mac
        src_ip/dst_ip
        src_ip:port/dst_ip:port
        In the counter, we count the packages between two end points,
        regardless of the src or dst.
        """
        print(args)
        super().update([tuple(sorted(args))])


import time


period = lambda x: int(time.time()/x)*x


class TimedNetCounter(Counter):
    def __init__(self, interval=300):
        """
        interval in seconds to form the timed buckets based on unix time.
        default interval value is 300 seconds
        """
        self._interval = 300
        super().__init__(self)
    def update(self, *args):
        bucket = period(self._interval)
        super().update([(bucket) + tuple(sorted(args))]) #call the parent callable
    @property
    def interval(self):
        return self._interval
    @interval.setter
    def interval(self, val):
        self._interval = val


from ..decoders.__packet_headers__ import Tcp


def _tcp_state(src, dst, flag):
    """
    't', dst - timeout on tcp connection to dst
    's', dst - tcp syn to dst
    'c', dst - tcp connection established
    'f', dst - tcp connection terminated
    'p', dst - tcp push packets
    'u', dst - tcp urgent packets
    'a', dst - tcp abnormal flagged packets
    'n', dst - normal packets after tcp connection is established
    """
    if flag & (Tcp.syn | Tcp.ack) is Tcp.syn:
        if (src, dst) in _tcp_state.track and _tcp_state.track[(src, dst)] is Tcp.syn:
            return 't', dst    # timed out on connection
        elif (src, dst) not in _tcp_state.track:
            _tcp_state.track[(src, dst)] = 's'   # new tcp setup request
            return 's', dst
    elif flag & (Tcp.syn | Tcp.ack) is (Tcp.syn | Tcp.ack):
        if (dst, src) in _tcp_state.track and _tcp_state.track[(dst, src)] is 's':
            _tcp_state.track[(dst, src)] = 'c'   # established tcp connection
            return 'c', src
    elif flag & Tcp.ack and not (flag & (Tcp.fin | Tcp.syn)):
        if (dst, src) in _tcp_state.track:
            return 'n', src # normal traffic
        elif (src, dst) in _tcp_state.track:
            return 'n', dst # normal traffic
    elif flag & Tcp.rst:
        if (dst, src) in _tcp_state.track:
            del(_tcp_state.track[(dst, src)])    # server reject tcp connection
            return 'r', src
    elif flag & Tcp.fin:
        if (src, dst) in _tcp_state.track:
            if _tcp_state.track[(src,dst)] is 'c':
                del(_tcp_state.track[(src, dst)])  # connection termination
                return 'f', dst
            else:
                del(_tcp_state.track[(src, dst)])  # remove abnomal fin related connection
                return 'a', dst
        elif (dst, src) in _tcp_state.track:
            if self._track[(dst, src)] is 'c':
                del(_tcp_state.track[(dst, src)])   # connection termination
                return 'f', src
            else:
                del(_tcp_state.track[(dst, src)])  # remove abnomal fin related connection
                return 'a', src
    else:
        return 'a', dst  # abnormal termination



class TcpCounter(Counter):
    def __init__(self):
        self._track = dict()
        super().__init__(self)
    def update(self, src, dst, flag):
        super().update([_tcp_state(src, dst, flag)])


class TimedTcpCounter(TcpCounter):
    def __init__(self, interval=300):
        """
        interval in seconds to form the timed buckets based on unix time.
        default interval value is 300 seconds
        """
        self._interval = 300
        super().__init__(self)
    def update(self, src, dst, flag):
        bucket = period(self._interval)
        super().update([(bucket) + _tcp_state(src, dst, flag)])


class TcpTimer():
    def __init__(self):
        self.track_t = dict()
        self.session_t = dict()
    def update(self, src, dst, flag):
        st, svr = _tcp_state(src, dst, flag)
        if st is 'c':
            self.track_t[(src, dst)] = time.time()
        elif st is 'f' and (src, dst) in self.track_t:
            self.session_t[svr].append(time.time() - track_t[(src, dst)])
            del(self.track_t[(src, dst)])
