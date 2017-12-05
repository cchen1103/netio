from functools import wraps
from ..decoders.__packet_headers__ import Tcp


def session(func):
    conn_track = dict()
    @wraps(func)
    def inner(*args, **kwargs):
        """
        return tcp attributes with additional flag:

        s - syn to estblish tcp connection
        a - abnormal tcp connection ( interrupt 3 way hand shakes)
        t - time out on syn setup
        c - connection established
        r - connection reset or reject
        f - connection finished
        None - other finish hadshake or regular tcp ack packages
        """
        attrs = func(*args, **kwargs)   # tcp has the last attribute as tcp flag
        conn, tcp_flag = attrs[:-1], attrs[-1]
        if tcp_flag & (Tcp.syn | Tcp.ack) == Tcp.syn:  # syn only
            if conn in  conn_track:
                if conn_track[conn] == 's':
                    del conn_track[conn]
                    return conn + ('t',) # time out
                else:
                    del conn_track[conn]
                    return conn + ('a',) #  abnormal connection
            conn_track[conn] = 's'
            return conn + ('s',) # setup connection
        if tcp_flag & (Tcp.syn | Tcp.ack) == Tcp.syn | Tcp.ack: # syn and ack
            if conn in conn_track:
                if conn_track[conn] == 's':
                    conn_track[conn] = 'c'
                    return conn + ('c',)
            del conn_track[conn]
            return attrs[:-1] + ('a',)
        if tcp_flag & Tcp.rst:    # rst
            del conn_track[conn]
            return attrs[:-1] + ('r',)
        if tcp_flag & Tcp.fin:  # fin
            if conn in conn_track:
                del conn_track[conn]
                return attrs[:-1] + ('f',)
    return inner


from ..counters import counter
from ..decoders import decoder


@counter.AttrCounter
@counter._filter_decode_output
@session
def tcp_conn_counter(data):
    return decoder.decode_tcp(data)
