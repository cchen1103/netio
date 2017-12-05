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
        tcp_conn = conn[:4] + ('*',) + conn[5:6]
        if tcp_flag & (Tcp.syn | Tcp.ack) == Tcp.syn:  # syn only
            if conn in  conn_track:
                if conn_track[conn] == 's':
                    del conn_track[conn]
                    return tcp_conn + ('t',) # time out
                else:
                    del conn_track[conn]
                    return tcp_conn + ('a1',) #  abnormal connection
            conn_track[conn] = 's'
            return tcp_conn + ('s',) # setup connection
        if tcp_flag & (Tcp.syn | Tcp.ack) == Tcp.syn | Tcp.ack: # syn and ack
            conn = (conn[1],conn[0],conn[3],conn[2],conn[5],conn[4])
            if conn in conn_track:
                if conn_track[conn] == 's':
                    conn_track[conn] = 'c'
                    return conn[:4] + ('*',) + conn[5:6] + ('c',)
                else:
                    del conn_track[conn]
            return conn[:4] + ('*',) + conn[5:6] + ('a2',)
        if tcp_flag & Tcp.rst:    # rst
            conn = (conn[1],conn[0],conn[3],conn[2],conn[5],conn[4])
            if conn in conn_track:
                del conn_track[conn]
            return conn[:4] + ('*',) + conn[5:6] + ('r',)
        if tcp_flag & Tcp.fin:  # fin
            if conn in conn_track:
                del conn_track[conn]
                return tcp_conn + ('f',)
            else:
                conn = (conn[1],conn[0],conn[3],conn[2],conn[5],conn[4])
                if conn in conn_track:
                    del conn_track[conn]
                    return conn[:4] + ('*',) + conn[5:6] + ('r',)
    return inner


from ..counters import counter
from ..decoders import decoder


@counter.AttrCounter
@counter._filter_decode_output
@session
def tcp_conn_counter(data):
    return decoder.decode_tcp(data)
