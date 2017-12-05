from functools import wraps
from ..decoders.__packet_headers__ import Tcp


def _swap_addr(addr):
    src_ip,dst_ip,src_port,dst_port = addr
    return (dst_ip,src_ip,dst_port,src_port)


def _mask_port(addr):
    src_ip,dst_ip,src_port,dst_port = addr
    return (src_ip, dst_ip, '*', dst_port)


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
        conn, tcp_flag = attrs[2:-1], attrs[-1] # take out first 2 items of mac addr
        if tcp_flag & (Tcp.syn | Tcp.ack) == Tcp.syn:  # syn only
            if conn in  conn_track:
                if conn_track[conn] == 's':
                    del conn_track[conn]
                    return _mask_port(conn) + ('t',) # time out
                else:
                    del conn_track[conn]
                    return _mask_port(conn) + ('a',) #  abnormal connection
            conn_track[conn] = 's'
            return _mask_port(conn) + ('s',) # setup connection
        if tcp_flag & (Tcp.syn | Tcp.ack) == Tcp.syn | Tcp.ack: # syn and ack
            conn = _swap_addr(conn)
            if conn in conn_track:
                if conn_track[conn] == 's':
                    conn_track[conn] = 'c'
                    return _mask_port(conn) + ('c',)
                else:
                    del conn_track[conn]
            return _mask_port(conn) + ('a',)
        if tcp_flag & Tcp.rst:    # rst
            conn = _swap_addr(conn)
            if conn in conn_track:
                del conn_track[conn]
            return _mask_port(conn) + ('r',)
        if tcp_flag & Tcp.fin:  # fin
            if conn in conn_track:
                del conn_track[conn]
                return _mask_port(conn) + ('f',)
            else:
                conn = _swap_addr(conn)
                if conn in conn_track:
                    del conn_track[conn]
                    return _mask_port(conn) + ('f',)
    return inner


from ..counters import counter
from ..decoders import decoder


@counter.AttrCounter
@counter._filter_decode_output
@session
def tcp_conn_counter(data):
    return decoder.decode_tcp(data)
