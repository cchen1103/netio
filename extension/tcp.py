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
        st = None    # default status of connection is None
        if tcp_flag & (Tcp.syn | Tcp.ack) == Tcp.syn:  # syn only
            if conn in  conn_track:
                st = 't' if conn_track[conn] == 's' else 'a'    # time out on syn for mutiple syn othewise abnormal
            else:   # syn
                st = 's'
                conn_track[conn] = 's'
        if tcp_flag & (Tcp.syn | Tcp.ack) == Tcp.syn | Tcp.ack: # syn and ack
            conn = _swap_addr(conn)
            st = 'c' if conn in conn_track and conn_track[conn] == 's' else 'a'  # tcp connection established on syn/ack
        if tcp_flag & Tcp.rst:    # rst
            conn = _swap_addr(conn)
            st = 'r' if conn in conn_track else 'a'    # reject
            if st == 'r':
                del conn_track[conn]
        if tcp_flag & Tcp.fin:  # fin
            st = 'f' if conn in conn_track or _swap_addr(conn) in conn_track else None
            if st == 'f' and conn in conn_track:
                del conn_track[conn]
            elif st == 'f':
                del conn_track[_swap_addr(conn)]
        return _mask_port(conn) + (st,) if st else None
    return inner


from ..counters import counter
from ..decoders import decoder


@counter.AttrCounter
@counter._filter_decode_output
@session
def tcp_conn_counter(data):
    return decoder.decode_tcp(data)


@counter.TimedAttrCounter
@counter._filter_decode_output
@session
def tcp_conn_timed_counter(data):
    return decoder.decode_tcp(data)
