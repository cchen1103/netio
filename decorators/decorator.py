from functools import wraps, lru_cache
from collections import deque

def attribute_only(func):
    """
    wraps to return only packet decoder attributes and cut of net next_protocol
    """
    @wraps
    def inner(*args, **kwargs):
        attr, next_proto = func(*args, **kwargs)
        return attr    
    return inner
