from functools import wraps

def cached(mask):
    @wraps
    def inner(func):
        @wraps
        def wrapper(arg1, arg2):
            key = ''.join([j for i, j in zip(mask,arg2) if j != '0'])
            if key not in cache:
                cache[key] = func(arg1, arg2)
            return cache[key]
        return wrapper
    return inner
