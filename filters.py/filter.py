from ..decoders import decoder

def filter_attr(*f_args):
    """
    filter only to selected attributes

    input:  '*' | value    # '*', no filter for this field; 'value', match the value in the field
    return: decorator
    """
    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            attrs = inner(*args, **kwargs)
            for x in (j for i,j in zip(f_args,attrs) if i != '*' and i != j):
                return None
            return attrs
        return inner
    return wrapper
