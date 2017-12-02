

class AttrCounter:
    def __init__(self, func):
        self.func = func
        self.counter = dict()
    def __call__(self, *args, **kwargs):
        attr = self.func(*args, **kwargs)
        if attr in self.counter:
            self.counter[attr] = self.counter[attr] + 1
        else:
            self.counter[attr] = 1
        return attr
    def clr_count(self, *attrs):
        if not attrs:
            self.counter = dict()   # clear all counters
        else:
            for attr in (x for x in attrs if x in self.counter):
                del self.counter(attr)  # remove listed attributes counter
    @property
    def attrs(self):
        return self.counter.keys()
    @property
    def count(self):
        return self.counter

        
