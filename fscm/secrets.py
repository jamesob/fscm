class Secrets:
    def __init__(self, d=None, /, **kwargs):
        if d:
            self.__dict__.update(d)
        self.__dict__.update(kwargs)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        items = (f"{k}='***'" for k in self.__dict__)
        return "{}({})".format(type(self).__name__, ", ".join(items))

    def keys(self):
        return self.__dict__.keys()

    def __iter__(self):
        return self.__dict__.__iter__()

    def __getitem__(self, k):
        return self.__dict__[k]

    def __setitem__(self, *args, **kwargs):
        return self.__dict__.__setitem__(*args, **kwargs)

    def __contains__(self, *args, **kwargs):
        return self.__dict__.__contains__(*args, **kwargs)

    def update(self, d):
        self.__dict__.update(d)
        return self

    def pop(self, key, default=None):
        return self.__dict__.pop(key, default)

    def __or__(self, other):
        return self.update(other)

    __ior__ = __or__
    __ror__ = __or__
