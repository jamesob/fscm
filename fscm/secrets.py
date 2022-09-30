class Secrets:
    def __init__(self, /, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        items = (f"{k}='***'" for k in self.__dict__)
        return "{}({})".format(type(self).__name__, ", ".join(items))

    def update(self, secrets):
        self.__dict__.update(secrets.__dict__)
        return self

    def pop(self, key, default=None):
        return self.__dict__.pop(key, default)

    def __or__(self, other):
        return self.update(other)

    __ior__ = __or__
    __ror__ = __or__
