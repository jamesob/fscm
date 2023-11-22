class Secrets(dict):
    def __repr__(self):
        items = (f"{k}='***'" for k in self)
        return "Secrets({})".format(", ".join(items))
