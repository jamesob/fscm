import datetime


class Change:
    # How this change is presented as human-readable text. Formatted with
    # `.format(**self.__dict__)`.
    msg: str = ""

    def __post_init__(self) -> None:
        self.timestamp = datetime.datetime.now()

ChangeList = list[Change]
