from contextlib import contextmanager
from argparse import Namespace
import typing as t

import mitogen.master
import mitogen.core
import mitogen.utils


class MitogenContext(Namespace):
    pass

class SSH(MitogenContext):
    pass

class Su(MitogenContext):
    pass

class Local(MitogenContext):
    pass


@contextmanager
def mitogen_router():
    broker = mitogen.master.Broker()
    router = mitogen.master.Router(broker)
    mitogen.utils.log_to_file(level='INFO')
    try:
        yield router
    finally:
        broker.shutdown()
        broker.join()

@contextmanager
def context_from_spec(specs: t.List[MitogenContext], **kwargs):
    with mitogen_router() as router:
        yield get_context_from_spec(router, specs, **kwargs)


def get_context_from_spec(
    router,
    specs: t.List[MitogenContext],
    pickle_whitelist: t.List[str] | None = None
) -> mitogen.core.Context:
    curr_context = None

    for spec in specs:
        kwargs = {
            'python_path': ['/usr/bin/env', 'python3'],
            'pickle_whitelist_patterns': pickle_whitelist,
        }

        match spec:
            case SSH():
                route_fnc = router.ssh
            case Su():
                route_fnc = router.su
            case Local():
                route_fnc = router.local
            case _:
                raise ValueError("unknown spec type")

        kwargs.update(**spec.__dict__)

        if curr_context:
            kwargs['via'] = curr_context

        curr_context = route_fnc(**kwargs)

    assert curr_context
    return curr_context


@contextmanager
def mitogen_context(*args, **kwargs):
    with mitogen_router() as router:
        yield (router, get_mitogen_context(router, *args, **kwargs))

def get_mitogen_context(router, hostname, *args, log_level="INFO", **kwargs):
    kwargs.setdefault("python_path", ["/usr/bin/env", "python3"])
    mitogen.utils.log_to_file(level=log_level)
    context = (
        router.local(*args, **kwargs)
        if hostname == "localhost"
        else router.ssh(*args, hostname=hostname, **kwargs)
    )
    # router.enable_debug()
    return context
