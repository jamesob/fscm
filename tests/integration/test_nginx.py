import subprocess
from .conftest import test_host

from fscm.remote import executor


def print_hello():
    return "hello"


def _pytest_nginx(container):
    with container():
        with executor(test_host) as exec:
            got = exec.run(print_hello)

        assert ['hello'] == list(got.succeeded.values())
