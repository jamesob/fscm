import pytest
import subprocess
import typing as t
from pathlib import Path
from contextlib import contextmanager

import fscm.remote
from fscm.remote import Host, SSH


DOCKER_SSH_PORT = 2222
CONTAINER_NAME = 'fscm-test'

fscm.remote.OPTIONS.pickle_whitelist = [r'tests\.integration\..+']


def arch_container(**kwargs):
    return boot_container('arch', **kwargs)


def debian_container(**kwargs):
    return boot_container('debian', **kwargs)


def cleanup_container(check=True):
    p = subprocess.run(f"docker rm -f {CONTAINER_NAME}", shell=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"failed to stop docker container {CONTAINER_NAME}")


def testdata_dir() -> Path:
    return Path(__file__).resolve().parent.parent / 'data'


def test_identity_file() -> Path:
    """Return the ed25519 ssh privkey used to get into test containers for `user`."""
    return testdata_dir() / 'id-fscm-test'


@contextmanager
def boot_container(distro, ports: t.Optional[t.Iterable[str]] = None):
    cleanup_container(check=False)

    extraports = ' '.join(f'-p {p}' for p in ports or [])

    proc = subprocess.run(
        f"docker run -d --name {CONTAINER_NAME} {extraports} -p {DOCKER_SSH_PORT}:22 "
        f"jamesob/fscm-test-ssh-{distro}",
        shell=True)

    if proc.returncode != 0:
        raise RuntimeError(f"failed to boot docker container for {distro}")

    print(subprocess.run("docker ps", shell=True, text=True).stdout)

    try:
        yield
    finally:
        cleanup_container()


def pytest_generate_tests(metafunc):
    """Parameterize tests by distro when injecting the container fixture."""
    if "container" in metafunc.fixturenames:
        # metafunc.parametrize("container", [arch_container, debian_container])
        metafunc.parametrize("container", [debian_container])
