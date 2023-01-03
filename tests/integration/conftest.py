import pytest
import subprocess
from pathlib import Path
from contextlib import contextmanager

import fscm.remote
from fscm.remote import Host, SSH


DOCKER_SSH_PORT = 2222
CONTAINER_NAME = 'fscm-test'

fscm.remote.OPTIONS.pickle_whitelist = [r'tests\.integration\..+']


def arch_container():
    return boot_container('arch')


def debian_container():
    return boot_container('debian')


def cleanup_container(check=True):
    p = subprocess.run(f"docker rm -f {CONTAINER_NAME}", shell=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"failed to stop docker container {CONTAINER_NAME}")


def testdata_dir() -> Path:
    return Path(__file__).resolve().parent.parent / 'data'


def test_identity_file() -> Path:
    """Return the ed25519 ssh privkey used to get into test containers for `user`."""
    return testdata_dir() / 'id-fscm-test'


# -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
test_host = Host(
    'test',
    connection_spec=(
        SSH(
            hostname='localhost',
            username='user',
            port='2222',
            identity_file=str(test_identity_file()),
            check_host_keys='ignore',
        ),
    ),
)


@contextmanager
def boot_container(distro):
    cleanup_container(check=False)
    proc = subprocess.run(
        f"docker run -d --name {CONTAINER_NAME} -p {DOCKER_SSH_PORT}:22 "
        f"jamesob/fscm-test-{distro}-ssh",
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
        metafunc.parametrize("container", [arch_container, debian_container])
