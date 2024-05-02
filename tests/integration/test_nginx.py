import urllib.request
from pathlib import Path
from textwrap import dedent

from fscm.remote import Host, executor, SSH
from fscm import p, s, run, Secrets

from .conftest import test_identity_file


test_host = Host(
    "test",
    connection_spec=(
        SSH(
            hostname="localhost",
            username="user",
            port="2222",
            identity_file=str(test_identity_file()),
            check_host_keys="ignore",
        ),
    ),
    secrets=Secrets(sudo_password="user"),
)


def install_nginx():
    s.pkg_install("nginx", sudo=True)
    if not (sites := Path('/etc/nginx/sites-enabled')).exists():
        p(sites, sudo=True).mkdir()

    p('/etc/nginx/sites-enabled/default', sudo=True).content(dedent(
        '''
        server {
            listen 80;
            root /home/user/hello.html
        }
        '''))
    p('/home/user/hello.html').content('<html>hello</html>')
    # run('systemctl restart nginx', sudo=True, check=True)


def pytest_nginx(container):
    with container(ports=['8100:80']):
        with executor(test_host) as exec:
            got = exec.run(install_nginx)

        assert got.ok
        assert 'hello' in urllib.request.urlopen("http://localhost:8100").read()
