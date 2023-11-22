#!/usr/bin/env python3

import sys
import getpass

import fscm
from fscm.remote import Host, executor, SSH


def run_sudo_thing():
    fscm.run('whoami')
    fscm.run('touch /tmp/foobar', sudo=True)


def check_sudo_file():
    fscm.run('ls -lah /tmp/foobar')


if __name__ == "__main__":
    username, hostname = sys.argv[1].split('@')

    # sudo_password = getpass.getpass('sudo password: ')
    # fscm.settings.sudo_password = sudo_password

    # print("This should touch /tmp/foobar as root, and shouldn't prompt you.")

    # run_sudo_thing()
    # check_sudo_file()

    print("Now we're ensuring that remote caching of the sudo password works.")
    sudo_password = getpass.getpass('remote sudo password: ')

    h1 = Host(hostname, username=username, connection_spec=(SSH(),))
    with executor(h1) as exec:
        h1.secrets['sudo_password'] = sudo_password
        exec.run(run_sudo_thing)
        exec.run(check_sudo_file)
