"""
A convenience extension to `clii.App` that eases remote execution of fscm-enabled
scripts on multiple hosts.
"""
import typing as t
import re
from functools import lru_cache
from pathlib import Path

import yaml
import fscm
from fscm import remote
from fscm.secrets import Secrets
from fscm.remote import Host
import clii


def default_load_secrets_fnc(secrets_path: str, hosts: list[Host]) -> Secrets:
    """
    TODO: make `secrets_path` generic beyond `pass`.
    """

    secrets = fscm.get_secrets(['*'], secrets_path)
    host_to_secrets = {}

    # TODO: formalize this "_hosts" map convention somewhere
    if '_hosts' in secrets:
        host_to_secrets = secrets.pop('_hosts')

    for host in hosts:
        secrets_for_host = host_to_secrets.get(host.name, {})
        # Set all secrets on the host, plus any host-specific secrets.
        host.secrets.update(secrets)
        host.secrets.update(secrets_for_host)

        # Inherit a general sudo password if one is provided.
        #
        # TODO: formalize this special case?
        if (general_sudo :=
                host_to_secrets.get('sudo_password')) and not secrets_for_host:
            host.secrets['sudo_password'] = general_sudo

    return secrets


def default_prepare_hosts_fnc(hosts: list[Host], secrets: Secrets) -> list[Host]:
    return hosts


class RemoteCliApp(clii.App):
    """
    A clii.App subclass which provides common command-line flags (e.g. `--host-filter`,
    `--dry-run`) and utilities for running remotely executing commands.
    """
    def __init__(
            self,
            *args,
            hosts_path: t.Optional[t.Union[str, Path]] = None,
            secrets_path: t.Optional[str] = None,
            check_host_keys: t.Optional[str] = None,
            HostClass: t.Type = remote.Host,
            load_secrets_fnc: t.Optional[t.Callable[[str, list[Host]], Secrets]] = None,
            prepare_hosts_fnc: t.Optional[t.Callable[[list[Host], Secrets],
                                                     list[Host]]] = None,
            **kwargs) -> None:
        """
        Args:
            load_secrets_fnc: a function that appends secrets to each `Host.secrets`
                from some source. Takes a path to the secrets and the list of loaded
                hosts.
        """
        super().__init__(*args, **kwargs)

        self.add_arg('-d', '--dry-run', '--dry', action='store_true')
        self.add_arg('-f', '--host-filter')
        self.add_arg("-t", "--tag-filter")

        self.hosts_path = hosts_path or ""
        self.HostClass = HostClass
        self.load_secrets_fnc = load_secrets_fnc or default_load_secrets_fnc
        self.prepare_hosts_fnc = prepare_hosts_fnc or default_prepare_hosts_fnc
        self.secrets_path = secrets_path
        self.secrets = fscm.Secrets()

        if check_host_keys:
            fscm.remote.OPTIONS.check_host_keys = check_host_keys

    def update_pickle_whitelist(self, whitelist: list[str]) -> None:
        """Allow classes to be passed (via pickle) as arguments to remote functions."""
        fscm.remote.OPTIONS.pickle_whitelist.extend(whitelist)

    def deserialize_hosts(self, hosts_path: str) -> list[Host]:
        data = yaml.safe_load(Path(hosts_path).read_text())
        return [self.HostClass.from_dict(name, d) for name, d in data['hosts'].items()]

    @lru_cache(100)
    def get_hosts(self, with_secrets: bool = True, getall: bool = False) -> list[Host]:
        assert self.hosts_path
        hosts: list[Host] = self.deserialize_hosts(self.hosts_path)

        if not getall:
            if filter := getattr(self.args, 'host_filter', ''):
                hosts = [h for h in hosts if h.name if re.match(filter, h.name)]

            if tags := getattr(self.args, 'tag_filter', ''):
                tagslist = [t.strip() for t in tags.split(',')]
                hosts = [h for h in hosts if any(tag in h.tags for tag in tagslist)]

        if with_secrets and self.secrets_path:
            self.secrets = self.load_secrets_fnc(self.secrets_path, hosts)
        else:
            print("WARNING !!! did not load secrets")

        return self.prepare_hosts_fnc(hosts, self.secrets)

    def get_hosts_by_tags(self, tags: str) -> list[Host]:
        tagslist = [t.strip() for t in tags.split(',')]
        return [h for h in self.get_hosts() if any(tag in h.tags for tag in tagslist)]

    def get_host(self, name: str) -> Host:
        return [h for h in self.get_hosts() if name == h.name][0]

    def run_on_hostname(self, name: str, *args, **kwargs) -> remote.HostGroupCallResult:
        host = self.get_host(name)
        return self.run_on_hosts([host], *args, **kwargs)

    def run_on_all(self, *args, **kwargs) -> remote.HostGroupCallResult:
        with self.get_executor() as exec:
            return exec.run(*args, **kwargs)

    def run_on_hosts(self, hosts, *args, **kwargs) -> remote.HostGroupCallResult:
        with self.get_executor(hosts=hosts) as exec:
            return exec.run(*args, **kwargs)

    def run_on_host(self, host, *args, **kwargs) -> remote.HostGroupCallResult:
        return self.run_on_hosts([host], *args, **kwargs)

    def get_executor(self, hosts: t.Optional[list[Host]] = None) -> t.ContextManager:
        hosts = hosts or self.get_hosts()
        return remote.executor(*hosts, dry_run=self.args.dry_run)
