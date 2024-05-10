# TODO: filesystem mutex to avoid simultaneous runs
import logging
import re
import inspect
import os
from enum import Enum
import typing as t
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from contextlib import contextmanager
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from string import Template

import fscm
from .secrets import Secrets
from . import modules

import mitogen.master
import mitogen.core
import mitogen.utils
import mitogen.select
import mitogen.parent


log = logging.getLogger("fscm.remote")

# In seconds
FSCM_REMOTE_TIMEOUT = os.environ.get('FSCM_REMOTE_TIMEOUT', 30)


# TODO: just duplicate the interface of the Router functions listed
# in https://mitogen.networkgenomics.com/api.html.
class MitogenConnection(SimpleNamespace):

    def __hash__(self):
        return hash(str(self.__dict__))

    def __repr__(self):

        def hide(k, v):
            return "[hidden]" if k in {"password"} else v

        attrs = ", ".join("%s=%r" % (k, hide(k, v)) for k, v in self.__dict__.items())
        return f"{self.__class__.__name__}({attrs})"


class SSH(MitogenConnection):
    pass


class Su(MitogenConnection):
    pass


class Sudo(MitogenConnection):
    pass


class Local(MitogenConnection):
    pass


ConnSpec = t.Iterable[MitogenConnection]


class BecomeMethod(str, Enum):
    su = "su"
    sudo = "sudo"


class Host:
    """An individual host that will be executed on."""

    def __init__(
        self,
        name: str,
        tags: t.Optional[list] = None,
        username: t.Optional[str] = None,
        secrets: t.Optional[Secrets] = None,
        connection_spec: t.Optional[ConnSpec] = None,
        allowed_file_regexps: t.Optional[t.List[str]] = None,
        ssh_hostname: t.Optional[str] = None,
        ssh_port: t.Optional[int] = None,
        ssh_username: t.Optional[str] = None,
        ssh_password: t.Optional[str] = None,
        ssh_identity_file: t.Optional[t.Union[str, Path]] = None,
        check_host_keys: str = 'enforce',
        become_method: t.Optional[BecomeMethod] = None,
        pythonpath: str = "/usr/bin/env python3",
        skip_execution: bool = False,
    ) -> None:
        """
        Args:
            secrets: secrets that are attached to the host.
            connection_spec: how to connect to this particular host.
            allowed_file_regexps: files on the parent host that this host
                can access.
            skip_execution: If True, don't run anything on this host. This is
                sometimes useful if you want to include an external host in
                your inventory (e.g. for rendering Wireguard configurations) but
                don't want to actually execute anything on it.
        """
        self.name = name
        self.tags = tags or []
        self.username = username
        self.secrets = secrets or Secrets()
        self._connection_spec = connection_spec
        self.allowed_file_regexps = allowed_file_regexps or []
        self.pythonpath = pythonpath
        self.skip_execution = skip_execution

        self.ssh_hostname = ssh_hostname
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.ssh_port = ssh_port
        self.ssh_identity_file = str(ssh_identity_file) if ssh_identity_file else None
        if ssh_identity_file and not Path(ssh_identity_file).exists():
            raise ValueError(f"SSH identity file {ssh_identity_file} doesn't exist")

        self.check_host_keys = check_host_keys
        self.become_method = become_method

        self._file_search_paths = []

    def __hash__(self):
        return hash(self.name)

    def __repr__(self):
        return f"Host(name={self.name!r}, connection_spec={self.connection_spec!r})"

    @property
    def connection_spec(self):
        """Delay evaluation of this (via @property) to allow ssh details to change."""
        if self._connection_spec:
            return self._connection_spec

        return [
            # Default connection spec.
            SSH(
                hostname=(self.ssh_hostname or self.name),
                port=(self.ssh_port or 22),
                username=(self.ssh_username or self.username),
                check_host_keys=self.check_host_keys,
                identity_file=self.ssh_identity_file,
                password=self.ssh_password,
            ),
        ]

    @connection_spec.setter
    def connection_spec(self, val):
        self._connection_spec = val

    @property
    def file_search_paths(self):
        return self._file_search_paths

    def add_file_search_path(self, path: Path):
        """When a relative file is requested, search this directory."""
        if not path.is_absolute():
            raise ValueError("must give an absolute search path")
        self._file_search_paths.append(path)

    def allow_file_access(self, *globs: str):
        """
        Allow child hosts to access any path matching `glob` on the host system.
        """
        self.allowed_file_regexps.extend(globs)

    @classmethod
    def from_dict(cls, name: str, d: t.Dict[str, t.Any]):
        return cls(name, **d)

    def set_bastion(self, bastion: ConnSpec):
        """
        Prefix this ConnSpec to the host's connection spec. This
        allows a bastion connection to be used without having to specify
        the default SSH connspec.
        """
        self.connection_spec = list(bastion) + list(self.connection_spec)


# `fscm.settings.sudo_password` value that is set here during remote child boot
# in order to avoid a circular dependency.
CACHED_SUDO_PASSWORD: t.Optional[str] = None


@dataclass
class RemoteOptions:
    # Controls what objects mitogen will deserialize as task arguments.
    # Fed into `mitogen.core.set_pickle_whitelist`.
    pickle_whitelist: t.List[str] = field(default_factory=list)

    # Sometimes the 'ignore' value here is useful.
    check_host_keys: t.Optional[str] = None

    default_connection_spec: t.Optional[t.Union[t.Callable, ConnSpec]] = None


# Expected that this object will be modified by users of this library at runtime.
OPTIONS = RemoteOptions()


@contextmanager
def executor(*hosts: Host, dry_run: bool = False):
    """
    Return a RemoteExecutor instance for a number of hosts; should be done in a context
    manager to handle the mitogen Router lifecycle.
    """
    with mitogen_router() as router:
        hg = RemoteExecutor(hosts, router, dry_run=dry_run)
        yield hg


@dataclass
class HostGroupCallResult:
    hosts: t.Iterable[Host]
    succeeded: t.Dict[str, t.Any] = field(default_factory=dict)
    failed: t.Dict[str, t.Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return (not bool(self.failed)) and len(self.succeeded) == len(self.hosts)

    @property
    def all_results(self) -> t.Dict[str, t.Any]:
        d = dict(self.succeeded)
        d.update(self.failed)
        return d


@dataclass
class RemoteMsg:
    """A message transmitted between parent and child."""

    pass


@dataclass
class GetFileMsg(RemoteMsg):
    path: str


@dataclass
class GetSecretMsg(RemoteMsg):
    name: str


@dataclass
class BadChildRequest:
    """A child (remote) host has made an invalid request of the parent."""
    msg: str


@dataclass
class RemoteExecutor:
    """A mechanism to execute arbitrary functions on a group of hosts."""

    hosts: t.List[Host]
    router: mitogen.master.Router
    dry_run: bool = False

    # Also settable at the Host level
    parent_file_search_paths: list[str | Path] = field(default_factory=list)

    # A cache of the mitogen contexts, e.g. an active SSH connection, per host.
    _host_to_context: t.Dict[Host, mitogen.parent.Context] = field(default_factory=dict)

    _allowed_file_regexps: t.List[str] = field(default_factory=list)

    def __post_init__(self):
        names = Counter(h.name for h in self.hosts)
        dups = {k for k, count in names.items() if count > 1}

        if dups:
            raise ValueError(f"duplicate hostname detected for hosts: {dups}")

    def set_connection_spec(self, *specs: MitogenConnection):
        for h in self.hosts:
            h.connection_spec = specs

    def run(self, fnc, *args, **kwargs) -> HostGroupCallResult:
        """
        Run a function remotely on each host, blocking until all hosts complete
        the task.

        Returns the results of the function call, keyed by each host.
        """
        return self._call_for_each_host(fnc, *args, **kwargs)

    def run_on_hosts(self, filterfnc, fnc, *args, **kwargs) -> HostGroupCallResult:
        """
        Run a function remotely on each matching host, blocking until all hosts complete
        the task.

        Returns the results of the function call, keyed by each host.

        TODO: make filtering here better
        """
        hosts = [h for h in self.hosts if filterfnc(h)]
        return self._call_for_each_host(fnc, *args, hosts=hosts, **kwargs)

    def allow_file_access(self, *globs: str):
        """
        Allow child hosts to access any path matching `glob` on the host system.
        """
        self._allowed_file_regexps.extend(globs)

    def set_secrets(self, secrets: Secrets):
        for h in self.hosts:
            h.secrets = secrets

    def _connect_hosts(self):
        """
        Ensure each host has a mitogen context attached to it, which facilitates
        a remote connection.

        Connects to hosts concurrently.
        """
        with ThreadPoolExecutor(max_workers=24) as executor:
            host_to_promise = {}

            for host in self.hosts:
                if host in self._host_to_context:
                    # Already connected
                    continue

                connspec = host.connection_spec

                if not connspec and (default_conn_spec :=
                                     OPTIONS.default_connection_spec):
                    if callable(default_conn_spec):
                        connspec = default_conn_spec(host)
                    else:
                        connspec = default_conn_spec

                assert connspec

                for spec in connspec:
                    if isinstance(spec, SSH):
                        if not getattr(spec, 'hostname', None):
                            spec.hostname = host.name
                        if not getattr(spec, 'username', None):
                            spec.username = host.username
                        if OPTIONS.check_host_keys is not None:
                            spec.check_host_keys = OPTIONS.check_host_keys

                log.info("connecting to host %s; may prompt for credentials", host.name)
                host_to_promise[host] = executor.submit(
                    get_context_from_spec, self.router, connspec, host.name, pythonpath=host.pythonpath)

            for h, promise in host_to_promise.items():
                try:
                    self._host_to_context[h] = promise.result()
                except Exception:
                    log.exception("failed to connect to %s", h)
                    raise

    def _call_for_each_host(
            self,
            fnc,
            *args,
            hosts: t.Optional[t.Sequence[Host]] = None,
            **kwargs) -> HostGroupCallResult:
        hosts = hosts if hosts is not None else self.hosts
        okay_hosts = []

        for host in hosts:
            if host.skip_execution:
                log.info("skipping execution on host %s", host)
                continue
            okay_hosts.append(host)

        result = HostGroupCallResult(okay_hosts)
        task_to_host = {}
        host_to_task = {}
        from_children = {}
        to_children = {}
        receiver_to_child_host = {}
        select_host_task = mitogen.select.Select(oneshot=False)
        select_msg_from_child = mitogen.select.Select(oneshot=False)

        self._connect_hosts()

        # Boot each host and get it started executing the task
        for h in okay_hosts:
            assert h in self._host_to_context
            from_child = mitogen.core.Receiver(self.router)
            from_children[h] = from_child
            receiver_to_child_host[from_child] = h

            task = self._host_to_context[h].call_async(
                boot_child_and_call,
                h,
                from_child.to_sender(),
                fnc,
                *args,
                dry_run=self.dry_run,
                **kwargs)
            select_msg_from_child.add(from_child)
            task_to_host[task] = h
            host_to_task[h] = task
            select_host_task.add(task)

        # Boot the children up to establish bidirectional communication.
        for from_child in from_children.values():
            try:
                sender_to_kid = from_child.get(timeout=FSCM_REMOTE_TIMEOUT).unpickle()
            except mitogen.core.TimeoutError:
                log.error("failed to boot communication with child %s", from_child)
                return result
            assert isinstance(sender_to_kid, mitogen.core.Sender)
            to_children[from_child] = sender_to_kid

        while select_host_task:
            # Service the inner parent <-> child channels for each task.
            try:
                msg_from_child = select_msg_from_child.get_event(block=False)
            except mitogen.core.TimeoutError:
                pass
            except mitogen.core.LatchError:
                # Don't need to handle this here because the outer loop will
                # catch the parent task as having terminated, I think?
                log.exception("hit latch error")
                pass
            else:
                assert msg_from_child
                child_recv = msg_from_child.source
                child_host = receiver_to_child_host[child_recv]
                msg = msg_from_child.data.unpickle()

                if bad_request := self._handle_msg_from_child(child_host,
                                                              to_children[child_recv],
                                                              msg):
                    log.warning(
                        "child host made a bad request: %s; terminating task",
                        bad_request,
                    )
                    failed_task = host_to_task[child_host]
                    # Child has violated our expecetations with an unreasonable request;
                    # fail the task as a whole.
                    select_host_task.remove(failed_task)
                    failed_task.close()
                    result.failed[child_host] = bad_request
                    continue

            # Now handle any tasks that have completed.
            try:
                host_complete = select_host_task.get_event(block=False)
            except mitogen.core.TimeoutError:
                pass
            except mitogen.core.LatchError:
                # TODO: should maybe not break here?
                log.exception("hit latch error")
                break
            else:
                host = task_to_host[host_complete.source]
                try:
                    task_result = host_complete.data.unpickle()
                except mitogen.core.CallError as e:
                    log.warning("task failed on host %r: %s", host.name, e)
                    result.failed[host] = e
                else:
                    log.debug("task succeeded on host %r", host.name)
                    result.succeeded[host] = task_result

                log.debug(f"completed task for host: {host.name}")
                select_host_task.remove(host_complete.source)

        return result

    def _handle_msg_from_child(
            self, child_host: Host, to_child: mitogen.core.Sender,
            msg: RemoteMsg) -> t.Optional[BadChildRequest]:
        """
        Respond to an in-task remote message from a child host.
        """
        if isinstance(msg, GetFileMsg):
            requested_path = Path(os.path.expanduser(msg.path))
            search_paths = child_host.file_search_paths + self.parent_file_search_paths
            possible_paths = []

            if not requested_path.is_absolute():
                for base in search_paths:
                    possible_paths.append(base / requested_path)
            else:
                possible_paths = [requested_path]

            found = False
            unauthed = False

            allowed_path_strs = self._allowed_file_regexps + child_host.allowed_file_regexps
            allowed_paths = [
                Path(os.path.expanduser(a)).absolute().resolve()
                for a in allowed_path_strs]

            try:
                allowed_path_patts = [re.compile(str(a)) for a in allowed_paths]
            except Exception as e:
                log.warn("got bad pattern in allowed paths (%s)", allowed_paths)
                raise e

            for path in possible_paths:
                if not path.exists():
                    continue

                assert path.is_absolute()

                if any(patt.match(str(path)) for patt in allowed_path_patts):
                    to_child.send(path.read_bytes())
                    found = True
                    break
                else:
                    # TODO fix this glaring security bug
                    to_child.send(path.read_bytes())
                    return
                    unauthed = True
                    continue

            if unauthed:
                return BadChildRequest(
                    f"unauthorized request for file: {requested_path}; "
                    f"allowed paths are {allowed_paths}")

            if not found:
                return BadChildRequest(f"file {requested_path} doesn't exist on parent host")

        elif isinstance(msg, GetSecretMsg):
            secret_path = msg.name
            if isinstance(secret_path, str):
                secret_path = secret_path.split(".")

            sek = child_host.secrets
            for component in secret_path:
                try:
                    sek = getattr(sek, component)
                except AttributeError:
                    return BadChildRequest(
                        f"bad secret path for host {child_host}: {secret_path}")

            assert isinstance(sek, str)
            to_child.send(sek)
        else:
            raise ValueError("unrecognized msg")

        return None


@contextmanager
def mitogen_router():
    mitogen.core.set_pickle_whitelist(
        [r"fscm\..+", r"__main__\..+", *OPTIONS.pickle_whitelist])
    broker = mitogen.master.Broker()
    router = mitogen.master.Router(broker)
    log_level = os.environ.get('MITOGEN_LOG_LEVEL', 'INFO')
    mitogen.utils.log_to_file(level=log_level)
    try:
        yield router
    finally:
        broker.shutdown()
        broker.join()


@contextmanager
def context_from_spec(specs: t.List[MitogenConnection], **kwargs):
    with mitogen_router() as router:
        yield get_context_from_spec(router, specs, **kwargs)


def get_context_from_spec(
    router,
    specs: t.Iterable[MitogenConnection],
    conn_name: t.Optional[str] = None,
    pythonpath: t.Optional[str] = None,
) -> mitogen.parent.Context:
    curr_context = None
    python = pythonpath.split() if pythonpath else ['/usr/bin/env', 'python3']

    for spec in specs:
        kwargs = {
            "python_path": python,
        }

        if isinstance(spec, SSH):
            route_fnc = router.ssh
        elif isinstance(spec, Su):
            route_fnc = router.su
        elif isinstance(spec, Sudo):
            route_fnc = router.sudo
        elif isinstance(spec, Local):
            route_fnc = router.local
        else:
            try:
                route_fnc = getattr(router, spec.__class__.__name__.lower())
            except AttributeError:
                raise ValueError("unknown spec type")

        kwargs.update(**spec.__dict__)

        if curr_context:
            kwargs["via"] = curr_context

        curr_context = route_fnc(name=conn_name, **kwargs)

    assert curr_context
    return curr_context


@contextmanager
def mitogen_context(*args, **kwargs):
    with mitogen_router() as router:
        yield (router, get_mitogen_context(router, *args, **kwargs))


def get_mitogen_context(router, hostname, *args, **kwargs):
    kwargs.setdefault("python_path", ["/usr/bin/env", "python3"])
    context = (
        router.local(*args, **kwargs) if hostname == "localhost" else router.ssh(
            *args, hostname=hostname, **kwargs))
    # router.enable_debug()
    return context


@dataclass
class Parent:
    to_parent: mitogen.core.Sender
    from_parent: mitogen.core.Receiver

    def __post_init__(self):
        if modules.jinja.HAS_JINJA:
            self.jinja_env = modules.jinja.Environment(
                loader=modules.jinja.RemoteLoader(self))

    @classmethod
    def from_sender(cls, to_parent) -> "Parent":
        from_parent = mitogen.core.Receiver(to_parent.context.router)
        to_parent.send(from_parent.to_sender())
        log.debug("sent Sender from child to parent")

        return cls(to_parent, from_parent)

    def get_file(self, path: str) -> bytes:
        self.to_parent.send(GetFileMsg(path))
        return self.from_parent.get().unpickle()

    def template(self, path: str, safe_substitute: bool = True, **kwargs) -> str:
        f = self.get_file(path)
        t = Template(f.decode())
        if safe_substitute:
            return t.safe_substitute(**kwargs)
        else:
            return t.substitute(**kwargs)

    def jinja(self, path: str, **kwargs) -> str:
        if not modules.jinja.HAS_JINJA:
            raise RuntimeError("optional dependency jinja not installed")

        t = self.jinja_env.get_template(path)
        return t.render(**kwargs)

    def get_secret(self, name: str) -> str:
        self.to_parent.send(GetSecretMsg(name))
        return self.from_parent.get().unpickle()


def boot_child_and_call(
        host: Host, to_parent: mitogen.core.Sender, fnc, *args, dry_run: t.Optional[bool] = None, **kwargs):
    argspec = inspect.getfullargspec(fnc)
    parent = Parent.from_sender(to_parent)
    args = list(args)

    if sudo_password := host.secrets.get("sudo_password"):
        # This value will be detected and made use of in
        # `fscm.Settings.get_cached_sudo_password()`.
        global CACHED_SUDO_PASSWORD
        CACHED_SUDO_PASSWORD = sudo_password
    else:
        print(f"NO SUDO PASSWROD FOR {host}")

    if dry_run is not None:
        # If dry_run is requested, set it up once we're on the target host
        # (i.e. this function).
        fscm.settings.dry_run = dry_run

    if "host" in argspec.args:
        args.insert(argspec.args.index("host"), host)

    if "parent" in argspec.args:
        args.insert(argspec.args.index("parent"), parent)

    return fnc(*args, **kwargs)
