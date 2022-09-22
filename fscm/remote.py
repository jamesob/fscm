# TODO: filesystem mutex to avoid simultaneous runs
import logging
import inspect
import typing as t
from dataclasses import dataclass, field
from contextlib import contextmanager
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from string import Template

import mitogen.master
import mitogen.core
import mitogen.utils
import mitogen.select
import mitogen.parent


log = logging.getLogger("fscm.remote")


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


class Host:
    """An individual host that will be provisioned to."""

    def __init__(
        self,
        name: str,
        username: t.Optional[str] = None,
        secrets: t.Optional[SimpleNamespace] = None,
        connection_spec: t.Optional[ConnSpec] = None,
        allowed_file_globs: t.Optional[t.List[str]] = None,
    ):
        """
        Args:
            secrets: secrets that are attached to the host.
            connection_spec: how to connect to this particular host.
            allowed_file_globs: files on the parent host that this host
              can access.
        """
        self.name = name
        self.username = username
        self.secrets = secrets or SimpleNamespace()
        self.connection_spec = connection_spec
        self.allowed_file_globs = allowed_file_globs or []

    def __hash__(self):
        return hash(self.name)

    def __repr__(self):
        return f"Host(name={self.name!r}, connection_spec={self.connection_spec!r})"

    def allow_file_access(self, *globs: str):
        """
        Allow child hosts to access any path matching `glob` on the host system.
        """
        self.allowed_file_globs.extend(globs)


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
def executor(*hosts: Host):
    """
    Return a RemoteExecutor instance for a number of hosts; should be done in a context
    manager to handle the mitogen Router lifecycle.
    """
    with mitogen_router() as router:
        hg = RemoteExecutor(hosts, router)
        yield hg


@dataclass
class HostGroupCallResult:
    hosts: t.Iterable[Host]
    succeeded: t.Dict[str, t.Any] = field(default_factory=dict)
    failed: t.Dict[str, t.Any] = field(default_factory=dict)

    @property
    def ok(self):
        return (not bool(self.failed)) and len(self.succeeded) == len(self.hosts)

    @property
    def all_results(self):
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
    msg: str


@dataclass
class RemoteExecutor:
    """A mechanism to execute arbitrary functions on a group of hosts."""

    hosts: t.List[Host]
    router: mitogen.master.Router

    # A cache of the mitogen contexts, e.g. an active SSH connection, per host.
    _host_to_context: t.Dict[Host, mitogen.parent.Context] = field(default_factory=dict)

    _allowed_file_globs: t.List[str] = field(default_factory=list)

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

    def run_on_hosts(self, host_prefix, fnc, *args, **kwargs) -> HostGroupCallResult:
        """
        Run a function remotely on each matching host, blocking until all hosts complete
        the task.

        Returns the results of the function call, keyed by each host.

        TODO: make filtering here better
        """
        hosts = [h for h in self.hosts if h.name.startswith(host_prefix)]
        return self._call_for_each_host(fnc, *args, hosts=hosts, **kwargs)

    def allow_file_access(self, *globs: str):
        """
        Allow child hosts to access any path matching `glob` on the host system.
        """
        self._allowed_file_globs.extend(globs)

    def set_secrets(self, secrets: SimpleNamespace):
        for h in self.hosts:
            h.secrets = secrets

    def _connect_hosts(self):
        """
        Ensure each host has a mitogen context attached to it, which facilitates
        a remote connection.
        """
        for host in self.hosts:
            if host in self._host_to_context:
                # Already connected
                continue

            connspec = host.connection_spec

            if not connspec and (default_conn_spec := OPTIONS.default_connection_spec):
                if callable(default_conn_spec):
                    connspec = default_conn_spec(host)
                else:
                    connspec = default_conn_spec

            assert connspec

            for spec in connspec:
                if isinstance(spec, SSH):
                    spec.hostname = host.name
                    if OPTIONS.check_host_keys is not None:
                        spec.check_host_keys = OPTIONS.check_host_keys

            log.info("connecting to host %s; may prompt for credentials", host.name)
            # TODO probably try and do this in parallel?
            try:
                self._host_to_context[host] = get_context_from_spec(
                    self.router, connspec
                )
            except Exception:
                log.exception(f"failed to connect to %s", host)
                raise

    def _call_for_each_host(
        self, fnc, *args, hosts: t.Optional[t.Sequence[Host]] = None, **kwargs
    ) -> HostGroupCallResult:
        hosts = hosts if hosts is not None else self.hosts
        result = HostGroupCallResult(self.hosts)
        task_to_host = {}
        host_to_task = {}
        from_children = {}
        to_children = {}
        receiver_to_child_host = {}
        select_host_task = mitogen.select.Select(oneshot=False)
        select_msg_from_child = mitogen.select.Select(oneshot=False)

        self._connect_hosts()

        # Boot each host and get it started executing the task
        for h in hosts:
            assert h in self._host_to_context
            from_child = mitogen.core.Receiver(self.router)
            from_children[h] = from_child
            receiver_to_child_host[from_child] = h

            task = self._host_to_context[h].call_async(
                boot_child_and_call, h, from_child.to_sender(), fnc, *args, **kwargs
            )
            select_msg_from_child.add(from_child)
            task_to_host[task] = h
            host_to_task[h] = task
            select_host_task.add(task)

        # Boot the children up to establish bidirectional communication.
        for from_child in from_children.values():
            try:
                sender_to_kid = from_child.get(timeout=10).unpickle()
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

                if bad_request := self._handle_msg_from_child(
                    child_host, to_children[child_recv], msg
                ):
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
        self, child_host: Host, to_child: mitogen.core.Sender, msg: RemoteMsg
    ) -> t.Optional[BadChildRequest]:
        """
        Respond to an in-task remote message from a child host.
        """
        if isinstance(msg, GetFileMsg):
            path = Path(msg.path)
            allowed_globs = self._allowed_file_globs + child_host.allowed_file_globs
            if any(path.match(glob) for glob in allowed_globs):
                to_child.send(path.read_bytes())
            else:
                return BadChildRequest(
                    f"unauthorized request for file: {path}; "
                    f"allowed paths are {allowed_globs}"
                )
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
                        f"bad secret path for host {child_host}: {secret_path}"
                    )

            assert isinstance(sek, str)
            to_child.send(sek)
        else:
            raise ValueError("unrecognized msg")


@contextmanager
def mitogen_router():
    mitogen.core.set_pickle_whitelist(
        [r"fscm\..+", r"__main__\..+", *OPTIONS.pickle_whitelist]
    )
    broker = mitogen.master.Broker()
    router = mitogen.master.Router(broker)
    mitogen.utils.log_to_file(level="INFO")
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
) -> mitogen.parent.Context:
    curr_context = None

    for spec in specs:
        kwargs = {
            "python_path": ["/usr/bin/env", "python3"],
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


@dataclass
class Parent:
    to_parent: mitogen.core.Sender
    from_parent: mitogen.core.Receiver

    @classmethod
    def from_sender(cls, to_parent) -> "Parent":
        from_parent = mitogen.core.Receiver(to_parent.context.router)
        to_parent.send(from_parent.to_sender())
        log.debug("sent Sender from child to parent")

        return cls(to_parent, from_parent)

    def get_file(self, path: str) -> bytes:
        self.to_parent.send(GetFileMsg(path))
        return self.from_parent.get().unpickle()

    def template(self, path: str, safe_substitute: bool = False, **kwargs) -> str:
        f = self.get_file(path)
        t = Template(f.decode())
        if safe_substitute:
            return t.safe_substitute(**kwargs)
        else:
            return t.substitute(**kwargs)

    def get_secret(self, name: str) -> str:
        self.to_parent.send(GetSecretMsg(name))
        return self.from_parent.get().unpickle()


def boot_child_and_call(
    host: Host, to_parent: mitogen.core.Sender, fnc, *args, **kwargs
):
    argspec = inspect.getfullargspec(fnc)
    parent = Parent.from_sender(to_parent)
    args = list(args)

    if sudo_password := getattr(host.secrets, "sudo_password", None):
        # This value will be detected and made use of in
        # `fscm.Settings.get_cached_sudo_password()`.
        global CACHED_SUDO_PASSWORD
        CACHED_SUDO_PASSWORD = sudo_password

    if "host" in argspec.args:
        args.insert(argspec.args.index("host"), host)

    if "parent" in argspec.args:
        args.insert(argspec.args.index("parent"), parent)

    return fnc(*args, **kwargs)
