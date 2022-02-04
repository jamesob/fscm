"""Main module."""
import os
import hashlib
import os.path
import subprocess
import time
import re
import textwrap
import threading
import difflib
import json
import inspect
import socket
import datetime
import logging
import sys
import tempfile
import typing as t
from types import SimpleNamespace
from contextlib import contextmanager
from urllib.parse import unquote, urlparse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from string import Template
from multiprocessing.pool import ThreadPool, AsyncResult

from .thirdparty import color as c

HAS_MITOGEN = True
try:
    import mitogen.master
    import mitogen.utils
except ImportError:
    HAS_MITOGEN = False

logger = logging.getLogger("fscm")

DEBUG = os.environ.get("FSCM_DEBUG")

# Used for finding slow commands.
CMD_TIMES = {}

CmdStrs = t.Union[str, t.Iterable[str]]
Pathable = t.Union[Path, str]
Regex = t.Union[re.Pattern, str]


class FscmException(Exception):
    pass


class NeedsSudoException(FscmException):
    pass


@dataclass
class OutputHandler:
    """Determines how user-facing output should be presented."""

    stream: t.TextIO = sys.stdout

    def log(self, msg: str):
        print(msg, flush=True, file=self.stream)

    def cmd_run(self, line: str, is_stdout: bool):
        """
        The format for streaming `run()` output as it happens, line by line.
        """
        if is_stdout:
            print(f"    {c.blue(line)}", file=self.stream)
        else:
            print(f"    {c.red(line)}", file=self.stream)

    def alert(self, msg: str):
        self.log(c.cyan(c.bold(" !! ")) + msg)


@dataclass
class Settings:
    """fscm-wide settings."""

    stream_output: bool
    # If true, don't actually execute anything - make a best effort to log what we
    # would've done.
    dry: bool = False
    output: OutputHandler = field(default_factory=OutputHandler)
    container_cmd: str = field(default="docker")


settings = Settings(
    stream_output=True,
)


@dataclass
class Change:
    # How this change is presented as human-readable text. Formatted with
    # `.format(**self.__dict__)`.

    def __post_init__(self):
        self.timestamp = datetime.datetime.now()

    def output_log(self):
        prefix = c.bold(" -- ")
        name = self.__class__.__name__

        if name.endswith("Add"):
            prefix = c.green(c.bold(" ++ "))
        elif name.endswith("Rm"):
            prefix = c.red(c.bold(" -- "))
        elif name.endswith("Modify"):
            prefix = c.yellow(c.bold(" ±± "))

        settings.output.log(prefix + self.msg.format(**self.__dict__))


ChangeList = list[Change]
CHANGELIST = []


def cl(ChangeCls, *args, **kwargs) -> Change:
    """Create a Change, append it to the global changelist, and return it."""
    c = ChangeCls(*args, **kwargs)
    CHANGELIST.append(c)
    c.output_log()
    return c


@dataclass
class FileAdd(Change):
    filename: str
    msg: str = "file added {filename}"


@dataclass
class FileRm(Change):
    filename: str
    msg: str = "file removed {filename}"


@dataclass
class FileModify(Change):
    filename: str
    diff: t.Optional[str] = None
    msg: str = "file modified {filename}"


@dataclass
class CmdRun(Change):
    cmd: str
    result: t.Optional["RunReturn"] = None
    msg: str = "command run ({result.returncode}) {cmd}"


class OutputStreamer(threading.Thread):
    """
    Allow streaming and capture of output from run processes.

    This mimics the file interface and can be passed to
    subprocess.Popen({stdout,stderr}=...).
    """
    def __init__(
        self, *, is_stdout: bool = True, capture: bool = True, quiet: bool = False
    ):
        super().__init__()
        self.daemon = False
        self.fd_read, self.fd_write = os.pipe()
        self.pipe_reader = os.fdopen(self.fd_read)
        self.start()
        self.capture = capture
        self.lines = []
        self.is_stdout = is_stdout
        self.quiet = quiet

    def fileno(self):
        return self.fd_write

    def run(self):
        for line in iter(self.pipe_reader.readline, ""):
            if settings.stream_output and not self.quiet:
                settings.output.cmd_run(line.rstrip("\n"), self.is_stdout)
            if self.capture:
                self.lines.append(line)

        self.pipe_reader.close()

    def close(self):
        os.close(self.fd_write)


class CommandFailure(FscmException):
    pass


@dataclass
class RunReturn:
    """
    Wraps subprocess.CompletedProcess and adds convenience methods.
    """

    args: str
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self):
        return self.returncode == 0

    @property
    def assert_ok(self):
        if self.returncode != 0:
            raise RuntimeError(
                f"command failed unexpectedly (code {self.returncode})"
                f"\nstdout:\n{self.stdout.decode()}\n\n"
                f"\nstderr:\n{self.stderr.decode()}\n"
            )
        return self

    @classmethod
    def from_std(cls, cp: subprocess.CompletedProcess):
        return cls(cp.args, cp.returncode, cp.stdout, cp.stderr)


def check_fail(cmd: str, *args, **kwargs) -> bool:
    """Return True if the command failed with a non-zero exit code."""
    kwargs["check"] = False
    kwargs["quiet"] = True

    return _run(cmd, *args, **kwargs).returncode != 0


@contextmanager
def cd(to_path):
    """Contextmanager that `chdir`s to a path for the duration of the cm."""
    old = Path.cwd()
    os.chdir(to_path)
    try:
        yield
    finally:
        os.chdir(old)


def get_secrets(
    keys_needed: t.List[str], pass_key: t.Optional[str] = None
) -> SimpleNamespace:
    """
    Load secrets, extract the necessary subset, and return them as a dict.

    Args:
        keys_needed: of the form `a.b.c`; extract these keys from the loaded secret
            store. Only pass what is necessary to a mitogen context.
    """
    sek = os.environ.get("FSCM_SECRETS")
    out = SimpleNamespace()
    if not sek and pass_key:
        settings.output.log(f"requesting secrets from {pass_key}")
        sek = _run(f"pass show {pass_key}", quiet=True).assert_ok.stdout
    assert sek

    try:
        loaded = json.loads(sek)
    except Exception:
        logger.exception(
            f"failed to deserialize secrets from {pass_key if pass_key else 'env'}"
        )
        raise

    ns = _dict_into_ns(loaded)

    for key in keys_needed:
        _extract_namespace_subset(ns, key, out)

    return out


def _dict_into_ns(d: dict):
    ns = SimpleNamespace()

    for k, v in d.items():
        if isinstance(v, dict):
            setattr(ns, k, _dict_into_ns(v))
        else:
            setattr(ns, k, v)

    return ns


def _extract_namespace_subset(orig: SimpleNamespace, key: str, newns: SimpleNamespace):
    k, *key_rest = key.split(".", 1)
    v = getattr(orig, k)

    if not getattr(newns, k, None):
        # Check to see if there's a value at the key so we don't overwrite common
        # key prefixes.
        setattr(newns, k, SimpleNamespace())

    if key_rest:
        _extract_namespace_subset(v, ".".join(key_rest), getattr(newns, k))
    else:
        setattr(newns, k, v)


def _pytest_extract_dict_subset():
    orig = _dict_into_ns(
        {
            "a": {"b": 2, "c": 3, "x": 2},
            "d": {"e": {"f": 1, "g": 6}},
        }
    )
    newns = SimpleNamespace()

    _extract_namespace_subset(orig, "a.b", newns)
    _extract_namespace_subset(orig, "a.c", newns)
    assert newns == _dict_into_ns({"a": {"b": 2, "c": 3}})

    _extract_namespace_subset(orig, "d.e.f", newns)
    assert newns == _dict_into_ns({"a": {"b": 2, "c": 3}, "d": {"e": {"f": 1}}})

    newns = SimpleNamespace()
    _extract_namespace_subset(orig, "a", newns)
    assert newns == _dict_into_ns({"a": {"b": 2, "c": 3, "x": 2}})


if HAS_MITOGEN:

    @contextmanager
    def mitogen_router():
        broker = mitogen.master.Broker()
        router = mitogen.master.Router(broker)
        try:
            yield router
        finally:
            broker.shutdown()
            broker.join()

    def get_mitogen_context(router, hostname, *args, log_level="INFO", **kwargs):
        kwargs.setdefault("python_path", ["/usr/bin/env", "python3"])
        mitogen.utils.log_to_file(level=log_level)
        settings.output.log(f"SSHing to {hostname}, may require auth...")
        context = (
            router.local(*args, **kwargs)
            if hostname == "localhost"
            else router.ssh(*args, hostname=hostname, **kwargs)
        )
        # router.enable_debug()
        return context

    @contextmanager
    def mitogen_context(hostname, *args, log_level="INFO", router=None, **kwargs):
        kwargs.setdefault("python_path", ["/usr/bin/env", "python3"])
        mitogen.utils.log_to_file(level=log_level)

        with mitogen_router() as router:
            settings.output.log(f"SSHing to {hostname}, may require auth...")
            context = (
                router.local(*args, **kwargs)
                if hostname == "localhost"
                else router.ssh(hostname=hostname, *args, **kwargs)
            )
            # router.enable_debug()
            yield (router, context)


@dataclass
class SymlinkAdd(Change):
    target: str
    linkname: str

    msg: str = "link {linkname} -> {target}"


@dataclass
class SymlinkModify(Change):
    target: str
    old_target: str
    linkname: str

    msg: str = "modify link {linkname} -> {target}"


class UnixSystem:
    def link(
        self,
        target: Pathable,
        dest: Pathable,
        sudo: bool = True,
        overwrite: bool = True,
        flags: str = "-s",
    ) -> ChangeList:
        needs_sudo_for_read = need_sudo_to_read(dest)
        needs_sudo_for_write = need_sudo_to_write(dest)
        exists = None
        current_target = None

        if needs_sudo_for_read:
            if exists := file_exists_sudo(dest):
                current_target = _run(f"readlink {dest}", sudo=sudo).stdout or None
        else:
            if exists := (dest := Path(dest)).exists():
                try:
                    current_target = dest.readlink()
                except OSError:
                    pass

        if needs_sudo_for_write and not sudo:
            raise FscmException(f"installing link to {dest} requires sudo")
        else:
            if not exists:
                _run(f"ln {flags} {target} {dest}", sudo=needs_sudo_for_write)
                return [cl(SymlinkAdd, str(target), str(dest))]
            elif overwrite and current_target != target:
                _run(
                    f"rm {dest} && ln {flags} {target} {dest}",
                    sudo=needs_sudo_for_write,
                )
                return [cl(SymlinkModify, str(target), str(dest))]

        return []

    def is_installed(self, name: str) -> bool:
        return _run(f"which {name}", quiet=True).ok

    def is_debian(self) -> bool:
        return _run("uname -a | grep Debian").ok

    def is_ubuntu(self) -> bool:
        return _run("uname -a | grep Ubuntu").ok


class SymlinkFailure(Exception):
    pass


@dataclass
class PkgAdd(Change):
    pkg_name: str
    msg: str = "system package added: {pkg_name}"


class PkgRm(Change):
    pkg_name: str
    msg: str = "system package removed: {pkg_name}"


class Debian(UnixSystem):
    def bootstrap(self, username, hostname):
        """
        Should be run outside of a mitogen context.

        Get the bare-minimum on target host to be able to run mitogen.
        """
        ok = _run(f'ssh {username}@{hostname} "which python3"', quiet=True).ok

        if not ok:
            settings.output.log(f"bootstrapping host {hostname!r}")
            _run(
                f"ssh {username}@{hostname} "
                '"sudo apt-get update; sudo apt install -y python3 apt"',
                check=True,
            )

    def pkg_is_installed(self, name: str) -> bool:
        ret = _run("dpkg-query -W -f='${Package},${Status}' " + f"'{name}'", quiet=True)

        if not ret.ok:
            return False
        # TODO:
        elif ret.returncode == 1 and "no packages found" in ret.stderr:
            return False

        for line in ret.stdout.splitlines():
            if line.startswith(f"{name},"):
                statuses = line.split(",")[1].split()
                if any(s == "installed" for s in statuses):
                    return True

        return False

    def pkg_install(self, name: str) -> ChangeList:
        if not self.pkg_is_installed(name):
            ensure_sudo("apt-get update")
            _run("DEBIAN_FRONTEND=noninteractive apt-get update", sudo=True, check=True)
            _run(
                f"DEBIAN_FRONTEND=noninteractive apt-get install -q --yes {name}",
                sudo=True,
                check=True,
            )
            return [cl(PkgAdd, name)]
        return []

    def pkgs_install(self, *names) -> ChangeList:
        allnames = []
        for n in names:
            allnames.extend([i.strip() for i in n.split()])

        uninstalled = [n for n in allnames if not self.pkg_is_installed(n)]
        if not uninstalled:
            return []

        ensure_sudo("apt-get update")
        _run("DEBIAN_FRONTEND=noninteractive apt-get update", sudo=True, check=True)
        _run(
            f"DEBIAN_FRONTEND=noninteractive "
            f"apt-get install --yes {' '.join(uninstalled)}",
            sudo=True,
            check=True,
        )

        return [cl(PkgAdd, n) for n in uninstalled]

    def add_apt_source(self, source_name: str, line: str) -> ChangeList:
        return file_(
            f"/etc/apt/sources.list.d/{source_name}.list",
            content=line,
            mode="755",
            sudo=True,
        )

    def apt_add_repo(
        self, repo_name: str, source_created_str: str, keyname: t.Optional[str] = None
    ) -> ChangeList:
        changes = []
        changes.extend(self.pkg_install("software-properties-common"))

        if not Path(f"/etc/apt/sources.list.d/{source_created_str}").exists():
            changes.extend(
                run(f"add-apt-repository -y {repo_name}", check=True, sudo=True)
            )

            if keyname:
                changes.extend(self.apt_add_key(keyname))

            _run("apt update", sudo=True, check=True)
        return changes

    def apt_add_key(self, keyname: str) -> ChangeList:
        return run(
            f"apt-key adv --keyserver keyserver.ubuntu.com --recv-keys {keyname}"
        )

    def service_start(self, service_name: str, enable: bool = False):
        run("systemctl daemon-reload", sudo=True)
        run(f"systemctl start {service_name}", sudo=True)
        if enable:
            run(f"systemctl enable {service_name}.service", sudo=True)


system = Debian()
s = system


def ln(*args, **kwargs) -> ChangeList:
    return s.link(*args, **kwargs)


class Docker:
    """Tested with podman also."""

    def volume_exists(self, name: str) -> bool:
        vols = _run(
            '%s volume ls --filter "name=%s"' % (settings.container_cmd, name),
            quiet=True,
        ).stdout.strip()

        return bool(vols)

    def create_volume(self, name: str) -> ChangeList:
        return run(f"{settings.container_cmd} volume create {name}")

    def _find_container(self, name: str) -> RunReturn:
        return _run(
            '%s ps -a --filter "name=%s" --format "{{.Status}}"'
            % (settings.container_cmd, name),
            quiet=True,
        )

    def is_container_up(self, name: str) -> bool:
        return self._find_container(name).stdout.strip().startswith("Up ")

    def container_exists(self, name: str) -> bool:
        return bool(self._find_container(name).stdout.strip())

    def image_exists(self, name: str) -> bool:
        return _run(
            f'%s image list | grep "^{name} "' % settings.container_cmd, quiet=True
        ).ok


docker = Docker()


@dataclass
class PipPkgAdd(Change):
    pkg_name: str
    msg: str = "pip package added: {pkg_name}"


@dataclass
class Pip:
    """
    TODO this assumes use of a virtualenv - i.e. that we can just refer to `pip`
    and have it do the right thing.
    """

    def pkg_is_installed(self, pkg_name: str) -> bool:
        return not check_fail(f"pip show {pkg_name}")

    def pkg_install(self, pkg_name: str) -> ChangeList:
        if self.pkg_is_installed(pkg_name):
            return []

        _run(f"pip install {pkg_name}", check=True)
        return [cl(PipPkgAdd, pkg_name)]


pip = Pip()


def hostname() -> str:
    return socket.gethostname()


@dataclass
class DirAdd(Change):
    path: Path
    msg: str = "mkdir {path}"


def mkdir(
    p: Pathable,
    mode: t.Optional[str] = None,
    owner: t.Optional[str] = None,
    sudo: bool = False,
    **kwargs,
) -> ChangeList:
    changes = []
    kwargs.setdefault("parents", True)
    kwargs.setdefault("exist_ok", True)
    p = _to_path(p)
    exists = p.exists()
    if mode:
        changes.extend(chmod(p, mode, sudo=sudo))
    if owner:
        changes.extend(chown(p, owner, sudo=sudo))

    if not exists:
        changes.append(cl(DirAdd, p))
    return changes


def _to_path(path: Pathable) -> Path:
    return path if isinstance(path, Path) else Path(path)


def is_file_executable(path: Pathable) -> bool:
    path = _to_path(path)
    return path.is_file() and os.access(path, os.X_OK)


def get_file_mode_user(path: Pathable) -> str:
    """Returns a string like '700'."""
    return oct(os.stat(path).st_mode)[-3:]


def get_file_mode_sudo(path: Pathable) -> str:
    """Returns a string like '700'."""
    return _run(f"stat -c '%a' {path}", quiet=True, sudo=True).stdout.strip()


def get_file_mode(path: Pathable, sudo: bool = False) -> str:
    needs_sudo_read = need_sudo_to_read(path)
    if needs_sudo_read:
        if not sudo:
            raise NeedsSudoException(f"get file mode on {path}")
        return get_file_mode_sudo(str(path))
    return get_file_mode_user(str(path))


@dataclass
class ChmodExecAdd(Change):
    path: Path
    msg: str = "chmod +x {path}"


@dataclass
class ChmodModify(Change):
    path: Path
    mode: str
    old_mode: str
    flags: str
    msg: str = "chmod {flags} {mode} {path} (from {old_mode})"


def make_executable(path: Pathable, sudo: bool = False) -> ChangeList:
    """Make a path executable."""
    path = _to_path(path)
    needs_sudo_w = need_sudo_to_write(path)
    if not is_file_executable(path):
        if needs_sudo_w and not sudo:
            raise NeedsSudoException(f"chmod +x {path}")
        _run(f"chmod +x {path}", check=True, sudo=needs_sudo_w)
        return [cl(ChmodExecAdd, path)]
    return []


def chmod(
    path: Pathable, mode: str, flags: t.Optional[str] = None, sudo: bool = False
) -> ChangeList:
    """Change a path's mode (permissions)."""
    path = _to_path(path)
    curr_mode = get_file_mode(path, sudo)
    needs_sudo = need_sudo_to_write(path)

    if curr_mode != mode:
        if needs_sudo and not sudo:
            raise NeedsSudoException(f"chmod {mode} {path}")
        _run(f"chmod {flags} {mode}", sudo=needs_sudo, check=True)
        return [cl(ChmodModify, path, mode, curr_mode, flags)]
    return []


@dataclass
class ChownModify(Change):
    path: Path
    owner: str
    old_owner: str
    flags: str
    msg: str = "chmod {flags} {owner} {path} (from {old_owner})"


def chown(
    path: Pathable, owner: str, flags: t.Optional[str] = None, sudo: bool = False
) -> ChangeList:
    """Change a path's owner."""
    path = _to_path(path)
    needs_sudo_w = need_sudo_to_write(path)
    needs_sudo_r = need_sudo_to_read(path)

    if needs_sudo_r and not sudo:
        raise NeedsSudoException(f"chown {path}")

    curr_owner = _run(
        f"stat -c '%U:%G' {path}", check=True, sudo=needs_sudo_r
    ).stdout.decode.strip()

    if ":" not in curr_owner:
        curr_owner = curr_owner.split(":", 1)[0]

    if curr_owner != owner:
        if needs_sudo_w and not sudo:
            raise NeedsSudoException(f"chown {owner} {path}")
        _run(f"chown {flags} {owner}", sudo=needs_sudo_w, check=True)
        return [cl(ChownModify, path, owner, curr_owner, flags)]
    return []


def _run(
    cmd: str, check: bool = False, quiet: bool = False, capture: bool = True, **kwargs
) -> RunReturn:
    """Run a command, capturing output and in shell mode by default."""
    kwargs.setdefault("text", True)
    kwargs.setdefault("shell", True)

    stdout = OutputStreamer(quiet=quiet, capture=capture)
    stderr = OutputStreamer(is_stdout=False, quiet=quiet, capture=capture)
    kwargs["stdout"] = stdout
    kwargs["stderr"] = stderr

    sudo = bool(kwargs.pop("sudo", False))

    if sudo:
        settings.output.alert(f"running sudo: {cmd}")
        ensure_sudo(cmd)
        cmd = f'sudo bash -c "{cmd}"'

    r = None

    if DEBUG:
        logger.info(f"running command {cmd!r}")

    start = time.time()

    with subprocess.Popen(cmd, **kwargs) as s:
        stdout.close()
        stderr.close()
        stdout.join()
        stderr.join()
        s.wait()
        r = RunReturn(
            s.args, s.returncode, "".join(stdout.lines), "".join(stderr.lines)
        )

    end = time.time()
    totaltime = end - start

    if totaltime > 0.1:
        logger.debug("cmd %r took %.3f seconds", cmd, end - start)

    if DEBUG:
        CMD_TIMES[(time.time(), cmd)] = totaltime

    if not r.ok:
        if not quiet:
            logger.warning(
                "Command failed (code {}): {}\nstdout:\n{}\n\nstderr:{}\n".format(
                    r.returncode, cmd, r.stdout, r.stderr
                )
            )

        if check:
            raise CommandFailure

    return r


run = _run


def runmany(cmds: CmdStrs, check: bool = True, **kwargs) -> t.List[RunReturn]:
    out = []

    for cmd in _split_cmd_input(cmds):
        r = _run(cmd, **kwargs)
        out.append(r)

        if check and not r.ok:
            break

    return out


def ensure_sudo(for_cmd: str):
    """Ensure we have sudo, prompting otherwise."""
    if _run("sudo -S true </dev/null", quiet=True).ok:
        # Sudo is cached
        return
    settings.output.alert(f"requesting sudo for {for_cmd!r}")
    # Slight race here obviously - cache may have expired since above.
    subprocess.run("sudo -S true", shell=True)


def dir(
    path: Pathable,
    mode: t.Optional[str] = None,
    owner: t.Optional[str] = None,
    sudo: bool = False,
):
    changes = []
    path = _to_path(path)
    if not path.exists():
        _run(f"mkdir -p {path}", sudo=sudo)
        changes.append(cl(DirAdd, path))

    if mode:
        changes.extend(chmod(path, mode))
    if owner:
        changes.extend(chown(path, owner))

    return changes


def file_exists_sudo(path: t.Union[str, Path]):
    return _run(f"test -e {path}", quiet=True, sudo=True).ok


def file_(
    path: Pathable,
    content: t.Union[str, Path],
    mode: str = None,
    owner: str = None,
    sudo: bool = False,
) -> ChangeList:
    path: Path = Path(path)
    changes = []

    exists = False

    if isinstance(content, Path):
        content = content.read_text()

    def set_perms(p: Pathable) -> ChangeList:
        cs = []
        if mode:
            cs.extend(chmod(p, mode, sudo=sudo))
        if owner:
            cs.extend(chown(p, owner, sudo=sudo))
        return cs

    needs_sudo_r = False
    try:
        exists = path.exists()
    except PermissionError:
        needs_sudo_r = True
        if sudo:
            exists = file_exists_sudo(path)
        else:
            raise FscmException("can't detect file {path} without sudo")

    if exists:
        if needs_sudo_r and not sudo:
            raise NeedsSudoException(f"can't read file {path} without sudo")

        txt = None
        if needs_sudo_r:
            txt = _run(f"cat {path}", sudo=True, quiet=True).stdout
        else:
            txt = path.read_text()

        assert txt is not None

        changes.extend(set_perms(path))

        if txt == content:
            # No change
            return changes
        logger.warn(f"path {path} already exists - overwriting")

        diff = "".join(
            difflib.unified_diff(
                [f"{i}\n" for i in txt.splitlines()],
                [f"{i}\n" for i in content.splitlines()],
                fromfile="original",
                tofile="new",
            )
        )

        settings.output.log(f"  diff on {path}:\n{textwrap.indent(diff, '    ')}")
        changes.append(cl(FileModify, path, diff))

    # New file

    if sudo:
        tmp = _get_tempfile(path if exists else None)
        set_perms(tmp)
        # Important to set perms before we write the contents.
        tmp.write_text(content)

        _run(f"mv {tmp} {path}", sudo=True)
    else:
        _run(f"touch {path}")
        set_perms(path)
        # Important to set perms before we write the contents.
        path.write_text(content)

    if not exists:
        changes.append(cl(FileAdd, path))

    return changes


def need_sudo_to_read(path: Pathable) -> bool:
    try:
        Path(path).exists()
    except PermissionError:
        return True
    return False


def need_sudo_to_write(path: Pathable) -> bool:
    path = _to_path(path)
    try:
        if not path.exists():
            # Check the containing dir for perms
            path = path.parent
        return not os.access(path, os.W_OK)
    except PermissionError:
        return True


def lineinfile(
    path: Pathable,
    content_or_func: t.Union[str, t.Callable],
    regex: t.Optional[Regex] = None,
    after_line: t.Optional[Regex] = None,
    sudo: bool = False,
) -> ChangeList:
    """
    Kwargs:
        content_or_func: note that newlines are appended to this value,
            and should not be included explicitly.
        regex: replace the matched line with `content_or_func`
        after_line: if a line cannot be found with `regex`, insert
            `content_or_func` after a line matching `after_line`

    Returns:
        whether or not the file was modified.

    TODO fix up for sudo capabilities
    """
    target = Path(path)

    if not target.exists():
        raise ValueError(f"{path} doesn't exist, can't be modified")

    lines = target.read_text().splitlines()
    patt = None
    after_patt = None

    if not (regex or after_line):
        raise ValueError("must specify either regex or after_line")

    if regex:
        patt = regex if isinstance(regex, re.Pattern) else re.compile(regex)
    if after_line:
        after_patt = (
            after_line if isinstance(after_line, re.Pattern) else re.compile(after_line)
        )

    newlines: t.List[str] = []
    modified = False

    def search(p: t.Union[str, re.Pattern], line: str) -> bool:
        return bool(re.search(p, line))

    def modify_line(old_line):
        return (
            content_or_func(old_line) if callable(content_or_func) else content_or_func
        )

    if patt:
        for line in lines:
            if search(patt, line):
                mod_line = modify_line(line)

                # Line already exists in file as it should.
                if line == mod_line:
                    return []

                modified = True
                newlines.append(mod_line)
            else:
                newlines.append(line)

    if not after_patt and not modified:
        newlines.append(modify_line(""))
        modified = True
    elif after_patt:
        # Prefer a regex-based replacement for the existing line (above) but
        # if we can't find a match, insert the line after this one.
        newlines = []
        for i, line in enumerate(lines):
            if search(after_patt, line):
                mod_line = modify_line("")

                # Line already exists in file as it should.
                if len(lines) > i and lines[i] == mod_line:
                    return False

                newlines.extend([line, mod_line])
                modified = True
            else:
                newlines.append(line)

    if not modified:
        return []

    tmp = _get_tempfile(target)
    chmod(tmp, get_file_mode(path, sudo))
    tmp.write_text("\n".join(newlines) + '\n')

    _run(f"mv {tmp} {path}", sudo=sudo)
    if sudo:
        # TODO fix this
        _run(f"chown root:root {path}", sudo=sudo)

    # TODO - implement diff
    return [cl(FileModify, path)]


def _get_tempfile(like_path: t.Optional[Path] = None) -> Path:
    p = Path(tempfile.mkstemp()[1])

    if like_path:
        p.chmod(int(get_file_mode(like_path), 8))

    return p


_running_promises: t.List[AsyncResult] = []
_pool = None


def run_bg(cmds: CmdStrs) -> AsyncResult:
    return exec_bg(run, (cmds,))


def exec_bg(fnc: t.Callable, args: t.Tuple) -> AsyncResult:
    global _pool
    if not _pool:
        _pool = ThreadPool(processes=6)

    async_res = _pool.apply_async(fnc, args)
    return async_res


def join_bg(timeout=None) -> t.List[object]:
    vals = [res.get(timeout=timeout) for res in _running_promises]
    _running_promises.clear()
    return vals


def this_file_path() -> Path:
    return Path(
        inspect.getfile(inspect.getouterframes(inspect.currentframe())[1].frame)
    ).absolute()


def template(path: t.Union[str, Path], **kwargs) -> str:
    p = Path(path)
    if p.is_absolute():
        text = p.read_text()
    else:
        p = this_dir_path(2) / p
        text = p.read_text()

    return Template(text).safe_substitute(**kwargs)


def this_dir_path(frame_idx=1) -> Path:
    """
    Returns the path to the dir containing the file that calls this function
    (not the dir containing *this* file).
    """
    # This code needs to be duplicated (instead of caling this_file_path()
    # because of the frame indexing.
    return Path(
        os.path.realpath(
            os.path.dirname(
                inspect.getfile(
                    inspect.getouterframes(inspect.currentframe())[frame_idx].frame
                )
            )
        )
    ).absolute()


def _pytest_this_file():
    assert this_file_path().name == "fscm.py"


def _split_cmd_input(cmds: CmdStrs) -> t.List[str]:
    if isinstance(cmds, list):
        return cmds
    cmds = textwrap.dedent(str(cmds))
    # Eat linebreaks
    cmds = re.sub(r"\s+\\\n\s+", " ", cmds)
    return [i.strip() for i in cmds.splitlines() if i]


def _pytest_split_cmds():
    assert _split_cmd_input(
        r"""
    ls -lah | \
      grep this \
        that and the other
    echo 'foo'
    """
    ) == [
        "ls -lah | grep this that and the other",
        "echo 'foo'",
    ]
    assert _split_cmd_input(
        """
    ls -lah | grep this that and the other
    echo 'foo'
    """
    ) == [
        "ls -lah | grep this that and the other",
        "echo 'foo'",
    ]


def download_and_check_sha(url: str, sha256: str) -> Path:
    topath = Path(tempfile.gettempdir())
    p = PurePosixPath(unquote(urlparse(url).path))
    end = p.parts[-1]
    output_path = topath / end

    if not output_path.exists():
        urllib.request.urlretrieve(url, filename=output_path)

    sha = hashlib.sha256()

    with open(output_path, "rb") as f:
        while data := f.read(1024 * 1024):
            sha.update(data)

    if sha256 != sha.hexdigest():
        raise FscmException(
            f"unexpected sha256 from {url}: got {sha.hexdigest()}, expected {sha256}"
        )

    return output_path


def print_slow_commands():
    cmds = list(
        reversed(sorted([(k[1], v) for k, v in CMD_TIMES.items()], key=lambda i: i[1]))
    )

    for cmd, time in cmds[:25]:
        settings.output.log(f"{time:<20.2} {cmd:<30}")
