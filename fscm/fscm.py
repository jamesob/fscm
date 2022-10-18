# TODO: figure out global default su strategy
# TODO: "version control"-ish file backup option
# TODO: document sudo requirement
# TODO: generic hosts.yml parser, CLI app factory
import os
import hashlib
import os.path
import subprocess
import time
import ast
import re
import textwrap
import threading
import difflib
import inspect
import getpass
import socket
import datetime
import logging
import pwd
import sys
import tempfile
import typing as t
from textwrap import dedent
from types import SimpleNamespace
from contextlib import contextmanager
from urllib.parse import unquote, urlparse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from string import Template
from multiprocessing.pool import ThreadPool, AsyncResult

from .thirdparty import color as c
from .secrets import Secrets

HAS_MITOGEN = True
try:
    import mitogen  # noqa
except ImportError:
    HAS_MITOGEN = False
else:
    from .remote import *
    from fscm import remote

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
    # TODO
    # dry: bool = False
    output: OutputHandler = field(default_factory=OutputHandler)
    container_cmd: str = field(default="docker")

    # If specified, automatially piped into `sudo -S | [cmd]` for any command requiring
    # privilege escalation.
    sudo_password: t.Optional[str] = None

    def __repr__(self):
        def hide(k, v):
            return "[hidden]" if k in {"sudo_password"} else v

        attrs = ", ".join("%s=%r" % (k, hide(k, v)) for k, v in self.__dict__.items())
        return f"{self.__class__.__name__}({attrs})"

    def get_cached_sudo_password(self) -> t.Optional[str]:
        cached_from_remote = None
        if HAS_MITOGEN:
            assert remote
            cached_from_remote = remote.CACHED_SUDO_PASSWORD

        logger.debug("setting cached sudo password")
        return self.sudo_password or cached_from_remote


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

    def assert_ok(self):
        if self.returncode != 0:
            raise RuntimeError(
                f"command failed unexpectedly (code {self.returncode})"
                f"\nstdout:\n{self.stdout}\n\n"
                f"\nstderr:\n{self.stderr}\n"
            )
        return self

    @classmethod
    def from_std(cls, cp: subprocess.CompletedProcess):
        return cls(cp.args, cp.returncode, cp.stdout, cp.stderr)


def check_fail(cmd: str, *args, **kwargs) -> bool:
    """Return True if the command failed with a non-zero exit code."""
    kwargs["check"] = False
    kwargs["quiet"] = True

    return run(cmd, *args, **kwargs).returncode != 0


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
    keys_needed: t.Optional[t.List[str]] = None, pass_key: t.Optional[str] = None
) -> Secrets:
    """
    Load secrets, extract the necessary subset, and return them as a dict.

    Args:
        keys_needed: of the form `a.b.c`; extract these keys from the loaded secret
            store. Only pass what is necessary to a mitogen context.
    """
    sek = os.environ.get("FSCM_SECRETS")
    ALL_KEYS = ['*']
    keys_needed = keys_needed or ALL_KEYS
    out = Secrets()
    if not sek and pass_key:
        settings.output.log(f"requesting secrets from {pass_key}")
        sek = run(f"pass show {pass_key}", quiet=True).assert_ok().stdout
    assert sek

    try:
        loaded = ast.literal_eval(sek)
    except Exception:
        logger.exception(
            f"failed to deserialize secrets from {pass_key if pass_key else 'env'}"
        )
        raise

    ns = _dict_into_ns(loaded)

    if keys_needed != ALL_KEYS:
        for key in keys_needed:
            _extract_namespace_subset(ns, key, out)
    else:
        out = ns

    return out


def _dict_into_ns(d: dict):
    ns = Secrets()

    for k, v in d.items():
        if isinstance(v, dict):
            setattr(ns, k, _dict_into_ns(v))
        else:
            setattr(ns, k, v)

    return ns


def _extract_namespace_subset(orig: Secrets, key: str, newns: Secrets):
    k, *key_rest = key.split(".", 1)
    v = getattr(orig, k)

    if not getattr(newns, k, None):
        # Check to see if there's a value at the key so we don't overwrite common
        # key prefixes.
        setattr(newns, k, Secrets())

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
    newns = Secrets()

    _extract_namespace_subset(orig, "a.b", newns)
    _extract_namespace_subset(orig, "a.c", newns)
    assert newns == _dict_into_ns({"a": {"b": 2, "c": 3}})

    _extract_namespace_subset(orig, "d.e.f", newns)
    assert newns == _dict_into_ns({"a": {"b": 2, "c": 3}, "d": {"e": {"f": 1}}})

    newns = Secrets()
    _extract_namespace_subset(orig, "a", newns)
    assert newns == _dict_into_ns({"a": {"b": 2, "c": 3, "x": 2}})

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
                current_target = run(f"readlink {dest}", sudo=sudo).stdout or None
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
                run(f"ln {flags} {target} {dest}", sudo=needs_sudo_for_write)
                return [cl(SymlinkAdd, str(target), str(dest))]
            elif overwrite and current_target != target:
                run(
                    f"rm {dest} && ln {flags} {target} {dest}",
                    sudo=needs_sudo_for_write,
                )
                return [cl(SymlinkModify, str(target), str(current_target), str(dest))]

        return []

    def is_installed(self, name: str) -> bool:
        return run(f"which {name}", quiet=True).ok

    def is_debian(self) -> bool:
        return run("uname -a | grep Debian").ok

    def is_ubuntu(self) -> bool:
        return run("uname -a | grep Ubuntu").ok


class SymlinkFailure(Exception):
    pass


@dataclass
class PkgAdd(Change):
    pkg_name: str
    version: str
    source: str
    msg: str = "package {pkg_name} added from {source}: {version}"


@dataclass
class PkgRm(Change):
    pkg_name: str
    msg: str = "system package removed: {pkg_name}"


@dataclass
class PkgUpgrade(Change):
    pkg_name: str
    old_ver: str
    new_ver: str
    msg: str = "package {pkg_name} upgraded: {old_ver} -> {new_ver}"


@dataclass
class UserGroupAdd(Change):
    user: str
    group_name: str
    msg: str = "user {user} added to group {group_name}"


class Debian(UnixSystem):
    def bootstrap(self, username, hostname):
        """
        Should be run outside of a mitogen context.

        Get the bare-minimum on target host to be able to run mitogen.
        """
        ok = run(f'ssh {username}@{hostname} "which python3"', quiet=True).ok

        if not ok:
            settings.output.log(f"bootstrapping host {hostname!r}")
            run(
                f"ssh {username}@{hostname} "
                '"sudo apt-get update; sudo apt install -y python3 apt"',
                check=True,
            )

    def pkg_is_installed(self, name: str) -> bool:
        ret = run("dpkg-query -W -f='${Package},${Status}' " + f"'{name}'", quiet=True)

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

    def pkg_install(self, name: str, sudo: bool = True) -> ChangeList:
        if not self.pkg_is_installed(name):
            run("DEBIAN_FRONTEND=noninteractive apt-get update", sudo=sudo, check=True)
            run(
                f"DEBIAN_FRONTEND=noninteractive apt-get install -q --yes {name}",
                sudo=sudo,
                check=True,
            )
            return [cl(PkgAdd, name, self.pkg_get_installed_version(name), "apt")]
        return []

    def pkg_get_installed_version(self, name: str) -> t.Optional[str]:
        output = run(f'dpkg -s {name} | grep "^Version: "').stdout
        if "Version: " not in output:
            return None
        return output.split("Version: ")[-1].strip()

    def pkgs_install(self, *names, sudo: bool = True) -> ChangeList:
        allnames = []
        for n in names:
            allnames.extend([i.strip() for i in n.split()])

        uninstalled = [n for n in allnames if not self.pkg_is_installed(n)]
        if not uninstalled:
            return []

        run("DEBIAN_FRONTEND=noninteractive apt-get update", sudo=sudo, check=True)
        run(
            f"DEBIAN_FRONTEND=noninteractive "
            f"apt-get install --yes {' '.join(uninstalled)}",
            sudo=sudo,
            check=True,
        )

        added = []
        for n in uninstalled:
            added.append(cl(PkgAdd, n, self.pkg_get_installed_version(n), "apt"))
        return added

    def add_apt_source(
        self, source_name: str, line: str, sudo: bool = True
    ) -> ChangeList:
        return file(
            f"/etc/apt/sources.list.d/{source_name}.list",
            content=line,
            mode="755",
            sudo=sudo,
        )

    def apt_add_repo(
        self,
        repo_name: str,
        source_created_str: str,
        keyname: t.Optional[str] = None,
        sudo: bool = True,
    ) -> ChangeList:
        changes = []
        changes.extend(self.pkg_install("software-properties-common"))

        if not Path(f"/etc/apt/sources.list.d/{source_created_str}").exists():
            changes.extend(
                run(f"add-apt-repository -y {repo_name}", check=True, sudo=sudo)
            )

            if keyname:
                changes.extend(self.apt_add_key(keyname))

            run("apt update", sudo=sudo, check=True)
        return changes

    def apt_add_key(self, keyname: str) -> ChangeList:
        return run(
            f"apt-key adv --keyserver keyserver.ubuntu.com --recv-keys {keyname}",
            sudo=True,
        )

    def service_start(self, service_name: str, enable: bool = False, sudo: bool = True):
        run("systemctl daemon-reload", sudo=sudo)
        run(f"systemctl start {service_name}", sudo=sudo)
        if enable:
            run(f"systemctl enable {service_name}.service", sudo=sudo)

    def group_member(self, user: str, group: str) -> ChangeList:
        """Ensure a user's membership in a group."""
        if group in run(f"groups {user}", quiet=True).stdout.split():
            return []
        run(f"usermod -aG {group} {user}", sudo=True)
        return [cl(UserGroupAdd, user, group)]


system = Debian()
s = system


def ln(*args, **kwargs) -> ChangeList:
    return s.link(*args, **kwargs)


class Docker:
    """Tested with podman also."""

    def volume_exists(self, name: str) -> bool:
        vols = run(
            '%s volume ls --filter "name=%s"' % (settings.container_cmd, name),
            quiet=True,
        ).stdout.strip()

        return bool(vols)

    def create_volume(self, name: str) -> ChangeList:
        return run(f"{settings.container_cmd} volume create {name}")

    def _find_container(self, name: str) -> RunReturn:
        return run(
            '%s ps -a --filter "name=%s" --format "{{.Status}}"'
            % (settings.container_cmd, name),
            quiet=True,
        )

    def is_container_up(self, name: str) -> bool:
        return self._find_container(name).stdout.strip().startswith("Up ")

    def container_exists(self, name: str) -> bool:
        return bool(self._find_container(name).stdout.strip())

    def image_exists(self, name: str) -> bool:
        return run(
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

        run(f"pip install {pkg_name}", check=True)
        return [cl(PipPkgAdd, pkg_name)]


pip = Pip()


def hostname() -> str:
    return socket.gethostname()


@dataclass
class DirAdd(Change):
    path: Path
    msg: str = "mkdir {path}"


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
    return run(f"stat -c '%a' {path}", quiet=True, sudo=True).stdout.strip()


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
        run(f"chmod +x {path}", check=True, sudo=needs_sudo_w)
        return [cl(ChmodExecAdd, path)]
    return []


def chmod(
    path: Pathable,
    mode: t.Union[str, int],
    flags: t.Optional[str] = None,
    sudo: bool = False,
) -> ChangeList:
    """Change a path's mode (permissions)."""
    path = _to_path(path)
    flags = flags or ""
    curr_mode = get_file_mode(path, sudo)
    needs_sudo = need_sudo_to_write(path)

    if not isinstance(mode, str):
        mode = str(mode)

    if curr_mode != mode:
        if needs_sudo and not sudo:
            raise NeedsSudoException(f"chmod {mode} {path}")
        run(f"chmod {flags} {mode} {path}", sudo=needs_sudo, check=True)
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
    # TODO fails when changing to root:root from a user who can write
    needs_sudo_w = need_sudo_to_write(path)
    needs_sudo_r = need_sudo_to_read(path)
    flags = flags or ""

    if owner.split(":")[0].startswith("root"):
        needs_sudo_w = True

    if needs_sudo_r and not sudo:
        raise NeedsSudoException(f"chown {path}")

    curr_owner = run(
        f"stat -c '%U:%G' {path}", check=True, sudo=needs_sudo_r, quiet=True
    ).stdout.strip()

    if ":" not in curr_owner:
        curr_owner = curr_owner.split(":", 1)[0]

    if curr_owner != owner:
        if needs_sudo_w and not sudo:
            raise NeedsSudoException(f"chown {owner} {path}")
        run(f"chown {flags} {owner} {path}", sudo=needs_sudo_w, check=True)
        return [cl(ChownModify, path, owner, curr_owner, flags)]
    return []


def run(
    cmd: str, check: bool = False, quiet: bool = False, capture: bool = True, **kwargs
) -> RunReturn:
    """
    Run a command, capturing output and in shell mode by default.

    'q' is also a kwarg alias for quiet.
    """
    cmd = cmd.strip()
    kwargs.setdefault("text", True)
    kwargs.setdefault("shell", True)

    if "q" in kwargs:
        quiet = bool(kwargs.pop("q"))

    stdout = OutputStreamer(quiet=quiet, capture=capture)
    stderr = OutputStreamer(is_stdout=False, quiet=quiet, capture=capture)
    kwargs["stdout"] = stdout
    kwargs["stderr"] = stderr

    sudo = bool(kwargs.pop("sudo", False))
    cached_sudo_password = None

    if sudo:
        settings.output.alert(f"running sudo: {cmd}")
        if cached_sudo_password := settings.get_cached_sudo_password():
            cmd = f'sudo -S -- bash -c "{cmd}"'
            if "stdin" in kwargs:
                raise ValueError("can't pass stdin when using sudo -S")
            kwargs["stdin"] = subprocess.PIPE
        else:
            ensure_sudo(cmd)
            cmd = f'sudo bash -c "{cmd}"'

    r = None

    if DEBUG:
        logger.info(f"running command {cmd!r}")

    start = time.time()

    def to_s(s) -> str:
        if isinstance(s, bytes):
            return s.decode()
        return s

    with subprocess.Popen(cmd, **kwargs) as s:
        if sudo and cached_sudo_password:
            assert s.stdin
            s.stdin.write(f"{cached_sudo_password}\n")
            s.stdin.close()
        stdout.close()
        stderr.close()
        stdout.join()
        stderr.join()
        s.wait()
        r = RunReturn(
            s.args,
            s.returncode,
            to_s("".join(stdout.lines)),
            to_s("".join(stderr.lines)),
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


def getstdout(*args, **kwargs) -> str:
    """A shorthand for quietly (by default) getting stdout from a shell command."""
    kwargs.setdefault("quiet", True)
    return run(*args, **kwargs).stdout.strip()


def runmany(cmds: CmdStrs, check: bool = True, **kwargs) -> t.List[RunReturn]:
    out = []

    for cmd in _split_cmd_input(cmds):
        r = run(cmd, **kwargs)
        out.append(r)

        if check and not r.ok:
            break

    return out


def ensure_sudo(for_cmd: str):
    """Ensure we have sudo, prompting otherwise."""
    if run("sudo -S true </dev/null", quiet=True).ok:
        # Sudo is cached
        return
    settings.output.alert(f"requesting sudo for {for_cmd!r}")
    # Slight race here obviously - cache may have expired since above.
    subprocess.run("sudo -S true", shell=True)


class DirectoryExistsError(Exception):
    pass


def mkdir(
    path: Pathable,
    mode: t.Optional[str] = None,
    owner: t.Optional[str] = None,
    sudo: bool = False,
    parents: bool = True,
    exist_ok: bool = True,
):
    changes = []
    path = _to_path(path)
    parents_flag = "-p" if parents else ""

    if not path.exists():
        run(f"mkdir {parents_flag} {path}", check=True, sudo=sudo)
    elif not exist_ok:
        raise DirectoryExistsError(path)

    if mode:
        changes.extend(chmod(path, mode, sudo=sudo))
    if owner:
        changes.extend(chown(path, owner, sudo=sudo))

    return changes


def file_exists_sudo(path: t.Union[str, Path]):
    return run(f"test -e {path}", quiet=True, sudo=True).ok


def file(
    path: Pathable,
    content: t.Union[str, bytes, Path],
    mode: str = None,
    owner: str = None,
    sudo: bool = False,
) -> ChangeList:
    path: Path = Path(path)
    changes = []

    exists = False

    if isinstance(content, bytes):
        content = content.decode()

    if isinstance(content, Path):
        content = content.read_text()

    assert isinstance(content, str)

    newline = "\n"
    if isinstance(content, bytes):
        newline = b"\n"

    if not content.endswith(newline):
        content += newline

    def set_perms(p: Pathable) -> ChangeList:
        cs = []
        if mode:
            cs.extend(chmod(p, mode, sudo=sudo))
        if owner:
            cs.extend(chown(p, owner, sudo=sudo))
        return cs

    if needs_sudo_r := need_sudo_to_read(path):
        if sudo:
            exists = file_exists_sudo(path)
        else:
            raise FscmException(f"can't detect file {path} without sudo")
    else:
        exists = path.exists()

    if exists:
        txt = None
        if needs_sudo_r:
            txt = run(f"cat {path}", sudo=True, quiet=True).stdout
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
        tmp = _get_tempfile(path if exists else None, sudo)
        tmp.write_text(content)
        set_perms(tmp)

        run(f"mv {tmp} {path}", sudo=True).assert_ok()
    else:
        run(f"touch {path}").assert_ok()
        set_perms(path)
        # Important to set perms before we write the contents.
        path.write_text(content)

    if not exists:
        changes.append(cl(FileAdd, path))

    return changes


# TODO remove this old name
file_ = file


def need_sudo_to_read(path: Pathable) -> bool:
    p = _to_path(path)
    try:
        exists = p.exists()
    except PermissionError:
        return True

    return not os.access(p if exists else p.parent, os.R_OK)


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

    tmp = _get_tempfile(target, sudo)
    chmod(tmp, get_file_mode(path, sudo))
    tmp.write_text("\n".join(newlines) + "\n")

    run(f"mv {tmp} {path}", sudo=sudo)
    if sudo:
        # TODO fix this
        run(f"chown root:root {path}", sudo=sudo)

    # TODO - implement diff
    return [cl(FileModify, path)]


def _get_tempfile(like_path: t.Optional[Path] = None, sudo: bool = False) -> Path:
    p = Path(tempfile.mkstemp()[1])

    if like_path:
        p.chmod(int(get_file_mode(like_path, sudo), 8))

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
    """
    Use Template.safe_substitute to fill out and return a template from the filesystem.
    """
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
    assert (
        _split_cmd_input(
            r"""
    ls -lah | \
      grep this \
        that and the other
    echo 'foo'
    """
        )
        == [
            "ls -lah | grep this that and the other",
            "echo 'foo'",
        ]
    )
    assert (
        _split_cmd_input(
            """
    ls -lah | grep this that and the other
    echo 'foo'
    """
        )
        == [
            "ls -lah | grep this that and the other",
            "echo 'foo'",
        ]
    )


def download_and_check_sha(url: str, sha256: str) -> Path:
    topath = Path(tempfile.gettempdir())
    p = PurePosixPath(unquote(urlparse(url).path))
    end = p.parts[-1]
    output_path = topath / end

    if not output_path.exists():
        tries = 3
        sleep_secs = 0.5

        while tries > 0:
            try:
                urllib.request.urlretrieve(url, filename=output_path)
            except urllib.error.URLError as e:
                if tries <= 0 or "Device or resource busy" not in str(e):
                    raise
                logger.exception(f'Hit "device busy" when retrieving {url}')
                tries -= 1
                time.sleep(sleep_secs)
                sleep_secs *= 2
            else:
                break

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


@dataclass
class PathHelper:
    path: Path
    sudo: t.Optional[bool] = None
    changes: t.List[ChangeList] = field(default_factory=list)

    def rm(self, flags: str = "", **kwargs) -> "PathHelper":
        kwargs = self._fill_default_kwargs(kwargs)

        if self.path.exists():
            run(f"rm {flags} {self.path}", **kwargs)
            self.changes.append([FileRm(str(self.path))])
        return self

    def contents(self, *args, **kwargs) -> "PathHelper":
        kwargs = self._fill_default_kwargs(kwargs)
        self.changes.extend(file(self.path, *args, **kwargs))
        return self

    def content(self, *args, **kwargs) -> "PathHelper":
        return self.contents(*args, **kwargs)

    def chmod(self, *args, **kwargs) -> "PathHelper":
        kwargs = self._fill_default_kwargs(kwargs)
        self.changes.extend(chmod(self.path, *args, **kwargs))
        return self

    def chown(self, *args, **kwargs) -> "PathHelper":
        kwargs = self._fill_default_kwargs(kwargs)
        self.changes.extend(chown(self.path, *args, **kwargs))
        return self

    def mkdir(self, *args, **kwargs) -> "PathHelper":
        kwargs = self._fill_default_kwargs(kwargs)
        self.changes.extend(mkdir(self.path, *args, **kwargs))
        return self

    def _fill_default_kwargs(self, kwargs: dict) -> dict:
        if self.sudo is not None and "sudo" not in kwargs:
            kwargs["sudo"] = self.sudo
        return kwargs


def p(pathlike: t.Union[Path, str], *args, **kwargs) -> PathHelper:
    return PathHelper(Path(pathlike), *args, **kwargs)


@dataclass
class ServiceAdded(Change):
    service_name: str
    msg: str = "add service {service_name}"


@dataclass
class ServiceEnabled(Change):
    service_name: str
    msg: str = "enabled service {service_name}"


@dataclass
class ServiceStarted(Change):
    service_name: str
    msg: str = "started service {service_name}"


@dataclass
class ServiceRestarted(Change):
    service_name: str
    msg: str = "restarted service {service_name}"


@dataclass
class ServiceStopped(Change):
    service_name: str
    msg: str = "restarted service {service_name}"


class Systemd:
    """
    Various utilities for working with systemd.
    """

    def user_service(
        self,
        service_name: str,
        description: str,
        exec_start_contents: str,
        user: t.Optional[str] = None,
        working_directory: t.Optional[str] = None,
        sudo: bool = False,
        contents: t.Optional[str] = None,
    ) -> ChangeList:
        """
        Install a very basic service unit at the user level.
        """
        changes: ChangeList = []
        user = user or getpass.getuser()

        working_directory_line = ''
        if working_directory:
            working_directory_line = f"WorkingDirectory = {working_directory}"

        contents = contents or dedent(
            f"""
            [Unit]
            Description={description}

            [Service]
            Type=simple
            StandardOutput=journal
            ExecStart={exec_start_contents}
            {working_directory_line}

            [Install]
            WantedBy=default.target
        """
        )

        user_dir = Path(f"/home/{user}/.config/systemd/user")
        changes.extend(p(user_dir, sudo=sudo).mkdir().chown(f'{user}:{user}').changes)

        service_change = (
            p(user_dir / f"{service_name}.service", sudo=sudo)
            .contents(contents)
            .chown(f'{user}:{user}')
            .chmod("600")
            .changes
        )
        changes.extend(service_change)

        self.run_as_user(user, f"systemctl --user enable {service_name}.service").assert_ok()

        is_running = self.is_service_running(service_name, as_user=user)
        action = 'start'
        if service_change:
            action = 'restart'

        if service_change or not is_running:
            self.run_as_user(user, f"systemctl --user {action} {service_name}.service")

        return changes

    def _user_flag(self, as_user: t.Optional[str] = None):
        as_user = as_user or getpass.getuser()
        is_root = as_user == 'root'
        return '--user' if not is_root else '--user'

    def is_service_running(self, service_name: str, as_user: t.Optional[str] = None, sudo: bool = False) -> bool:
        return self.service_status(service_name, as_user, sudo=sudo) == 'active'

    def enable_service(self, service_name: str, start: bool = True, restart: bool = False, sudo: bool = False) -> ChangeList:
        uflag = self._user_flag() if not sudo else ''

        status = run(f'systemctl {uflag} is-enabled {service_name}', quiet=True)
        if 'disabled' in status.stdout or not status.ok:
            run(f'systemctl {uflag} enable {service_name}', sudo=sudo).assert_ok()

        is_running = self.is_service_running(service_name, sudo=sudo)
        if start and not is_running:
            run(f'systemctl {uflag} start {service_name}', sudo=sudo).assert_ok()
        elif is_running and restart:
            run(f'systemctl {uflag} restart {service_name}', sudo=sudo).assert_ok()

        # TODO fill this changelist out
        return []

    def service_status(self, service_name: str, as_user: t.Optional[str] = None, sudo: bool = False) -> str:
        uf = self._user_flag(as_user) if not sudo else ''
        cmd = f"systemctl show {uf} {service_name} --no-page"
        info = self.run_as_user(as_user, cmd, quiet=True).assert_ok().stdout

        infod = dict([i.split('=', 1) for i in info.splitlines()])

        if 'ActiveState' not in infod:
            print(infod)
        return infod['ActiveState']

    def restart_service(self, name: str, as_user: t.Optional[str] = None, sudo: bool = False) -> RunReturn:
        uf = self._user_flag(as_user) if not sudo else ''
        self.run_as_user(as_user, f'systemctl {uf} restart {name}')

    def run_as_user(self, user: str, cmd: str, *args, **kwargs) -> RunReturn:
        user = user or getpass.getuser()
        uid = pwd.getpwnam(user).pw_uid
        needs_sudo = getpass.getuser() != user

        # Per https://unix.stackexchange.com/q/245768
        env = (
            f'XDG_RUNTIME_DIR="/run/user/{uid}" '
            f'DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/{uid}/bus"')

        if needs_sudo:
            return run(f"sudo -i -u {user} {env} {cmd}", *args, **kwargs)
        else:
            return run(f"{env} {cmd}", *args, **kwargs)


systemd = Systemd()
