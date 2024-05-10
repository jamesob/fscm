import getpass
import typing as t
import pwd
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent

from ..fscm import run, run_ro, p, RunReturn, cl, settings, CommandFailure
from ..changes import ChangeList, Change
from . import docker


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


def user_simple_service(*args, **kwargs) -> ChangeList:
    """
    Install a very basic service unit at the user level.
    """
    kwargs['user'] = getpass.getuser()
    return simple_service(*args, **kwargs)


def simple_service(
    service_name: str,
    description: str,
    exec_start_contents: str,
    user: str = 'root',
    working_directory: str | None = None,
    sudo: bool = True,
    wanted_by: str = "multi-user.target",
    contents: str | None = None,
) -> ChangeList:
    """
    Install a very basic service unit; by default at the root level.
    """
    changes: ChangeList = []

    working_directory_line = ""
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
        WantedBy={wanted_by}
    """
    )

    if user == 'root':
        conf_dir = Path("/etc/systemd/system")
    else:
        assert Path(f"/home/{user}").exists()
        conf_dir = Path(f"/home/{user}/.config/systemd/user")
        changes.extend(
            p(conf_dir, sudo=sudo).mkdir().chown(f"{user}:{user}").changes)

    service_changes = (
        p(conf_dir / f"{service_name}.service", sudo=sudo)
        .contents(contents)
        .chown(f"{user}")
        .chmod("650")
        .changes
    )
    changes.extend(service_changes)
    changes.extend(activate_service(user, service_name, bool(service_changes)))

    return changes


def activate_service(user: str, service_name: str, has_changed: bool) -> ChangeList:
    uflag = '--user' if user != 'root' else ''
    if has_changed:
        run_as_user(user, f"systemctl {uflag} daemon-reload").assert_ok()
    return enable_service(
        service_name, now=True, restart=has_changed, sudo=(user == 'root'))


def docker_compose_service(
    service_name,
    description: str,
    path: Path | str,
    env: str = "",
    docker_compose_path: str | None = None,
) -> ChangeList:
    """Create a basic docker-compose service."""
    if not docker_compose_path:
        if not (docker_compose_path := docker.get_compose_command()):
            raise RuntimeError("docker compose not installed")

    contents = dedent(
        f"""
        [Unit]
        Description={description}

        [Service]
        Type=oneshot
        Environment={env}
        WorkingDirectory={path}
        RemainAfterExit=true

        ExecStartPre={docker_compose_path} pull
        ExecStart={docker_compose_path} up -d --remove-orphans
        ExecStop={docker_compose_path} rm -fs

        [Install]
        WantedBy=default.target
        """
    )
    return user_simple_service(service_name, description, "", contents=contents)


def _user_flag(as_user: t.Optional[str] = None):
    as_user = as_user or getpass.getuser()
    is_root = as_user == "root"
    return "--user" if not is_root else "--user"


def is_service_running(
    service_name: str, as_user: t.Optional[str] = None, sudo: bool = False
) -> bool:
    return service_status(service_name, as_user, sudo=sudo) == "active"


def enable_service(
    service_name: str,
    now: bool = True,
    restart: bool = False,
    sudo: bool = False,
) -> ChangeList:
    changes = []
    uflag = _user_flag() if not sudo else ""

    status = run(
        f"systemctl {uflag} is-enabled {service_name}", check=False, quiet=True
    )
    if "disabled" in status.stdout or not status.ok:
        run(f"systemctl {uflag} enable {service_name}", sudo=sudo).assert_ok()
        changes.append(cl(ServiceEnabled, service_name))

    is_running = is_service_running(service_name, sudo=sudo)

    try:
        if now and not is_running:
            run(f"systemctl {uflag} start {service_name}", sudo=sudo).assert_ok()
            changes.append(cl(ServiceStarted, service_name))
        elif is_running and restart:
            run(f"systemctl {uflag} restart {service_name}", sudo=sudo).assert_ok()
            changes.append(cl(ServiceRestarted, service_name))
    except CommandFailure:
        settings.output.log(
            f"service {service_name} failed to start; journalctl says")
        run_ro(f"journalctl {uflag} -u {service_name}", sudo=sudo)
        raise

    return changes


def restart_service(
    service_name: str,
    start: bool = True,
    sudo: bool = False,
) -> ChangeList:
    return enable_service(service_name, start, restart=True, sudo=sudo)

def service_status(
    service_name: str, as_user: t.Optional[str] = None, sudo: bool = False
) -> str:
    uf = _user_flag(as_user) if not sudo else ""
    cmd = f"systemctl show {uf} {service_name} --no-page"
    info = str(
        run_as_user(as_user, cmd, quiet=True, destructive=False)
        .assert_ok()
        .stdout
    )

    infod: dict[str, str] = dict([i.split("=", 1) for i in info.splitlines()])
    return infod["ActiveState"]

def run_as_user(
    user: t.Optional[str], cmd: str, *args, **kwargs
) -> RunReturn:
    user = user or getpass.getuser()
    uid = pwd.getpwnam(user).pw_uid
    needs_sudo = getpass.getuser() != user

    # Per https://unix.stackexchange.com/q/245768
    env = (
        f'XDG_RUNTIME_DIR="/run/user/{uid}" '
        f'DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/{uid}/bus"'
    )

    if needs_sudo:
        kwargs['sudo'] = True
        return run(f"sudo -i -u {user} {env} {cmd}", *args, **kwargs)
    else:
        return run(f"{env} {cmd}", *args, **kwargs)
