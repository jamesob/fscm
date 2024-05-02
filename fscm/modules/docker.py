from ..fscm import run, run_ro, RunReturn, settings
from ..changes import ChangeList


def get_compose_command() -> str | None:
    """Returns the absolute-path docker compose command invocation."""

    if (podman_c := run_ro("which podman-compose")).ok:
        return podman_c.stdout.strip()
    elif run_ro("docker compose --help").ok:
        return run_ro("which docker").stdout.strip() + " compose"
    else:
        return run_ro("which docker-compose").stdout.strip()

    return None


def volume_exists(name: str) -> bool:
    vols = run_ro('%s volume ls --filter "name=%s"' %
                  (settings.container_cmd, name),).stdout.strip()

    return bool(vols)


def create_volume(name: str) -> ChangeList:
    return [run(f"{settings.container_cmd} volume create {name}").to_change]


def _find_container(name: str) -> RunReturn:
    return run_ro(
        '%s ps -a --filter "name=%s" --format "{{.Status}}"' %
        (settings.container_cmd, name),)


def is_container_up(name: str) -> bool:
    """Return true if the container is up."""
    return _find_container(name).stdout.strip().startswith("Up ")


def container_exists(name: str) -> bool:
    """Return true if the container exists."""
    return bool(_find_container(name).stdout.strip())


def image_exists(name: str) -> bool:
    """Return true if the container image exists."""
    return run_ro(f'%s image list | grep "^{name} "' % settings.container_cmd).ok
