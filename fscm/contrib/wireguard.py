import typing as t
import logging
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from ipaddress import IPv4Address

import fscm
from fscm import p, run, remote

logger = logging.getLogger(__name__)


@dataclass
class Peer:
    name: str
    ip: IPv4Address
    pubkey: str
    endpoint: str
    a: t.Optional[str] = None
    dns: t.Optional[str] = None


@dataclass
class Server:
    name: str
    cidr: str
    port: int
    pubkey: str
    interfaces: t.List[str]
    host: str
    external_peers: t.Dict[str, str]

    @classmethod
    def from_dict(cls, name, d):
        return cls(
            name,
            cidr=d["cidr"],
            port=int(d["port"]),
            pubkey=d["pubkey"],
            interfaces=d["interfaces"],
            host=d["host"],
            external_peers=d.get("external_peers", {}),
        )


class WireguardHostType(t.Protocol):
    wireguards: t.Dict[str, Peer]
    name: str


class Host(remote.Host):
    """A mixin that adds the .wireguard attribute to a Host."""

    def __init__(
        self,
        *args,
        wgs: t.Optional[t.Dict[str, Peer]] = None,
        **kwargs,
    ):
        kwargs.setdefault("ssh_hostname", args[0] + ".lan")
        super().__init__(*args, **kwargs)
        self.wireguards = wgs or {}

    @classmethod
    def from_dict(cls, name, d):
        wgd = d.pop("wireguard", {})
        instance = super().from_dict(name, d)
        wgs = {}

        for wgname, netd in wgd.items():
            wgs[wgname] = Peer(wgname, **netd)

        instance.wireguards = wgs
        return instance


def wg_server_config(wg: Server, hosts: t.List[WireguardHostType]) -> str:
    hosts = [h for h in hosts if wg.name in h.wireguards]

    conf = dedent(
        f"""
    [Interface]
    Address = {wg.cidr}
    ListenPort = {wg.port}

    PostUp = wg set %i private-key /etc/wireguard/{wg.name}-privkey
    PreUp = sysctl -w net.ipv4.ip_forward=1

    PostUp = iptables -I INPUT 1 -i {wg.name} -j ACCEPT
    PostUp = iptables -I FORWARD 1 -o {wg.name} -j ACCEPT
    PostDown = iptables -D INPUT -i {wg.name} -j ACCEPT
    PostDown = iptables -D FORWARD -o {wg.name} -j ACCEPT
    """
    ).lstrip()

    for iface in wg.interfaces:
        conf += dedent(
            f"""
            PostUp = iptables -I INPUT 1 -i {iface} -p udp -m udp --dport {wg.port} -j ACCEPT
            PostDown = iptables -D INPUT -i {iface} -p udp -m udp --dport {wg.port} -j ACCEPT
            """
        ).lstrip()

    for host in hosts:
        hwg = host.wireguards[wg.name]

        if not hwg.pubkey:
            continue

        conf += dedent(
            f"""

            [Peer]
            # {host.name}
            PublicKey = {hwg.pubkey}
            AllowedIPs = {hwg.ip}/32
            """
        )

    for name, val in wg.external_peers.items():
        [pubkey, ip] = [i.strip() for i in val.split(",")]
        if ip.endswith("/32"):
            ip = ip.rstrip("/32")

        conf += dedent(
            f"""

            [Peer]
            # {name}
            PublicKey = {pubkey}
            AllowedIPs = {ip}/32
            """
        )

    return conf


def server(
    host: remote.Host, wg: Server, hosts: t.List[WireguardHostType]
):
    fscm.s.pkgs_install("wireguard-tools")

    if not wg.pubkey:
        pubkey = make_privkey(wg.name)
        print(f"Pubkey for {host}, {wg} is {pubkey}")

    changed = (
        p(f"/etc/wireguard/{wg.name}.conf", sudo=True)
        .contents(wg_server_config(wg, hosts))
        .changes
    )

    fscm.systemd.enable_service(f"wg-quick@{wg.name}", restart=bool(changed), sudo=True)


def peer(host: WireguardHostType, wgs: dict[str, Server]):
    fscm.s.pkgs_install("wireguard-tools")

    for wg in host.wireguards.values():
        if not wg.pubkey:
            pubkey = make_privkey(wg.name)
            if not pubkey:
                logger.warn(f"privkey for {host}, {wg} already exists - using that")
                pubkey = (
                    run(
                        f"cat /etc/wireguard/{wg.name}-privkey | wg pubkey",
                        sudo=True,
                        quiet=True,
                    )
                    .assert_ok()
                    .stdout
                )

            logger.info(f"setting pubkey for {wg}: {pubkey}")
            wg.pubkey = pubkey

        server = wgs[wg.name]
        changed = bool(
            p(f"/etc/wireguard/{wg.name}.conf", sudo=True)
            .contents(peer_config(server, wg))
            .changes
        )

        fscm.systemd.enable_service(f"wg-quick@{wg.name}", restart=changed, sudo=True)


def peer_config(wgs: Server, wg: Peer) -> str:
    first_host = wgs.cidr.split("/")[0]
    return dedent(
        f"""
        [Interface]
        Address = {wg.ip}/32
        PostUp = wg set %i private-key /etc/wireguard/{wg.name}-privkey
        PostUp = sleep 0.5; nc -nvuz {first_host} {wgs.port}
        {f'# DNS = {wg.dns}' if wg.dns else ''}

        [Peer]
        PublicKey = {wgs.pubkey}
        AllowedIPs = {wgs.cidr}
        Endpoint = {wg.endpoint}:{wgs.port}
        PersistentKeepalive = 25
        """
    ).lstrip()


def make_privkey(wg_name: str, overwrite: bool = False) -> t.Optional[str]:
    privkey = Path(f"/etc/wireguard/{wg_name}-privkey")
    if not overwrite:
        if run(f"ls {privkey}", sudo=True, quiet=True).ok:
            return None

    return (
        run(
            f"( umask 077 & wg genkey | tee {privkey} | wg pubkey )",
            sudo=True,
            quiet=True,
        )
        .assert_ok()
        .stdout.strip()
    )
