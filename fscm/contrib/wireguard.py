import re
import typing as t
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from ipaddress import IPv4Address

import yaml
import fscm
from fscm import p, run, file_, ChangeList, s, remote
import textwrap


@dataclass
class WireguardPeer:
    name: str
    ip: IPv4Address
    pubkey: str
    endpoint: str
    a: t.Optional[str] = None
    dns: t.Optional[str] = None


@dataclass
class WireguardServer:
    name: str
    cidr: str
    port: int
    pubkey: str
    interfaces: t.List[str]
    host: str
    external_peers: t.Map[str, str]

    @classmethod
    def from_dict(cls, name, d):
        return cls(
            name,
            cidr=d["cidr"],
            port=int(d["port"]),
            pubkey=d["pubkey"],
            interfaces=d["interfaces"],
            host=d["host"],
            external_peers=d.get('external_peers', {}),
        )


def wg_server_config(wg: WireguardServer, hosts: [Host]) -> str:
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
        [pubkey, ip] = [i.strip() for i in val.split(',')]
        if ip.endswith('/32'):
            ip = ip.rstrip('/32')

        conf += dedent(
            f"""

            [Peer]
            # {name}
            PublicKey = {pubkey}
            AllowedIPs = {ip}/32
            """
        )

    return conf


def wireguard_server(host: Host, wg: WireguardServer, hosts: [Host]):
    fscm.s.pkgs_install("wireguard-tools")

    if not wg.pubkey:
        pubkey = make_wireguard_privkey(wg.name)
        print(f"Pubkey for {host}, {wg} is {pubkey}")

    changed = (
        p(f"/etc/wireguard/{wg.name}.conf", sudo=True)
        .contents(wg_server_config(wg, hosts))
        .changes
    )

    fscm.systemd.enable_service(f"wg-quick@{wg.name}", restart=bool(changed), sudo=True)


def wireguard_peer(host: Host, wgs: dict[str, WireguardServer]):
    for wgname, wg in host.wireguards.items():
        server = wgs[wg.name]
        changed = bool(
            p(f"/etc/wireguard/{wg.name}.conf", sudo=True)
            .contents(wireguard_peer_config(host, server, wg))
            .changes
        )

        fscm.systemd.enable_service(f"wg-quick@{wg.name}", restart=changed, sudo=True)


def wireguard_peer_config(host: Host, wgs: WireguardServer, wg: WireguardPeer):
    first_host = wgs.cidr.split('/')[0]
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


def make_wireguard_privkey(wg_name: str, overwrite: bool = False) -> t.Optional[str]:
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


