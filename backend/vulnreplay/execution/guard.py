"""Target authorization, SSRF and DNS-rebinding protection for outbound test traffic."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1", "ip6-localhost"}
ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "100.64.0.0/10",
        "192.0.0.0/24",
        "198.18.0.0/15",
        "::/128",
        "fe80::/10",
        "ff00::/8",
        "fd00:ec2::254/128",
    )
]
Resolver = Callable[[str, int], list[str]]


class TargetNotAllowed(PermissionError):
    """Raised when a request would leave the explicitly authorized target."""


def default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


@dataclass
class TargetGuard:
    """Validates every outbound URL and every resolved address against an authorized target.

    * scheme must be http/https; credentials in URLs are rejected
    * host must equal the authorized target host *and* appear in the global allowlist
    * all resolved addresses are checked (link-local / metadata / multicast are always blocked);
      private and loopback ranges are only reachable when the target is local or explicitly
      flagged ``allow_private_network`` by an administrator
    * the checked IP is pinned for the connection, defeating DNS rebinding
    """

    base_url: str
    allowed_hosts: list[str]
    allow_private_network: bool = False
    resolver: Resolver = field(default=default_resolver)

    def __post_init__(self) -> None:
        parts = urlsplit(self.base_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise TargetNotAllowed("Target base URL must be an absolute http(s) URL")
        if parts.username or parts.password:
            raise TargetNotAllowed("Credentials in target URLs are not allowed")
        self.host = parts.hostname.lower()
        self.scheme = parts.scheme
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        allowed = {h.lower().strip() for h in self.allowed_hosts}
        if self.host not in allowed:
            raise TargetNotAllowed(f"Host '{self.host}' is not in the execution allowlist")
        self.is_local = self.host in LOOPBACK_NAMES

    def check_url(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"}:
            raise TargetNotAllowed(f"Scheme '{parts.scheme}' is not allowed")
        if parts.username or parts.password:
            raise TargetNotAllowed("Credentials in URLs are not allowed")
        host = (parts.hostname or "").lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if host != self.host or port != self.port or parts.scheme != self.scheme:
            raise TargetNotAllowed(f"Destination {parts.scheme}://{host}:{port} is outside the authorized target")

    def _ip_allowed(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if any(ip in net for net in ALWAYS_BLOCKED_NETWORKS):
            return False
        if ip.is_loopback:
            return self.is_local or self.allow_private_network
        if ip.is_private or ip.is_reserved:
            return self.allow_private_network
        return not self.is_local  # a "localhost" target must never resolve to a public address

    def resolve(self, host: str, port: int) -> str:
        if host.lower() != self.host:
            raise TargetNotAllowed(f"Host '{host}' is outside the authorized target")
        try:
            addresses = self.resolver(host, port)
        except OSError as exc:
            raise TargetNotAllowed(f"Could not resolve '{host}': {exc}") from exc
        if not addresses:
            raise TargetNotAllowed(f"'{host}' did not resolve")
        for addr in addresses:
            if not self._ip_allowed(ipaddress.ip_address(addr.split("%")[0])):
                raise TargetNotAllowed(f"'{host}' resolves to disallowed address {addr}")
        return addresses[0]


class GuardedTransport(httpx.BaseTransport):
    """httpx transport that re-validates and pins the resolved IP for every single request."""

    def __init__(self, guard: TargetGuard, verify: bool = True) -> None:
        self.guard = guard
        self._inner = httpx.HTTPTransport(verify=verify, retries=0)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.guard.check_url(str(request.url))
        host = request.url.host
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        pinned_ip = self.guard.resolve(host, port)
        default_port = port == (443 if request.url.scheme == "https" else 80)
        request.headers["Host"] = host if default_port else f"{host}:{port}"
        if request.url.scheme == "https":
            request.extensions = {**request.extensions, "sni_hostname": host}
        request.url = request.url.copy_with(host=pinned_ip)
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()
