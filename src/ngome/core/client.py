"""The caller's address, as Google's front end saw it.

Cloud Run appends the address it accepted the connection from to ``X-Forwarded-For``.
Anything to the left of that entry was written by the caller and can be made up, so it is
never used. ``NGOME_PROXY_HOPS`` says how many entries from the right that address sits
(1 on Cloud Run; 2 behind a Google load balancer, which appends its own). Without the
header (local runs, tests), the socket's peer is used.

Uvicorn's ``--proxy-headers`` with ``FORWARDED_ALLOW_IPS=*`` sets ``request.client`` from
the *leftmost* entry, which is why this reads the header itself.
"""

import ipaddress

from starlette.requests import Request


def client_address(request: Request, hops: int) -> str | None:
    """The trusted client address as text, or ``None`` when there is none to trust."""
    values = request.headers.getlist("x-forwarded-for")
    if values and hops > 0:
        entries = [e.strip() for e in ",".join(values).split(",") if e.strip()]
        if len(entries) < hops:
            return None
        return _valid(entries[-hops])
    peer = request.scope.get("client")
    return _valid(peer[0]) if peer else None


def _valid(text: str) -> str | None:
    # "[2001:db8::1]:443" or "203.0.113.7:51000" from some proxies; plain addresses otherwise.
    host = text
    if host.startswith("[") and "]" in host:
        host = host[1 : host.index("]")]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None
