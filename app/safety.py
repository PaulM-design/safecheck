import asyncio
import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeTarget(ValueError):
    pass


async def validate_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeTarget("Only absolute HTTP(S) URLs are accepted")
    if parsed.username or parsed.password:
        raise UnsafeTarget("Credentials in target URLs are not accepted")
    if parsed.port and parsed.port not in {80, 443, 8080, 8443}:
        raise UnsafeTarget("Only standard web ports are accepted")

    try:
        literal = ipaddress.ip_address(parsed.hostname)
        addresses = [literal]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            records = await loop.getaddrinfo(
                parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise UnsafeTarget("Target hostname could not be resolved") from exc
        addresses = list({ipaddress.ip_address(record[4][0]) for record in records})

    if not addresses or any(not address.is_global for address in addresses):
        raise UnsafeTarget("Private, loopback, link-local, reserved, and mixed-address targets are blocked")

