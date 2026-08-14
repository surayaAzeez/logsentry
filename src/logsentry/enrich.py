"""IP enrichment: geolocation and reputation hints.

LogSentry ships an offline CIDR table rather than calling a geo-IP API, so the
tool runs air-gapped and the test suite is deterministic. The table is coarse
(country/city centroids) — enough for impossible-travel maths, not enough for
street-level attribution.

To use real data, drop in MaxMind GeoLite2 and swap :func:`lookup`; the rest of
the codebase only depends on the :class:`GeoInfo` return type.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from functools import lru_cache
from math import asin, cos, radians, sin, sqrt
from pathlib import Path

_DATA_FILE = Path(__file__).parent / "data" / "geoip.json"


@dataclass(frozen=True)
class GeoInfo:
    country: str
    city: str
    latitude: float
    longitude: float
    asn: str = ""

    @property
    def label(self) -> str:
        return f"{self.city}, {self.country}"


@lru_cache(maxsize=1)
def _load_table() -> list[tuple[ipaddress.IPv4Network, GeoInfo]]:
    if not _DATA_FILE.exists():
        return []
    raw = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    table: list[tuple[ipaddress.IPv4Network, GeoInfo]] = []
    for entry in raw:
        try:
            network = ipaddress.ip_network(entry["cidr"], strict=False)
        except ValueError:
            continue
        if not isinstance(network, ipaddress.IPv4Network):
            continue
        table.append(
            (
                network,
                GeoInfo(
                    country=entry["country"],
                    city=entry["city"],
                    latitude=float(entry["lat"]),
                    longitude=float(entry["lon"]),
                    asn=entry.get("asn", ""),
                ),
            )
        )
    # Longest prefix first so a /24 override beats the /8 it sits inside.
    table.sort(key=lambda item: item[0].prefixlen, reverse=True)
    return table


@lru_cache(maxsize=4096)
def lookup(ip: str) -> GeoInfo | None:
    """Return geo info for ``ip``, or ``None`` if unknown/private."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if address.is_private or address.is_loopback:
        return GeoInfo(country="--", city="Internal network", latitude=0.0, longitude=0.0)
    if not isinstance(address, ipaddress.IPv4Address):
        return None
    for network, info in _load_table():
        if address in network:
            return info
    return None


def haversine_km(
    lat1: float, lon1: float, lat2: float, lon2: float
) -> float:
    """Great-circle distance between two points, in kilometres."""
    earth_radius_km = 6371.0
    d_lat = radians(lat2 - lat1)
    d_lon = radians(lon2 - lon1)
    a = (
        sin(d_lat / 2) ** 2
        + cos(radians(lat1)) * cos(radians(lat2)) * sin(d_lon / 2) ** 2
    )
    return 2 * earth_radius_km * asin(sqrt(a))
