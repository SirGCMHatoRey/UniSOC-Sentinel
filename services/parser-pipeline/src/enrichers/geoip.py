"""GeoIP enricher using MaxMind GeoLite2-City database."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import urllib.request
import gzip
import shutil
import tarfile
from pathlib import Path
from typing import Any, Optional

import geoip2.database
import geoip2.errors

from .base import BaseEnricher

logger = logging.getLogger(__name__)

# RFC 1918 + special-purpose ranges that we skip for GeoIP
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),    # link-local
    ipaddress.ip_network("100.64.0.0/10"),     # shared address space
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]


def _is_private(ip_str: str) -> bool:
    """Return True if the IP is private/loopback/link-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True  # treat unparseable as private → skip


class GeoIPEnricher(BaseEnricher):
    """
    Enrich IP addresses with geographic information from a MaxMind
    GeoLite2-City database.

    - Returns None for private / loopback / link-local IPs.
    - Handles missing DB file gracefully (logs a warning, returns None).
    - Optionally downloads the DB if MAXMIND_LICENSE_KEY is provided and
      the file is missing.
    """

    def __init__(self, db_path: str, maxmind_license_key: Optional[str] = None) -> None:
        self._db_path = Path(db_path)
        self._license_key = maxmind_license_key
        self._reader: Optional[geoip2.database.Reader] = None
        self._available = False

    async def initialize(self) -> None:
        """Load the database; optionally download if missing."""
        if not self._db_path.exists():
            if self._license_key:
                logger.info("GeoIP DB not found — attempting download", extra={"path": str(self._db_path)})
                await self._download_db()
            else:
                logger.warning(
                    "GeoIP database not found and MAXMIND_LICENSE_KEY not set — "
                    "GeoIP enrichment disabled",
                    extra={"path": str(self._db_path)},
                )
                return

        if self._db_path.exists():
            try:
                self._reader = geoip2.database.Reader(str(self._db_path))
                self._available = True
                logger.info("GeoIP database loaded", extra={"path": str(self._db_path)})
            except Exception as exc:
                logger.error("Failed to open GeoIP database", exc_info=exc)

    async def _download_db(self) -> None:
        """Download GeoLite2-City.mmdb from MaxMind (runs in executor)."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._do_download)

    def _do_download(self) -> None:
        url = (
            f"https://download.maxmind.com/app/geoip_download"
            f"?edition_id=GeoLite2-City&license_key={self._license_key}&suffix=tar.gz"
        )
        tmp_tar = self._db_path.parent / "GeoLite2-City.tar.gz"
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            logger.info("Downloading GeoLite2-City database from MaxMind...")
            urllib.request.urlretrieve(url, str(tmp_tar))  # noqa: S310
            with tarfile.open(str(tmp_tar), "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith(".mmdb"):
                        member.name = self._db_path.name  # flatten path
                        tar.extract(member, str(self._db_path.parent))
                        break
            logger.info("GeoLite2-City database downloaded successfully")
        except Exception as exc:
            logger.error("Failed to download GeoLite2-City database", exc_info=exc)
        finally:
            if tmp_tar.exists():
                tmp_tar.unlink(missing_ok=True)

    async def enrich(self, ip_str: str) -> Optional[dict[str, Any]]:
        """Return GeoIP data for the given IP, or None."""
        if not self._available or not self._reader:
            return None
        if not ip_str or _is_private(ip_str):
            return None

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._lookup, ip_str)

    def _lookup(self, ip_str: str) -> Optional[dict[str, Any]]:
        try:
            record = self._reader.city(ip_str)
            lat = record.location.latitude
            lon = record.location.longitude
            return {
                "country_iso_code": record.country.iso_code,
                "country_name": record.country.name,
                "city_name": record.city.name,
                "location": {
                    "lat": lat,
                    "lon": lon,
                } if lat is not None and lon is not None else None,
            }
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as exc:
            logger.debug("GeoIP lookup error for %s: %s", ip_str, exc)
            return None

    async def close(self) -> None:
        if self._reader:
            self._reader.close()
            self._reader = None
