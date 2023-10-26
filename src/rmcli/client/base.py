"""Client base"""
from typing import Optional, Type, Tuple, Self, cast
from types import TracebackType
from dataclasses import dataclass, field
from pathlib import Path
import ssl
import logging

import aiohttp
from libpvarki.mtlshelp.session import get_session
from libpvarki.mtlshelp.context import get_ca_context
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

LOGGER = logging.getLogger(__name__)


def ca_session() -> aiohttp.ClientSession:
    """Insert cas, return session"""
    ssl_ctx = get_ca_context(ssl.Purpose.SERVER_AUTH)
    conn = aiohttp.TCPConnector(ssl=ssl_ctx)
    return aiohttp.ClientSession(connector=conn)


@dataclass
class RMClientBase:
    """Rasenmaeher Client base"""

    url_base: str = field()
    timeout: float = field(default=5.0)
    _session: aiohttp.ClientSession = field(default_factory=ca_session)

    def __post_init__(self) -> None:
        """Set basic stuff"""
        self._session.headers["Accept"] = "application/json"
        if self.url_base.endswith("/"):
            self.url_base = self.url_base[:-1]

    async def set_identity(self, certfile: Path, keyfile: Path) -> None:
        """Set identity to mTLS cert"""
        await self._session.close()
        self._session = get_session((certfile, keyfile))

    def set_jwt(self, jwt: str) -> None:
        """Set JWT to bearer token"""
        self._session.headers["Authorization"] = f"Bearer {jwt}"

    async def exchange_logincode(self, logincode: str) -> None:
        """Exchange login code to JWT and set it to session auth"""
        resp = await self._session.post(
            f"{self.url_base}/api/v1/token/code/exchange",
            json={"code": logincode},
            timeout=self.timeout,
        )
        LOGGER.debug("resp={}".format(resp))
        resp.raise_for_status()
        payload = await resp.json()
        LOGGER.debug("payload={}".format(payload))
        self.set_jwt(payload["jwt"])

    async def get_callsign(self) -> str:
        """Get the callsign for the currently authenticated session"""
        resp = await self._session.get(
            f"{self.url_base}/api/v1/check-auth/mtls_or_jwt",
            timeout=self.timeout,
        )
        LOGGER.debug("resp={}".format(resp))
        resp.raise_for_status()
        payload = await resp.json()
        LOGGER.debug("payload={}".format(payload))
        return str(payload["userid"])

    async def get_cert(self, callsign: Optional[str] = None) -> Tuple[bytes, bytes]:
        """Download the pfx, decode it and return the cert and key as PEM"""
        if not callsign:
            callsign = await self.get_callsign()
        resp = await self._session.get(
            f"{self.url_base}/api/v1/enduserpfx/{callsign}.pfx",
            timeout=self.timeout,
        )
        LOGGER.debug("resp={}".format(resp))
        resp.raise_for_status()
        pfxbytes = await resp.read()
        pfxdata = pkcs12.load_pkcs12(pfxbytes, callsign.encode("utf-8"))
        private_key = cast(rsa.RSAPrivateKey, pfxdata.key)
        keybytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        if not pfxdata.cert:
            raise ValueError("PFX did not contain cert (this should never happen)")
        cert = pfxdata.cert.certificate
        certbytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
        return certbytes, keybytes

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        await self._session.close()
