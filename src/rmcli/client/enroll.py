"""Enrollment things"""
from typing import Tuple
import logging

from .base import RMClientBase


LOGGER = logging.getLogger(__name__)


class EnrollClient(RMClientBase):
    """Client for enrollments"""

    async def enroll_admin(self, callsign: str, logincode: str) -> Tuple[bytes, bytes]:
        """Run the admin enrollment flow, return certificate and key as PEM"""
        await self.exchange_logincode(logincode)
        resp = await self._session.post(
            f"{self.url_base}/api/v1/firstuser/add-admin",
            json={"callsign": callsign},
            timeout=self.timeout,
        )
        LOGGER.debug("resp={}".format(resp))
        resp.raise_for_status()
        payload = await resp.json()
        LOGGER.debug("payload={}".format(payload))
        await self.exchange_logincode(payload["jwt_exchange_code"])
        return await self.get_cert(callsign)
