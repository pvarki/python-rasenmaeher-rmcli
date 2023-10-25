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

    async def create_pool(self) -> str:
        """Create new enrollment pool (aka invitecode)

        Requires admin identity"""
        resp = await self._session.post(
            f"{self.url_base}/api/v1/enrollment/invitecode/create",
            json=None,
            timeout=self.timeout,
        )
        LOGGER.debug("resp={}".format(resp))
        resp.raise_for_status()
        payload = await resp.json()
        LOGGER.debug("payload={}".format(payload))
        return str(payload["invite_code"])

    async def approve(self, callsign: str, code: str) -> None:
        """Approve enrollment

        Requires admin identity"""
        resp = await self._session.post(
            f"{self.url_base}/api/v1/enrollment/accept",
            json={
                "callsign": callsign,
                "approvecode": code,
            },
            timeout=self.timeout,
        )
        LOGGER.debug("resp={}".format(resp))
        resp.raise_for_status()
        payload = await resp.json()
        LOGGER.debug("payload={}".format(payload))

    async def enroll_user_init(self, callsign: str, invitecode: str) -> Tuple[str, str]:
        """Start enrollment, returns the approvecode and JWT to fetch data once approved"""
        resp = await self._session.post(
            f"{self.url_base}/api/v1/enrollment/invitecode/enroll",
            json={"callsign": callsign, "invite_code": invitecode},
            timeout=self.timeout,
        )
        LOGGER.debug("resp={}".format(resp))
        resp.raise_for_status()
        payload = await resp.json()
        LOGGER.debug("payload={}".format(payload))
        return payload["approvecode"], payload["jwt"]

    async def enrollment_is_approved(self, jwt: str) -> bool:
        """Check if we are approved"""
        self.set_jwt(jwt)
        resp = await self._session.get(
            f"{self.url_base}/api/v1/enrollment/have-i-been-accepted",
            timeout=self.timeout,
        )
        LOGGER.debug("resp={}".format(resp))
        resp.raise_for_status()
        payload = await resp.json()
        LOGGER.debug("payload={}".format(payload))
        return bool(payload["have_i_been_accepted"])

    async def enroll_user_finish(self, callsign: str, jwt: str) -> Tuple[bytes, bytes]:
        """Finish the enrollment by downloading the cert"""
        if not await self.enrollment_is_approved(jwt):
            raise RuntimeError("Not yet approved")
        return await self.get_cert(callsign)
