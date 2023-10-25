"""User specific opertaions"""
from typing import Dict, List
from dataclasses import dataclass, field
import logging
import base64

from .base import RMClientBase


LOGGER = logging.getLogger(__name__)


@dataclass
class UserFile:
    """File gotten from server"""

    title: str = field()
    content: bytes = field(repr=False)
    filename: str = field()


class UserClient(RMClientBase):
    """Client for user ops, all of these require some auth"""

    async def get_files(self) -> Dict[str, List[UserFile]]:
        """Get all user files we can"""
        resp = await self._session.get(
            f"{self.url_base}/api/v1/instructions/user",
            timeout=self.timeout,
        )
        LOGGER.debug("resp={}".format(resp))
        resp.raise_for_status()
        payload = await resp.json()
        assert isinstance(payload["files"], dict)
        ret: Dict[str, List[UserFile]] = {}
        for product, filelist in payload["files"].items():
            if not filelist:
                LOGGER.warning("Product {} did not have files".format(product))
                continue
            for fpl in filelist:
                data = str(fpl["data"])
                assert data.startswith("data:")
                _, b64data = data.split(",")
                dec = base64.b64decode(b64data)
                if product not in ret:
                    ret[product] = []
                ret[product].append(UserFile(str(fpl["title"]), dec, str(fpl["filename"])))
        return ret
