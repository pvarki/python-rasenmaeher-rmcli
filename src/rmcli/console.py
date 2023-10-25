"""CLI entrypoints for rmcli"""
from typing import Optional
import asyncio
import logging
from pathlib import Path
import os

import click
from libadvian.logging import init_logging

from rmcli import __version__
from rmcli.client.enroll import EnrollClient

LOGGER = logging.getLogger(__name__)


@click.group()
@click.version_option(version=__version__)
@click.pass_context
@click.option("-l", "--loglevel", help="Python log level, 10=DEBUG, 20=INFO, 30=WARNING, 40=CRITICAL", default=30)
@click.option("-v", "--verbose", count=True, help="Shorthand for info/debug loglevel (-v/-vv)")
@click.option(
    "--capath", help="Path to extra CA certs to accept", type=click.Path(exists=True), default=None, required=False
)
@click.option("--timeout", type=float, default=5.0)
@click.argument("url", required=True)
def cli_group(  # pylint: disable=R0913
    ctx: click.Context, loglevel: int, verbose: int, url: str, timeout: float, capath: Optional[Path]
) -> None:
    """CLI interface to RASENMAEHER API"""
    if verbose == 1:
        loglevel = 20
    if verbose >= 2:
        loglevel = 10
    init_logging(loglevel)
    LOGGER.setLevel(loglevel)

    if capath:
        LOGGER.info("Extra certs from {}".format(capath))
        os.environ["LOCAL_CA_CERTS_PATH"] = str(capath)

    ctx.ensure_object(dict)
    ctx.obj["loop"] = asyncio.get_event_loop()
    ctx.obj["url"] = url
    ctx.obj["timeout"] = timeout


@cli_group.command(name="enroll")
@click.option("-a", "--admin", is_flag=True, help="Do admin entrollment")
@click.argument("code", required=True)
@click.argument("callsign", required=True)
@click.pass_context
def enroll(ctx: click.Context, admin: bool, callsign: str, code: str) -> None:
    """Do enrollment, write callsign.crt and callsign.key"""

    async def enroll_actual() -> int:
        """Do enrollment, write callsign.crt and callsign.key"""
        nonlocal ctx, admin, callsign, code
        if not admin:
            raise NotImplementedError("user enrollment not done yet")

        async with EnrollClient(url_base=ctx.obj["url"], timeout=ctx.obj["timeout"]) as client:
            certbytes, keybytes = await client.enroll_admin(callsign, code)

        certpth = Path(f"{callsign}.crt")
        certpth.write_bytes(certbytes)
        LOGGER.info("Wrote {}".format(certpth))
        keypth = Path(f"{callsign}.key")
        keypth.write_bytes(keybytes)
        LOGGER.info("Wrote {}".format(keypth))
        return 0

    ctx.exit(ctx.obj["loop"].run_until_complete(enroll_actual()))


def rmcli_cli() -> None:
    """CLI interface to RASENMAEHER API"""
    init_logging(logging.WARNING)
    cli_group()  # pylint: disable=no-value-for-parameter
