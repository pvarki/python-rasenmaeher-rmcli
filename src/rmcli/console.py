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
from rmcli.client.base import RMClientBase
from rmcli.client.user import UserClient

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
@click.option("--wait", type=float, default=10.0, help="initial wait and check interval")
@click.pass_context
def enroll(ctx: click.Context, admin: bool, callsign: str, code: str, wait: float) -> None:
    """Do enrollment, write callsign.crt and callsign.key"""

    async def enroll_actual() -> int:
        """Do enrollment, write callsign.crt and callsign.key"""
        nonlocal ctx, admin, callsign, code, wait
        if not admin:
            async with EnrollClient(url_base=ctx.obj["url"], timeout=ctx.obj["timeout"]) as client:
                acode, jwt = await client.enroll_user_init(callsign, code)
                click.echo(f"Approvecode: {acode}")
                LOGGER.info("Waiting for approval")
                await asyncio.sleep(wait)
                while not await client.enrollment_is_approved(jwt):
                    LOGGER.warning("Enrollment for {} not yet approved. code is: {}".format(callsign, acode))
                    await asyncio.sleep(wait)
                certbytes, keybytes = await client.enroll_user_finish(jwt, callsign)
        else:
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


@cli_group.group(name="admin")
@click.argument("certfile", required=True, type=click.Path(exists=True))
@click.argument("keyfile", required=True, type=click.Path(exists=True))
@click.pass_context
def admingrp(ctx: click.Context, certfile: Path, keyfile: Path) -> None:
    """Admin commands, requires mTLS identity"""
    ctx.ensure_object(dict)
    ctx.obj["ident"] = (Path(certfile), Path(keyfile))
    if "mtls" not in ctx.obj["url"]:
        LOGGER.warning("Url does not contain 'mtls' are you sure it's correct ?")


@admingrp.command()
@click.option("-a", "--admin", is_flag=True, help="Create single-use admin logincode")
@click.pass_context
def invite(ctx: click.Context, admin: bool) -> None:
    """Create invite code for users"""

    async def invite_actual() -> int:
        """Actual operation"""
        nonlocal ctx, admin
        if admin:
            raise NotImplementedError()
        async with EnrollClient(url_base=ctx.obj["url"], timeout=ctx.obj["timeout"]) as client:
            await client.set_identity(*ctx.obj["ident"])
            code = await client.create_pool()
        click.echo(code)
        return 0

    ctx.exit(ctx.obj["loop"].run_until_complete(invite_actual()))


@admingrp.command()
@click.argument("code", required=True)
@click.argument("callsign", required=True)
@click.pass_context
def approve(ctx: click.Context, code: str, callsign: str) -> None:
    """Approve given enrollment"""

    async def approve_actual() -> int:
        """Actual operation"""
        nonlocal ctx, code, callsign
        async with EnrollClient(url_base=ctx.obj["url"], timeout=ctx.obj["timeout"]) as client:
            await client.set_identity(*ctx.obj["ident"])
            await client.approve(callsign, code)
        return 0

    ctx.exit(ctx.obj["loop"].run_until_complete(approve_actual()))


@cli_group.group(name="user")
@click.argument("certfile", required=True, type=click.Path(exists=True))
@click.argument("keyfile", required=True, type=click.Path(exists=True))
@click.pass_context
def usergrp(ctx: click.Context, certfile: Path, keyfile: Path) -> None:
    """User commands, requires mTLS identity"""
    ctx.ensure_object(dict)
    ctx.obj["ident"] = (Path(certfile), Path(keyfile))
    if "mtls" not in ctx.obj["url"]:
        LOGGER.warning("Url does not contain 'mtls' are you sure it's correct ?")


@usergrp.command()
@click.pass_context
def whoami(ctx: click.Context) -> None:
    """Return the callsign (in case the cert and key files are named wrong"""

    async def ask_server() -> int:
        """Ask the server who am I"""
        nonlocal ctx
        async with RMClientBase(url_base=ctx.obj["url"], timeout=ctx.obj["timeout"]) as client:
            await client.set_identity(*ctx.obj["ident"])
            callsign = await client.get_callsign()
            click.echo(callsign)
            return 0

    ctx.exit(ctx.obj["loop"].run_until_complete(ask_server()))


@usergrp.command()
@click.pass_context
def get_files(ctx: click.Context) -> None:
    """Get the downloadable files that products want to give to us"""

    async def get_and_save() -> int:
        """The actual fetch"""
        nonlocal ctx
        async with UserClient(url_base=ctx.obj["url"], timeout=ctx.obj["timeout"]) as client:
            await client.set_identity(*ctx.obj["ident"])
            files = await client.get_files()
            for product, fileinfos in files.items():
                for fileinfo in fileinfos:
                    new_name = Path(f"{product}_{fileinfo.filename}")
                    new_name.write_bytes(fileinfo.content)
                    LOGGER.info("Wrote {} ({})".format(new_name, fileinfo.title))

        return 0

    ctx.exit(ctx.obj["loop"].run_until_complete(get_and_save()))


def rmcli_cli() -> None:
    """CLI interface to RASENMAEHER API"""
    init_logging(logging.WARNING)
    cli_group()  # pylint: disable=no-value-for-parameter
