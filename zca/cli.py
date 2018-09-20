from os.path import exists
from datetime import datetime
import click
from . import crypto, ca_paths, click_ordering


@click.group(cls=click_ordering.NaturalOrderGroup)
@click.pass_context
@click.argument("organization_name")
def cli(ctx, organization_name):
    """common cli work/variables"""
    paths = ctx.obj
    paths.init_organization_name_paths(organization_name)


@cli.command()
@click.pass_context
def generate_root_key(ctx):
    """generate key for org ca root"""
    paths = ctx.obj
    if exists(paths.root_key_file):
        raise Exception("Root key already exists.")
    root_key_password = bytes(click.prompt(text="password to encrypt ca root key?", default=None, hide_input=True, confirmation_prompt=False), 'utf-8')
    crypto.generate_key(paths.root_key_file, root_key_password)


@cli.command()
@click.pass_context
def generate_root_cert(ctx):
    """generate a new cert for the ca root"""
    paths = ctx.obj
    root_key_password = bytes(click.prompt(text="password to decrypt ca root key?", default=None, hide_input=True, confirmation_prompt=False), 'utf-8')
    key = crypto.load_key(paths.root_key_file, root_key_password)
    cert_file_name = f"{paths.organization_name}_root_certificate_{int(datetime.utcnow().timestamp())}.pem"
    new_root_cert_file = paths.root_certificate_dir / cert_file_name

    crypto.generate_root_certificate(
        new_cert_path=new_root_cert_file,
        root_key=key,
        organization_name=paths.organization_name
    )


@cli.command()
@click.pass_context
@click.argument("intermediary")
def generate_intermediary_key(ctx, intermediary):
    """generate key for org intermediary"""
    paths = ctx.obj
    paths.init_intermediary_paths(intermediary)

    intermediary_key_password = bytes(click.prompt(text="password to encrypt intermediary key?", default=None, hide_input=True, confirmation_prompt=False), 'utf-8')
    crypto.generate_key(
        file=paths.intermediary_key_file,
        password=intermediary_key_password
    )


@cli.command()
@click.pass_context
@click.argument("intermediary")
def generate_intermediary_cert(ctx, intermediary):
    """generate a new cert for a ca intermediary"""
    paths = ctx.obj
    paths.init_intermediary_paths(intermediary)

    root_key_password = bytes(click.prompt(text="password to decrypt root key?", default=None, hide_input=True, confirmation_prompt=False), 'utf-8')
    root_key = crypto.load_key(
        file=paths.root_key_file,
        password=root_key_password
    )

    intermediary_key_password = bytes(click.prompt(text="password to decrypt intermediary key?", default=None, hide_input=True, confirmation_prompt=False), 'utf-8')
    intermediary_key = crypto.load_key(
        file=paths.intermediary_key_file,
        password=intermediary_key_password
    )

    cert_file_name = f"{paths.organization_name}_{intermediary}_certificate_{int(datetime.utcnow().timestamp())}.pem"
    new_cert_file = paths.intermediary_certificate_dir / cert_file_name
    crypto.generate_intermediary_certificate(
        organization_name=paths.organization_name,
        root_key=root_key,
        intermediary=intermediary,
        intermediary_key=intermediary_key,
        new_cert_path=new_cert_file,
    )


@cli.command()
@click.pass_context
@click.argument("intermediary")
@click.argument("server")
# @click.argument("sans", nargs=-1)
def generate_web_server_key(ctx, intermediary, server):
    """generate key for org server under intermediary"""
    paths = ctx.obj
    paths.init_intermediary_paths(intermediary)
    paths.init_server_paths(server)

    server_key_password = bytes(click.prompt(text="password to encrypt server key?", default=None, hide_input=True, confirmation_prompt=False), 'utf-8')
    crypto.generate_key(
        file=paths.server_key_file,
        password=server_key_password
    )


@cli.command()
@click.pass_context
@click.argument("intermediary")
@click.argument("server")
@click.argument("names", nargs=-1)
def generate_web_server_cert(ctx, intermediary, server, names):
    """generate a new cert for org server under intermediary"""
    paths = ctx.obj
    paths.init_intermediary_paths(intermediary)
    paths.init_server_paths(server)

    intermediary_key_password = bytes(click.prompt(text="password to decrypt intermediary key?", default=None, hide_input=True, confirmation_prompt=False), 'utf-8')
    intermediary_key = crypto.load_key(
        file=paths.intermediary_key_file,
        password=intermediary_key_password
    )

    server_key_password = bytes(click.prompt(text="password to decrypt server key?", default=None, hide_input=True, confirmation_prompt=False), 'utf-8')
    server_key = crypto.load_key(
        file=paths.server_key_file,
        password=server_key_password
    )

    cert_file_name = f"{paths.organization_name}_{intermediary}_{server}_certificate_{int(datetime.utcnow().timestamp())}.pem"
    new_cert_file = paths.server_certificate_dir / cert_file_name

    crypto.generate_web_server_certificate(
        organization_name=paths.organization_name,
        intermediary_key=intermediary_key,
        intermediary=paths.intermediary,
        server_key=server_key,
        server=server,
        names=names,
        new_cert_path=new_cert_file
    )


if __name__ == "__main__":
    cli(obj=ca_paths.CAPaths())
