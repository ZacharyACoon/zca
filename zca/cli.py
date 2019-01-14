from os.path import exists
from datetime import datetime
import click
from . import crypto, ca_paths, click_ordering, mode_openers


@click.group(cls=click_ordering.NaturalOrderGroup)
@click.pass_context
@click.argument("organization_name")
def cli(ctx, organization_name):
    """common cli work/variables"""
    paths = ctx.obj
    paths.init_organization_name_paths(organization_name)


@cli.command()
@click.pass_context
@click.option("--yubikey/--no-yubikey", default=False)
def generate_root_key(ctx, yubikey):
    """generate key for org ca root"""
    paths = ctx.obj

    if exists(paths.root_key_file):
        raise Exception("Root key already exists.")

    root_key_password = bytes(click.prompt(text="password to encrypt ca root key?", default=None, hide_input=True, confirmation_prompt=True), 'utf-8')
    crypto.generate_key(
        private_key_file=paths.root_key_file,
        password=root_key_password,
        public_key_file=paths.root_public_key_file,
        yubikey=yubikey
    )


@cli.command()
@click.pass_context
def generate_root_cert(ctx):
    """generate a new cert for the ca root"""
    paths = ctx.obj

    root_key_password = bytes(click.prompt(text="password to decrypt ca root key?", default=None, hide_input=True, confirmation_prompt=False), 'utf-8')
    root_key = crypto.load_key(paths.root_key_file, root_key_password)

    cert_file_name = f"{paths.organization_name}_root_certificate_{int(datetime.utcnow().timestamp())}.pem"
    new_root_cert_file = paths.root_certificate_dir / cert_file_name

    crypto.generate_root_certificate(
        new_cert_path=new_root_cert_file,
        root_key=root_key,
        organization_name=paths.organization_name
    )


@cli.command()
@click.pass_context
@click.argument("intermediary")
#@click.option("--yubikey/--no-yubikey", default=False)
def generate_intermediary_key(ctx, intermediary):
    """generate key for org intermediary"""
    paths = ctx.obj
    paths.init_intermediary_paths(intermediary)

    intermediary_key_password = bytes(click.prompt(text="password to encrypt intermediary key?", default=None, hide_input=True, confirmation_prompt=True), 'utf-8')
    crypto.generate_key(
        private_key_file=paths.intermediary_key_file,
        password=intermediary_key_password,
        public_key_file=paths.intermediary_public_key_file
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
        password=root_key_password,
    )
    root_cert = crypto.load_cert(paths.root_certificate_last)
    intermediary_public_key = crypto.load_public_key(
        file=paths.intermediary_public_key_file
    )

    cert_file_name = f"{paths.organization_name}_{intermediary}_certificate_{int(datetime.utcnow().timestamp())}.pem"
    new_cert_file = paths.intermediary_certificate_dir / cert_file_name
    crypto.generate_intermediary_certificate(
        root_key=root_key,
        root_cert=root_cert,
        intermediary=intermediary,
        intermediary_public_key=intermediary_public_key,
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

    server_key_password = bytes(click.prompt(text="password to encrypt server key?", default="", hide_input=True, confirmation_prompt=True), 'utf-8')
    crypto.generate_key(
        private_key_file=paths.server_key_file,
        password=server_key_password,
        public_key_file=paths.server_public_key_file
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

    intermediary_key_password = bytes(click.prompt(text="password to decrypt intermediary key?", default="", hide_input=True, confirmation_prompt=False), 'utf-8')
    intermediary_key = crypto.load_key(
        file=paths.intermediary_key_file,
        password=intermediary_key_password
    )
    intermediary_cert = crypto.load_cert(paths.intermediary_certificate_last)

    server_public_key = crypto.load_public_key(file=paths.server_public_key_file)

    cert_file_name = f"{paths.organization_name}_{intermediary}_{server}_certificate_{int(datetime.utcnow().timestamp())}.pem"
    new_cert_file = paths.server_certificate_dir / cert_file_name

    crypto.generate_web_server_certificate(
        intermediary_key=intermediary_key,
        intermediary_cert=intermediary_cert,
        server_public_key=server_public_key,
        server=server,
        names=names,
        new_cert_path=new_cert_file
    )


@cli.command()
@click.pass_context
@click.argument("intermediary")
@click.argument("user")
@click.option("--yubikey/--no-yubikey", default=False)
def generate_user_key(ctx, intermediary, user):
    """generate key for org user under intermediary"""
    paths = ctx.obj
    paths.init_intermediary_paths(intermediary)
    paths.init_user_paths(user)

    user_key_password = bytes(click.prompt(text="password to encrypt user key?", default=None, hide_input=True, confirmation_prompt=False), 'utf-8')

    crypto.generate_key(
        private_key_file=paths.user_key_file,
        password=user_key_password,
        public_key_file=paths.user_public_key_file
    )


@cli.command()
@click.pass_context
@click.argument("intermediary")
@click.argument("username")
def generate_user_cert(ctx, intermediary, username):
    """generate cert for org user under intermediary"""
    paths = ctx.obj
    paths.init_intermediary_paths(intermediary)
    paths.init_user_paths(user)

    intermediary_key_password = bytes(click.prompt(text="password to decrypt intermediary key?", default=None, hide_input=True, confirmation_prompt=False), 'utf-8')
    intermediary_key = crypto.load_key(
        file=paths.intermediary_key_file,
        password=intermediary_key_password
    )
    intermediary_cert = crypto.load_cert(paths.intermediary_cert_last)

    user_key_password = bytes(click.prompt(text="password to decrypt user key?", default=None, hide_input=True, confirmation_prompt=False), 'utf-8')
    user_key = crypto.load_key(
        file=paths.user_key_file,
        password=user_key_password
    )
    user_public_key = crypto.load_public_key(file=paths.user_public_key_file)

    cert_file_name = f"{paths.organization_name}_{intermediary}_{user}_certificate_{int(datetime.utcnow().timestamp())}.pem"
    new_cert_file = paths.user_certificate_dir / cert_file_name

    crypto.generate_user_certificate(
        intermediary_key=intermediary_key,
        intermediary_cert=intermediary_cert,
        user_public_key=user_public_key,
        username=username,
        new_cert_path=new_cert_file
    )


@cli.command()
@click.pass_context
@click.argument("intermediary")
@click.argument("web_server")
def generate_web_server_cert_chain(ctx, intermediary, web_server):
    paths = ctx.obj
    paths.init_intermediary_paths(intermediary)
    paths.init_server_paths(web_server)

    if not paths.server_certificate_last:
        print("No server certificates found.")
        return False
    with open(paths.server_certificate_last, 'r') as f:
        server_pem = f.read()

    if not paths.intermediary_certificate_last:
        print("No intermediary certificates found.")
        return False
    with open(paths.intermediary_certificate_last, 'r') as f:
        intermediary_pem = f.read()

    chain_cert_name = paths.server_certificate_chain_dir / f"{paths.server_certificate_last.stem}_chain.pem"
    with open(chain_cert_name, mode='w', opener=mode_openers.public_file_opener) as f:
        f.write(intermediary_pem)
        f.write(server_pem)


@cli.command()
@click.pass_context
@click.argument("intermediary")
@click.argument("web_server")
def generate_web_server_cert_chain_reverse(ctx, intermediary, web_server):
    paths = ctx.obj
    paths.init_intermediary_paths(intermediary)
    paths.init_server_paths(web_server)

    if not paths.server_certificate_last:
        print("No server certificates found.")
        return False
    with open(paths.server_certificate_last, 'r') as f:
        server_pem = f.read()

    if not paths.intermediary_certificate_last:
        print("No intermediary certificates found.")
        return False
    with open(paths.intermediary_certificate_last, 'r') as f:
        intermediary_pem = f.read()

    chain_cert_name = paths.server_certificate_chain_dir / f"{paths.server_certificate_last.stem}_chain_reverse.pem"
    with open(chain_cert_name, mode='w', opener=mode_openers.public_file_opener) as f:
        f.write(server_pem)
        f.write(intermediary_pem)


def run():
    cli(obj=ca_paths.CAPaths())


if __name__ == "__main__":
    run()
