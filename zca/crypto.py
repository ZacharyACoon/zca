from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from datetime import timedelta, datetime
import os
from datetime import datetime


def private_file_opener(path, flags):
    print(path)
    return os.open(path, flags=flags, mode=0o500)


def public_file_opener(path, flags):
    print(path)
    return os.open(path, flags=flags, mode=0o555)


def generate_key(file, password, yubi_key=False):
    """generate password protected key"""

    # yubikeys (4) support RSA2048,ECCp256,384
    if yubi_key:
        curve = ec.BrainpoolP384R1
    else:
        # highest available?
        curve = ec.BrainpoolP512R1

    key = ec.generate_private_key(
        curve=curve,
        backend=default_backend()
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    with open(file, mode='wb', opener=private_file_opener) as f:
        f.write(key_pem)


def load_key(file, password):
    """load and return a decrypted key"""
    with open(file, 'rb') as f:
        key = serialization.load_pem_private_key(
            data=f.read(),
            password=password,
            backend=default_backend()
        )
    return key


def generate_root_certificate(new_cert_path, root_key, organization_name):
    """generate a self signed root certificate expiring in 20 years"""
    name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization_name),
            # x509.NameAttribute(x509.NameOID.COMMON_NAME, 'root'),
            x509.NameAttribute(x509.NameOID.USER_ID, 'root'),
        ]
    )
    cert = x509.CertificateBuilder(
        issuer_name=name,
        subject_name=name,
        public_key=root_key.public_key(),
        serial_number=x509.random_serial_number(),
        not_valid_before=datetime.utcnow(),
        not_valid_after=datetime.utcnow() + timedelta(days=365*20),
        extensions=[]
    ).add_extension(
        critical=True,
        extension=x509.BasicConstraints(
            ca=True,
            path_length=1
        )
    ).add_extension(
        critical=True,
        extension=x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )
    ).sign(
        private_key=root_key,
        algorithm=hashes.SHA512(),
        backend=default_backend(),
    )
    with open(new_cert_path, mode='wb', opener=public_file_opener) as f:
        f.write(cert.public_bytes(Encoding.PEM))


def generate_intermediary_certificate(organization_name, root_key, intermediary, intermediary_key, new_cert_path):
    """generate an intermediary certificate expiring in 1 year"""
    issuer_name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization_name),
            # x509.NameAttribute(x509.NameOID.COMMON_NAME, 'root'),
            x509.NameAttribute(x509.NameOID.USER_ID, 'root'),
        ]
    )

    subject_name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization_name),
            # x509.NameAttribute(x509.NameOID.COMMON_NAME, intermediary),
            x509.NameAttribute(x509.NameOID.USER_ID, intermediary),
        ]
    )

    cert = x509.CertificateBuilder(
        issuer_name=issuer_name,
        subject_name=subject_name,
        public_key=intermediary_key.public_key(),
        serial_number=x509.random_serial_number(),
        not_valid_before=datetime.utcnow(),
        not_valid_after=datetime.utcnow() + timedelta(days=365 * 1),
        extensions=[]
    ).add_extension(
        critical=True,
        extension=x509.BasicConstraints(
            ca=True,
            path_length=0
        )
    ).add_extension(
        critical=True,
        extension=x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )
    ).sign(
        private_key=root_key,
        algorithm=hashes.SHA512(),
        backend=default_backend(),
    )
    with open(new_cert_path, mode='wb', opener=public_file_opener) as f:
        f.write(cert.public_bytes(Encoding.PEM))


def generate_web_server_certificate(organization_name, intermediary_key, intermediary, server_key, server, names, new_cert_path):
    """generate a web server certificate expiring in 1 year"""
    issuer_name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization_name),
            # x509.NameAttribute(x509.NameOID.COMMON_NAME, intermediary),
            x509.NameAttribute(x509.NameOID.USER_ID, intermediary),
        ]
    )
    subject_name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization_name),
            # x509.NameAttribute(x509.NameOID.COMMON_NAME, intermediary),
            x509.NameAttribute(x509.NameOID.USER_ID, server),
        ]
    )
    cert = x509.CertificateBuilder(
        issuer_name=issuer_name,
        subject_name=subject_name,
        public_key=server_key.public_key(),
        serial_number=x509.random_serial_number(),
        not_valid_before=datetime.utcnow(),
        not_valid_after=datetime.utcnow() + timedelta(days=365 * 1),
        extensions=[]
    ).add_extension(
        critical=True,
        extension=x509.SubjectAlternativeName(
            [x509.DNSName(name) for name in names]
        )
    ).add_extension(
        critical=True,
        extension=x509.BasicConstraints(
            ca=False,
            path_length=None
        )
    ).add_extension(
        critical=True,
        extension=x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )
    ).sign(
        private_key=intermediary_key,
        algorithm=hashes.SHA512(),
        backend=default_backend(),
    )
    with open(new_cert_path, mode='wb', opener=public_file_opener) as f:
        f.write(cert.public_bytes(Encoding.PEM))
