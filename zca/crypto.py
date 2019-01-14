from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509

from datetime import timedelta
from datetime import datetime
from . import mode_openers


def generate_key(private_key_file, password, public_key_file, yubikey=False):
    """generate password protected key"""

    # yubikeys (4) support RSA2048,ECCp256,384
    # chrome supports up to 384
    curve = ec.SECP384R1

    key = ec.generate_private_key(
        curve=curve,
        backend=default_backend()
    )
    # key = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=4096 if yubikey else 1024*16,
    #     backend=default_backend()
    # )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    )
    with open(private_key_file, mode='wb', opener=mode_openers.private_file_opener) as f:
        f.write(key_pem)

    public_key_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_file, mode='wb', opener=mode_openers.public_file_opener) as f:
        f.write(public_key_pem)


def load_key(file, password):
    """load and return a decrypted key"""
    with open(file, 'rb') as f:
        key = serialization.load_pem_private_key(
            data=f.read(),
            password=password,
            backend=default_backend()
        )
    return key


def load_public_key(file):
    with open(file, 'rb') as f:
        key = serialization.load_pem_public_key(
            data=f.read(),
            backend=default_backend()
        )
    return key


def load_cert(file):
    with open(file, 'rb') as f:
        cert = x509.load_pem_x509_certificate(
            f.read(),
            backend=default_backend()
        )
    return cert


def generate_root_certificate(new_cert_path, root_key, organization_name):
    """generate a self signed root certificate expiring in 20 years"""
    subject_name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, 'root'),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, 'root'),
        ]
    )
    cert = x509.CertificateBuilder(
        issuer_name=subject_name,
        subject_name=subject_name,
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
        algorithm=hashes.SHA384(),
        backend=default_backend(),
    )
    with open(new_cert_path, mode='wb', opener=mode_openers.public_file_opener) as f:
        f.write(cert.public_bytes(Encoding.PEM))


def generate_intermediary_certificate(root_key, root_cert, intermediary, intermediary_public_key, new_cert_path):
    """generate an intermediary certificate expiring in 1 year"""
    subject_name = x509.Name(
        [
            root_cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0],
            x509.NameAttribute(x509.NameOID.COMMON_NAME, intermediary),
        ]
    )

    cert = x509.CertificateBuilder(
        issuer_name=root_cert.subject,
        subject_name=subject_name,
        public_key=intermediary_public_key,
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
        algorithm=hashes.SHA384(),
        backend=default_backend(),
    )
    with open(new_cert_path, mode='wb', opener=mode_openers.public_file_opener) as f:
        f.write(cert.public_bytes(Encoding.PEM))


def generate_web_server_certificate(intermediary_key, intermediary_cert, server_public_key, server, names, new_cert_path):

    """generate a web server certificate expiring in 1 year"""
    subject_name = x509.Name(
        [
            intermediary_cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0],
            x509.NameAttribute(x509.NameOID.COMMON_NAME, server),

            # TODO: ExtendedValidation
            # x509.NameAttribute(x509.NameOID.JURISDICTION_COUNTRY_NAME, "Earth"),
            # x509.NameAttribute(x509.NameOID.BUSINESS_CATEGORY, )
        ]
    )

    cert = x509.CertificateBuilder(
        issuer_name=intermediary_cert.subject,
        subject_name=subject_name,
        public_key=server_public_key,
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
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
    ).add_extension(
        critical=True,
        extension=x509.ExtendedKeyUsage(
            [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]
        )
    # TODO: ExtendedValidation
    # ).add_extension(
    #     critical=True,
    #     extension=x509.PrecertificateSignedCertificateTimestamps(
    #         []
    #     )
    ).sign(
        private_key=intermediary_key,
        algorithm=hashes.SHA384(),
        backend=default_backend(),
    )
    x509.cer
    x509.certificate_transparency.SignedCertificateTimestamp()
    with open(new_cert_path, mode='wb', opener=mode_openers.public_file_opener) as f:
        f.write(cert.public_bytes(Encoding.PEM))


def generate_user_certificate(intermediary_key, intermediary_cert, user_public_key, username, new_cert_path):
    """generate a web server certificate expiring in 1 year"""
    subject_name = x509.Name(
        [
            intermediary_cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0],
            x509.NameAttribute(x509.NameOID.COMMON_NAME, username),
            x509.NameAttribute(x509.NameOID.USER_ID, username),
        ]
    )
    cert = x509.CertificateBuilder(
        issuer_name=intermediary_cert.subject,
        subject_name=subject_name,
        public_key=user_public_key,
        serial_number=x509.random_serial_number(),
        not_valid_before=datetime.utcnow(),
        not_valid_after=datetime.utcnow() + timedelta(days=365 * 2),
        extensions=[]
    ).add_extension(
        critical=True,
        extension=x509.BasicConstraints(
            ca=False,
            path_length=None
        )
    ).add_extension(
        critical=True,
        extension=x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
    ).add_extension(
        critical=True,
        extension=x509.ExtendedKeyUsage(
            [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
        )
    ).sign(
        private_key=intermediary_key,
        algorithm=hashes.SHA384(),
        backend=default_backend(),
    )
    with open(new_cert_path, mode='wb', opener=mode_openers.public_file_opener) as f:
        f.write(cert.public_bytes(Encoding.PEM))
