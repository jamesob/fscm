import sys
from pathlib import Path
from datetime import datetime, timedelta

from clii import App

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    HAS_PKI = True
except ImportError:
    HAS_PKI = False
    RSAPublicKey = object()
    RSAPrivateKey = object()


cli = App()

KEY_SIZE = 4096
PUBLIC_EXPONENT = 65537


def create_ca(common_name: str, org_name: str):
    # Generate private key for CA
    ca_private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE, backend=default_backend())

    # Create CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())
    )

    return ca_private_key, ca_cert

def create_cert_for_service(ca_private_key, ca_cert, domains: list[str], org_name: str):
    # Generate private key for service
    service_private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE, backend=default_backend())

    # Create certificate for the service
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ])
    service_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(service_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain) for domain in domains
            ]),
            critical=False,
        ).sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())
    )

    return service_private_key, service_cert


@cli.cmd
def new_ca(common_name: str, org_name: str):
    """Create a new certificate authority, returning the privkey in a hex string."""
    ca_private_key, ca_cert = create_ca(common_name, org_name)

    privkey_bytes = _save_to_file(ca_private_key, ca_cert, common_name)
    print(privkey_bytes.hex())


@cli.cmd
def new_cert(ca_cert_path: str, ca_privkey_path: str, domain_names: str, org_name: str):
    """Create a new certificate. Expects PEM-encoded CA cert hex privkey to be piped in."""
    privkey = serialization.load_pem_private_key(
        Path(ca_privkey_path).read_bytes(), password=None, backend=default_backend())

    ca_certificate = x509.load_pem_x509_certificate(
        Path(ca_cert_path).read_bytes(), default_backend())

    domains = domain_names.split(',')
    domain = domains[0]

    service_privkey, service_pubkey = create_cert_for_service(
        privkey, ca_certificate, domains, org_name)

    _save_to_file(service_privkey, service_pubkey, domain)


def _save_to_file(key: RSAPrivateKey, cert: RSAPublicKey, filename_prefix: str) -> bytes:
    privkey_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())

    privkey_fname = f"{filename_prefix}_key.pem"
    with open(privkey_fname, "wb") as f:
        f.write(privkey_bytes)
    print(f"Wrote privkey to {privkey_fname}")

    pubkey_fname = f"{filename_prefix}_cert.pem"
    with open(pubkey_fname, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Wrote pubkey to {pubkey_fname}")

    return privkey_bytes


def main():
    if not HAS_PKI:
        print("!! missing cryptography library - try\n  pip install cryptography")
        sys.exit(1)

    cli.run()
