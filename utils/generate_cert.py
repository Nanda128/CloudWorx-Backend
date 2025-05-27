import argparse  # noqa: INP001
import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(
    common_name: str,
    output_dir: str,
    key_file: str = "server.key",
    cert_file: str = "server.crt",
    days_valid: int = 365,
) -> None:
    """Generate a self-signed certificate"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Evil-Limerick"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Drogheda"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CloudWorx"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ],
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(
            subject,
        )
        .issuer_name(
            issuer,
        )
        .public_key(
            private_key.public_key(),
        )
        .serial_number(
            x509.random_serial_number(),
        )
        .not_valid_before(
            datetime.datetime.now(datetime.timezone.utc),
        )
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_valid),
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.DNSName(common_name),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ],
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    key_path = Path(output_dir) / key_file
    with key_path.open("wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
    cert_path = Path(output_dir) / cert_file
    with cert_path.open("wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated self-signed certificate for {common_name}")
    print(f"Private key: {Path(output_dir) / key_file}")
    print(f"Certificate: {Path(output_dir) / cert_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate self-signed TLS certificate")
    parser.add_argument("--common-name", default="cloudworx.local", help="Common name for the certificate")
    parser.add_argument("--output-dir", default=".", help="Directory to save the certificate and key")
    parser.add_argument("--key-file", default="server.key", help="Filename for the private key")
    parser.add_argument("--cert-file", default="server.crt", help="Filename for the certificate")
    parser.add_argument("--days", type=int, default=365, help="Number of days the certificate is valid")

    args = parser.parse_args()

    generate_self_signed_cert(
        args.common_name,
        args.output_dir,
        args.key_file,
        args.cert_file,
        args.days,
    )

# Try running: python utils/generate_cert.py --common-name cloudworx.local --output-dir . before anything
