import uuid
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import requests

# Fetch the DER-encoded certificate content directly
# This assumes the URL is always accessible and content is valid
debian_ca_der_content = requests.get("https://salsa.debian.org/efi-team/shim/-/raw/master/debian/debian-uefi-ca.der").content

# Load the DER-encoded certificate
certificate = x509.load_der_x509_certificate(debian_ca_der_content)

# Get the Subject Distinguished Name in its DER-encoded byte representation
subject_dn_der_bytes = certificate.subject.public_bytes(serialization.Encoding.DER)

# Convert the DER bytes to a hexadecimal string, which uuid.uuid5 expects as the 'name'
subject_dn_hex_string = subject_dn_der_bytes.hex()

# Generate the UUID v5 using NAMESPACE_X500
cert_uuid = uuid.uuid5(uuid.NAMESPACE_X500, subject_dn_hex_string)

print(f"Generated UUID for the certificate (using NAMESPACE_X500 and Subject DN DER): {cert_uuid}")
print(f"Subject DN (human-readable): {certificate.subject}")