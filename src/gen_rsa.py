#!/usr/bin/env python3

# Generate RSA Key Pair

import os
import ssl
import sys
import datetime as dt
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from lib.helper import generate_id_from_public_key, password_key_derivation

key_password = os.getenv('FLUXCHAT_KEY_PASSWORD', 'password').encode()
data_dir = os.getenv('FLUXCHAT_DATA_DIR', 'var/data')

print('-> Password Key Derivation', file=sys.stderr)
pkd = password_key_derivation(key_password).encode()

# Private Key
print('-> Generating RSA Key Pair', file=sys.stderr)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
private_key_pem = private_key.private_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PrivateFormat.PKCS8,
	encryption_algorithm=serialization.BestAvailableEncryption(pkd)
)
private_key_path = os.path.join(data_dir, 'private_key.pem')
with open(private_key_path, 'wb') as f:
	f.write(private_key_pem)


# Public Key
public_key = private_key.public_key()
print('-> Generating Certificate', file=sys.stderr)
public_key_pem = public_key.public_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PublicFormat.SubjectPublicKeyInfo
)
public_key_path = os.path.join(data_dir, 'public_key.pem')
with open(public_key_path, 'wb') as f:
	f.write(public_key_pem)


# Certificate
print('-> Generating Certificate', file=sys.stderr)
subject = issuer = x509.Name([
	x509.NameAttribute(NameOID.COUNTRY_NAME, u'XX'),
	x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'StateName'),
	x509.NameAttribute(NameOID.LOCALITY_NAME, u'CityName'),
	x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'FluxChat'),
	x509.NameAttribute(NameOID.COMMON_NAME, u'fluxchat.dev'),
])

serial_number = x509.random_serial_number()
not_valid_before = dt.datetime.utcnow()
not_valid_after = not_valid_before + dt.timedelta(days=3650)
builder = x509.CertificateBuilder(issuer, subject, public_key, serial_number, not_valid_before, not_valid_after)
cert = builder.sign(private_key, hashes.SHA256(), default_backend())
certificate_pem = cert.public_bytes(serialization.Encoding.PEM)

certificate_path = os.path.join(data_dir, 'certificate.pem')
with open(certificate_path, 'wb') as f:
	f.write(certificate_pem)


# Test SSL
print('-> Test SSL', file=sys.stderr)
_server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
_server_ssl.load_cert_chain(certfile=certificate_path, keyfile=private_key_path, password=pkd)

print('-> Generate ID from Public Key', file=sys.stderr)
print(generate_id_from_public_key(public_key_pem), end='')
