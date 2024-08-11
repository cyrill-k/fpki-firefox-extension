import sys
import json
import ssl
import socket
from base64 import b64encode
from datetime import datetime
import hashlib
from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open("native_app.log", "a", encoding="utf-8") as logfile:
        logfile.write(f"{timestamp} - {message}\n")


# Load certificates from a single .pem file
def load_trusted_certificates(pem_file_path):
    certs = []
    try:
        with open(pem_file_path, 'rb') as f:
            pem_data = f.read().decode('utf-8')
            for cert_str in pem_data.split("-----END CERTIFICATE-----"):
                if "-----BEGIN CERTIFICATE-----" in cert_str:
                    cert_str = cert_str + "-----END CERTIFICATE-----"
                    try:
                        cert = x509.load_pem_x509_certificate(cert_str.encode('utf-8'), default_backend())
                        certs.append(cert)
                    except Exception as e:
                        log(f"Error loading certificate: {e}")
        log(f"Successfully loaded all certificates")
    except Exception as e:
        log(f"Error loading certificates from {pem_file_path}: {e}")
    return certs


# Path to your single .pem file containing multiple certificates
mozilla_ca_certs = load_trusted_certificates("certificates/cacert.pem")

def is_built_in_root(cert):
    try:
        for trusted_cert in mozilla_ca_certs:
            if cert.fingerprint(hashes.SHA256()) == trusted_cert.fingerprint(hashes.SHA256()):
                return True
    except Exception as e:
        log(f"Error checking if certificate is built-in root: {e}")
    return False

def serialize_bytes(obj):
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError("Type not serializable")

def get_certificate_info(cert):
    try:
        # Convert OpenSSL certificate to cryptography certificate
        cert_bytes = cert.to_cryptography().public_bytes(serialization.Encoding.DER)
        x509_cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        
        sha1_fingerprint = cert.digest('sha1').decode('ascii')
        sha256_fingerprint = cert.digest('sha256').decode('ascii')
        sha256_pub_key_info = hashlib.sha256(x509_cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).hexdigest()
        
        return {
            "fingerprint": {
                "sha1": sha1_fingerprint,
                "sha256": sha256_fingerprint,
            },
            "isBuiltInRoot": is_built_in_root(x509_cert),
            "issuer": [
                (k.decode('utf-8') if isinstance(k, bytes) else k, 
                 v.decode('utf-8') if isinstance(v, bytes) else v) 
                for k, v in cert.get_issuer().get_components()
            ],
            "rawDER": list(cert_bytes),
            "serialNumber": str(cert.get_serial_number()),
            "subject": [
                (k.decode('utf-8') if isinstance(k, bytes) else k, 
                 v.decode('utf-8') if isinstance(v, bytes) else v) 
                for k, v in cert.get_subject().get_components()
            ],
            "subjectPublicKeyInfoDigest": {
                "sha256": sha256_pub_key_info
            },
            "validity": {
                "start": int(datetime.strptime(cert.get_notBefore().decode('ascii'), "%Y%m%d%H%M%SZ").timestamp() * 1000),
                "end": int(datetime.strptime(cert.get_notAfter().decode('ascii'), "%Y%m%d%H%M%SZ").timestamp() * 1000)
            }
        }
    except Exception as e:
        log(f"Error getting certificate info: {e}")
        return {}

def get_security_info(domain):
    try:
        dst = (domain, 443)
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        s = socket.create_connection(dst)
        s = SSL.Connection(ctx, s)
        s.set_connect_state()
        s.set_tlsext_host_name(dst[0].encode())

        s.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
        s.recv(16)

        cert_chain = s.get_peer_cert_chain()
        
        certificates = [get_certificate_info(cert) for cert in cert_chain]
        
        s.close()

        log(f"Parsed certificates for {domain}: {certificates}")
        return {"certificates": certificates}
    except Exception as e:
        log(f"Error retrieving security info for {domain}: {e}")
        return {"error": str(e)}
def read_message():
    raw_length = sys.stdin.read(4)
    if not raw_length:
        sys.exit(0)
    message_length = int.from_bytes(raw_length.encode('utf-8'), byteorder='little')
    message = sys.stdin.read(message_length)
    return json.loads(message)

def send_message(message_content):
    message_json = json.dumps(message_content, default=serialize_bytes)
    sys.stdout.buffer.write(len(message_json).to_bytes(4, byteorder='little'))
    sys.stdout.buffer.write(message_json.encode('utf-8'))
    sys.stdout.buffer.flush()

log("Starting native messaging host")

while True:
    try:
        log("Application started, waiting for message")
        received_message = read_message()
        log(f"Received message: {received_message}")
        if received_message['type'] == 'getSecurityInfo':
            domain = received_message['domain']
            security_info = get_security_info(domain)
            send_message({"securityInfo": security_info})
            log(f"Sent security info: {security_info}")
    except Exception as e:
        log(f"Error: {e}")
        send_message({"error": str(e)})