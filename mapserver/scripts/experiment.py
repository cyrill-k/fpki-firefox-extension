#!/usr/bin/env python3

import argparse
import urllib.request
import urllib.error
import csv
import json
import base64
import collections

# from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Performance evaluations of a mapserver",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--destination-address", "-d", default="129.132.55.210:8080", help="ip address (+ port) of the mapserver")
    parser.add_argument("--output-file", "-o", default="measurements.csv", help="output csv file")
    parser.add_argument("--toplist-file", "-t", type=str, default="/home/cyrill/inf-gitlab/OU-PERRIG/cyrill/ct-log-scraping/input/top-1m.csv", help="Alexa most popular domain list csv file")
    parser.add_argument("--toplist-threshold", type=int, default=100000, help="highest Alexa rank to extract (inclusive)")

    return parser.parse_args()


def fetch_and_get_measurements(url):
    request = urllib.request.Request(url)
    types = {RSAPublicKey: "RSAPublicKey", DSAPublicKey: "DSAPublicKey", EllipticCurvePublicKey: "EllipticCurvePublicKey", Ed25519PublicKey: "Ed25519PublicKey", Ed448PublicKey: "Ed448PublicKey", X25519PublicKey: "X25519PublicKey", X448PublicKey: "X448PublicKey"}
    try:
        with urllib.request.urlopen(request) as response:
            raw_data = response.read()
            data = json.loads(raw_data.decode("utf-8"))
            proof_length = list(map(lambda x: len(x["PoI"]["Proof"]), data))
            signature_length = list(map(lambda x: len(x["PoI"]["ProofValue"]) if x["PoI"]["ProofValue"] is not None else 0, data))

            def get_certificates(entry, unique=False):
                base64_entry = entry["DomainEntryBytes"]
                if len(base64_entry) == 0:
                    return []
                else:
                    json_entry = json.loads(base64.b64decode(base64_entry))
                    certs = []
                    certs.extend(y for x in json_entry["CAEntry"] for y in x["DomainCerts"])
                    certs.extend(z for x in json_entry["CAEntry"] for y in x["DomainCertChains"] for z in y)
                    return set(certs) if unique else certs
            certificates = [y for x in data for y in get_certificates(x)]
            unique_certificates = [y for x in data for y in get_certificates(x, True)]

            def count_certificate_types(certificates, types):
                certs = list(map(lambda x: x509.load_pem_x509_certificate(f"-----BEGIN CERTIFICATE-----\n{x}\n-----END CERTIFICATE-----".encode('utf-8')), certificates))
                d = collections.defaultdict(int)
                for x in certs:
                    t = None
                    for c, s in types.items():
                        if isinstance(x.public_key(), c):
                            t = s
                    d[t] += 1
                return d

            certificate_types = count_certificate_types(certificates, types)
            unique_certificate_types = count_certificate_types(unique_certificates, types)

            def get_n_certificates(entry):
                base64_entry = entry["DomainEntryBytes"]
                if len(base64_entry) == 0:
                    return 0
                else:
                    json_entry = json.loads(base64.b64decode(base64_entry))
                    return sum([len(x["DomainCerts"]) for x in json_entry["CAEntry"]])

            n_certificates = list(map(get_n_certificates, data))

            def get_n_unique_certificates(entry, certificate_type):
                base64_entry = entry["DomainEntryBytes"]
                if len(base64_entry) == 0:
                    return 0
                else:
                    intermediate_certs = set()
                    json_entry = json.loads(base64.b64decode(base64_entry))
                    intermediate_certs.update([z for x in json_entry["CAEntry"] for y in (x["DomainCertChains"][:-1] if certificate_type == "intermediate" else [x["DomainCertChains"][-1]]) for z in y])
                    return len(intermediate_certs)

            n_unique_intermediate_certificates = list(map(lambda x: get_n_unique_certificates(x, "intermediate"), data))
            n_unique_root_certificates = list(map(lambda x: get_n_unique_certificates(x, "root"), data))

            values = {
                "total_size": len(raw_data),
                "proof_length": ";".join(map(str, proof_length)),
                "signature_length": ";".join(map(str, signature_length)),
                "n_certificates": ";".join(map(str, n_certificates)),
                "n_unique_intermediate_certificates": ";".join(map(str, n_unique_intermediate_certificates)),
                "n_unique_root_certificates": ";".join(map(str, n_unique_root_certificates)),
            }

            for x in types.values():
                values[f"certificate_{x}"] = certificate_types[x]
                values[f"unique_certificate_{x}"] = unique_certificate_types[x]

            values["sum_proof_length"] = sum(proof_length)
            values["sum_signature_length"] = sum(signature_length)
            values["sum_n_certificates"] = sum(n_certificates)
            values["sum_n_unique_intermediate_certificates"] = sum(n_unique_intermediate_certificates)
            values["sum_n_unique_root_certificates"] = sum(n_unique_root_certificates)
            values["status"] = response.status
            return values
    except urllib.error.HTTPError as e:
        values = {
            "total_size": 0,
            "proof_length": "0",
            "signature_length": "0",
            "n_certificates": "0",
            "n_unique_intermediate_certificates": "0",
            "n_unique_root_certificates": "0",
            "sum_proof_length": 0,
            "sum_signature_length": 0,
            "sum_n_certificates": 0,
            "sum_n_unique_intermediate_certificates": 0,
            "sum_n_unique_root_certificates": 0,
            "status": e.code
        }
        for x in types.values():
            values[f"certificate_{x}"] = 0
            values[f"unique_certificate_{x}"] = 0
        return values


def main():
    args = parse_arguments()

    measurements = []
    with open(args.toplist_file, newline='') as csvfile:
        csvreader = csv.reader(csvfile)
        for row in csvreader:
            rank = int(row[0])
            domain = row[1]
            if rank <= args.toplist_threshold:
                measurements.append({**{"rank": rank, "domain": domain}, **fetch_and_get_measurements(f"http://{args.destination_address}?domain={domain}")})
                print(".", end="", flush=True)

    with open(args.output_file, 'w', newline='') as csvfile:
        csvwriter = csv.DictWriter(csvfile, fieldnames=measurements[0].keys())
        csvwriter.writeheader()
        csvwriter.writerows(measurements)
    # print(measurements)


if __name__ == '__main__':
    main()
