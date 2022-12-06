#!/usr/bin/env python3

import csv
from cryptography import x509

def main():
    limit = 100000

    with open('certs.csv', newline='') as csvfile:
        csvreader = csv.reader(csvfile)
        for idx, row in enumerate(csvreader):
            if idx == 0:
                print(",".join(row))
                continue
            if idx > limit:
                break
            cert = x509.load_pem_x509_certificate(row[1].encode('ascii'))
            subject = [x.value for x in cert.subject if x.oid == x509.oid.NameOID.COMMON_NAME][0]
            sanExtensions = [x.value for x in cert.extensions if x.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME]
            if len(sanExtensions) > 0:
                sanEntries = sanExtensions[0].get_values_for_type(x509.DNSName)
                if "google.com" == subject or "google.com" in sanEntries:
                    print(subject)
                    print(sanEntries)
                    print(",".join(row))



if __name__ == '__main__':
    main()
