import {firefox_trust_store_cas} from "./trust_store_cas.js"

export const defaultConfig = {
    "legacy-trust-preference": {
        "*": [
            {
                "caSet": "All Trust-Store CAs",
                "level": 2
            }
        ]
    },
    "ca-sets": {
        "All Trust-Store CAs": firefox_trust_store_cas
    },
    "ca-sets-descriptions": {
        "All Trust-Store CAs": "All CAs included in your browsers Trust-Store."
    },
    "mapservers": [
        {
            "identity": "local-mapserver",
            "domain": "http://localhost:8080",
            "querytype": "lfpki-http-get"
        },
        /*{
            "identity": "ETH-mapserver-top-100k",
            "domain": "http://129.132.55.210:8080",
            "querytype": "lfpki-http-get"
        }*/
    ],
    "trust-levels": {
        "Untrusted": 0,
        "Low Trust": 1,
        "Standard Trust": 2,
        "High Trust": 3,
        "Perfect Trust": 4
    },
    "trust-levels-rev": {
        "0": "Untrusted",
        "1": "Low Trust",
        "2": "Standard Trust",
        "3": "High Trust",
        "4": "Perfect Trust"
    },
    "cache-timeout": 3600000,
    "max-connection-setup-time": 1000,
    "proof-fetch-timeout": 10000,
    "proof-fetch-max-tries": 3,
    "mapserver-quorum": 1,
    "mapserver-instances-queried": 1,
    "send-log-entries-via-event": true,
    "wasm-certificate-parsing": true,
    "policy-trust-preference": {
        "*": [
            {
                "pca": "pca",
                "level": 1
            }
        ]
    },
    "root-pcas": {
        "pca": "local PCA for testing purposes"
    },
    "root-cas": {
        "GTS CA 1C3": "description: ...",
        "DigiCert Global Root CA": "description: ...",
        "TrustAsia TLS RSA CA": "description: ...",
        "DigiCert SHA2 Secure Server CA": "description: ...",
        "DigiCert Secure Site CN CA G3": "description: ...",
        "GlobalSign Organization Validation CA - SHA256 - G2": "description: ...",
        "DigiCert TLS Hybrid ECC SHA384 2020 CA1": "description: ..."
    }
}
