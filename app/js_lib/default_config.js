import {firefox_trust_store_cas} from "./trust_store_cas.js"

export const defaultConfig = {
    "legacy-trust-preference": {
        "*": [
            {
                "ca-set": "All Trust-Store CAs",
                "level": "Standard Trust",
            }
        ],
        "fpki.netsec.ethz.ch": [
            {
                "ca-set": "Let's Encrypt",
                "level": "High Trust",
            }
        ]
    },
    "ca-sets": {
        "All Trust-Store CAs": {
            "description": "All CAs included in your browser's Trust-Store",
            "cas": firefox_trust_store_cas
        },
        "Let's Encrypt": {
            "description": "CAs used by Let's Encrypt",
            "cas": [
                "CN=ISRG Root X2,O=Internet Security Research Group,C=US",
                "CN=ISRG Root X1,O=Internet Security Research Group,C=US"
            ]
        },
        "Google CAs": {
            "description": "CAs used by Google Trust Services (GTS). Note that the GlobalSign CA is currently used to cross-sign their ACME-issued certificates.",
            "cas": [
                "CN=GTS Root R1,O=Google Trust Services LLC,C=US",
                "CN=GTS Root R2,O=Google Trust Services LLC,C=US",
                "CN=GTS Root R3,O=Google Trust Services LLC,C=US",
                "CN=GTS Root R4,O=Google Trust Services LLC,C=US",
                "CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE",
            ]
        },
    },
    "policy-trust-preference": {
        "fpki.netsec.ethz.ch": [
            {
                "policy-ca-set": "Netsec Test PCAs",
                "level": "High Trust",
            }
        ]
    },
    "policy-ca-sets": {
        "Netsec Test PCAs": {
            "description": "Policy CA used for testing FP-PKI functionality in *.fpki.netsec.ethz.ch subdomains",
            "pcas": [
                "Netsec Test PCA",
            ]
        }
    },
    "policy-cas": {
        "Netsec Test PCA": {
            "publickey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxmlqMQhGhyz2H3GOR0Kfx4wA/g4v6+u3dSHWvVeMZZjcJIuH2N3kBjx+NydcUBNzelE+VkIkMn8aE5u7945yJC3Qo8QBcJnYcnbPCJQd40OtZgVYGRKp4k0qyDpxWJACqh1Ttd4K3ZePDzYgtqpAOjLcncw4KA/bXKGkDP0qZkfMLLUxOcvklbe/zISsxdsw4q3LdUY2+oNXfmC32Tv3if1DjNYVgW1TbNPMxyiNnH1YBslPFRCUPDwqKSIXabzOqA3pK6edYv2J/6xV4wTVp7+VjHHt52kBeCnDroa8UUf3ulbmD5ZZiOk7MzBxnhIEGoNrLy2b/tkjA/eMvbfSpQIDAQAB"
        }
    },
    "mapservers": [
        {
            "identity": "Netsec Test Map Server",
            "domain": "http://129.132.55.210:8080",
            "querytype": "lfpki-http-get",
            "publickey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0aluJvWMsPqLnil97uE1XQpDVB1L7byH3Kar6Ims9XiZM3UgHG7FHur+HTdGSMrdhe1iDNEgpiKxIgAVgj8sIX44z5stXxi+zuVUDTVmnSEIDbl703IbDozrXEig6zTAvi1OuxEbHpS6i60onZqL6pmBzh8emWLvFIuumGTFKESd3qyEE/ohJcp3yuM/bYH7bUhqETPO3/kjKKBizuv/pnUgKnM31aL/kXX7PsokXXn3sakeDLByfMEPmRjvB8381zPWauM5GoNj1DahhGls2KmnTfN8T6jC5Eln2Epjmq4iq0yCf/trtV6kMawsVkBO++Y1RRwPn4NbAAf/ELu6UwIDAQAB"
        }
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
    "wasm-certificate-parsing": false,
    "wasm-certificate-caching": true,
}
