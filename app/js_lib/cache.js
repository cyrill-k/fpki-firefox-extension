import { parsePemCertificate, getSubjectPublicKeyInfoHash, getSubject } from "./x509utils.js"
import { arrayToHexString, intToHexString, hashPemCertificateWithoutHeader } from "./helper.js"

var domainToCertificateCache = new Map();
var certificateCache = new Map();

// TODO: store encoded certificate in persistent storage? and only decode if necessary? Or pre-emptively decode them
class CertificateCacheEntry {
    constructor(timestamp, certificate, parentHash, notValidBefore, notValidAfter, publicKeyHash, highestTrustLevel, highestTrustLevelEvaluationTimestamp) {
        this.timestamp = timestamp;
        this.certificate = certificate;
        this.parentHash = parentHash;
        this.notValidBefore = notValidBefore;
        this.notValidAfter = notValidAfter;
        this.publicKeyHash = publicKeyHash;
        this.highestTrustLevel = highestTrustLevel;
        this.highestTrustLevelEvaluationTimestamp = highestTrustLevelEvaluationTimestamp;
    }
}

class DomainToCertificateCacheEntry {
    constructor(timestamp, domain, certificateHash) {
        this.timestamp = timestamp;
        this.domain = domain;
        this.certificateHash = certificateHash;
    }
}

// returns the certificate stored in the cache for a specific key
export function getCertificateFromCacheByHash(certificateHash) {
    if (certificateCache.has(certificateHash)) {
        return certificateCache.get(certificateHash).certificate;
    }
    return null;
}

// returns the certificate and the corresponding certificate chain stored in the cache for a specific key
export function getCertificateChainFromCacheByHash(leafCertificateHash) {
    if (!certificateCache.has(leafCertificateHash)) {
        return null;
    } else {
        const certChain = [];
        let parentHash = leafCertificateHash;
        do {
            const currentCert = certificateCache.get(parentHash);
            certChain.push(currentCert.certificate);
            parentHash = currentCert.parentHash;
        } while (parentHash !== null)
        return certChain;
    }
}

function toHexString(byteArray) {
    return Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

// adds the certificate to the cache and returns its hash (i.e., the hash of the leaf certificate) as a reference (i.e., key in the cache)
export async function addCertificateChainToCacheIfNecessary(pemCertificateWithoutHeader, pemCertificateChainWithoutHeader) {
    const fullChain = [pemCertificateWithoutHeader].concat(pemCertificateChainWithoutHeader.map(c => c === null ? [] : c));
    const fullChainHashes = await Promise.all(fullChain.map(async c => arrayToHexString(await hashPemCertificateWithoutHeader(c), ":")));
    let nCertificatesParsed = 0;
    for (let i = fullChain.length - 1; i >= 0; i--) {
        const hash = fullChainHashes[i];
        if (certificateCache.has(hash)) {
            // the certificate was already parsed and thus all parents must have been parsed as well
            continue;
        } else {
            const startParsing = performance.now();
            const rawCertificate = fullChain[i];
            const certificate = parsePemCertificate(rawCertificate, true);
            nCertificatesParsed += 1;
            const parentHash = i === fullChain.length - 1 ? null : fullChainHashes[i + 1];
            const notValidBefore = certificate.tbsCertificate.validity.notBefore.value;
            const notValidAfter = certificate.tbsCertificate.validity.notAfter.value;
            const publicKeyHash = await getSubjectPublicKeyInfoHash(certificate);

            console.log("adding certificate to cache: subject=" + getSubject(certificate) +
                ", serial=" + intToHexString(certificate.tbsCertificate.serialNumber, ":") +
                ", validity=" + notValidBefore + "-" + notValidAfter +
                ", hash=" + hash +
                ", subjectPublicKeyInfoHash=" + publicKeyHash +
                ", parentHash=" + parentHash +
                ", cache size=" + certificateCache.size +
                ", time to parse=" + (performance.now() - startParsing));
            certificateCache.set(hash,
                new CertificateCacheEntry(
                    new Date(),
                    certificate,
                    parentHash,
                    notValidBefore,
                    notValidAfter,
                    publicKeyHash,
                    null,
                    null
                ));
        }
    }
    return { hash: fullChainHashes[0], nCertificatesParsed };
}
