import { parsePemCertificate, getSubjectPublicKeyInfoHash, getSubject } from "./x509utils.js"
import { cLog, arrayToHexString, intToHexString, hashPemCertificateWithoutHeader } from "./helper.js"

var domainToCertificateCache = new Map();
var certificateCache = new Map();
var certificateCacheTest = new Map();


// TODO: store encoded certificate in persistent storage? and only decode if necessary? Or pre-emptively decode them
class CertificateCacheEntry {
    constructor(timestamp, certificate, parentHash, notValidBefore, notValidAfter, publicKeyHash, highestTrustLevel, highestTrustLevelEvaluationTimestamp) {
        this.timestamp = timestamp;
        this.certificate = certificate;
        this.parentHash = parentHash;
        this.notValidBefore = new Date(notValidBefore);
        this.notValidAfter = new Date(notValidAfter);
        this.publicKeyHash = publicKeyHash;
        this.highestTrustLevel = highestTrustLevel;
        this.highestTrustLevelEvaluationTimestamp = highestTrustLevelEvaluationTimestamp;
    }
}


class CertificateCacheEntryGo {
    constructor(subjectStr, issuerStr, timestamp, certificateBase64, parentHash, notValidBefore, notValidAfter, subjectPublicKeyInfoHash, highestTrustLevel, highestTrustLevelEvaluationTimestamp) {
        this.subjectStr = subjectStr;
        this.issuerStr = issuerStr;
        this.timestamp = new Date(timestamp);
        this.certificateBase64 = certificateBase64;
        this.parentHash = parentHash;
        this.notValidBefore = new Date(notValidBefore);
        this.notValidAfter = new Date(notValidAfter);
        this.subjectPublicKeyInfoHash = subjectPublicKeyInfoHash
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
    if (certificateCacheTest.has(certificateHash)) {
        return certificateCacheTest.get(certificateHash).certificate;
        //return certificateCache.get(certificateHash).certificateBase64;
    }
    return null;
}

// returns the certificate and the corresponding certificate chain stored in the cache for a specific key
export function getCertificateChainFromCacheByHash(leafCertificateHash) {
    if (window.GOCACHE) {
        return getCertificateChainFromCacheByHashGO(leafCertificateHash);
    } else {
        return getCertificateChainFromCacheByHashJS(leafCertificateHash);
    }

}

function getCertificateChainFromCacheByHashJS(leafCertificateHash) {
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

function getCertificateChainFromCacheByHashGO(leafCertificateHash) {
    if (!certificateCacheTest.has(leafCertificateHash)) {
        return null;
    } else {
        const certChain = [];
        let parentHash = leafCertificateHash;
        do {
            const currentCert = certificateCacheTest.get(parentHash);
            certChain.push(currentCert);
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
export async function addCertificateChainToCacheIfNecessary(pemCertificateWithoutHeader, pemCertificateChainWithoutHeader, requestId) {
    const fullChain = [pemCertificateWithoutHeader].concat(pemCertificateChainWithoutHeader.map(c => c === null ? [] : c));
    const fullChainHashes = await Promise.all(fullChain.map(async c => arrayToHexString(await hashPemCertificateWithoutHeader(c), ":")));
    let nCertificatesParsed = 0;

    if(window.GOCACHE) {
        var startParsing = performance.now();

        // decide which certificates should be parsed
        // append certificates to parse and their hashes in 
        // single strings 
        window.CertificateCacheEntryGo = CertificateCacheEntryGo;
         var pemCertificatesToAddStr = "";
         var hashesOfCertificatesToAddStr = "";
         var parentHashesOfCertificatesToAddStr = "";
         for (let i = fullChain.length - 1; i >= 0; i--) {
             const hash = fullChainHashes[i];
     
             if (certificateCacheTest.has(hash)) {
                 // the certificate was already parsed and thus all parents must have been parsed as well
                 continue;
             } else {
                 var parentHash = "";
                 if(i === 0) {
                     parentHash = null;    
                 } else {
                     parentHash = fullChainHashes[i-1];
                 }
                 const rawCertificate = fullChain[i];
                 pemCertificatesToAddStr += ("-----BEGIN CERTIFICATE-----\n"+rawCertificate+"\n-----END CERTIFICATE-----\n;");
                 hashesOfCertificatesToAddStr += (hash+"\n");
                 parentHashesOfCertificatesToAddStr += (parentHash+"\n")
             }
         }
         
         // if there are new certificates to parse, switch to Go 
         if(pemCertificatesToAddStr !== "") {
             var certificateMapObject = parsePEMCertificates(pemCertificatesToAddStr, hashesOfCertificatesToAddStr, parentHashesOfCertificatesToAddStr);
             var certificateMap = new Map(Object.entries(certificateMapObject));
     
             // append certificates to certificate cache
             for (const [hash, certificate] of certificateMap) {
                 certificateCacheTest.set(hash, certificate);
                 //console.log(certificate.notValidBefore);
                 //console.log(certificate.notValidAfter);
                 //console.log(certificate.subjectStr);
                 //console.log(certificate.subjectPublicKeyInfoHash);
             }
         }
         console.log("NEW: " + (performance.now() - startParsing) + " ENTRIES: " + certificateCacheTest.size);
    } else {
        var startParsing = performance.now();
        for (let i = fullChain.length - 1; i >= 0; i--) {
            const hash = fullChainHashes[i];
            //console.log(hash);
            //console.log(certificateCache.has(hash));
            if (certificateCache.has(hash)) {
                // the certificate was already parsed and thus all parents must have been parsed as well
                continue;
            } else {
                //const startParsing = performance.now();
                const rawCertificate = fullChain[i];
                const certificate = parsePemCertificate(rawCertificate, true);
                nCertificatesParsed += 1;
                const parentHash = i === fullChain.length - 1 ? null : fullChainHashes[i + 1];
                const notValidBefore = certificate.tbsCertificate.validity.notBefore.value;
                const notValidAfter = certificate.tbsCertificate.validity.notAfter.value;
                const publicKeyHash = await getSubjectPublicKeyInfoHash(certificate);
                //console.log(publicKeyHash);
    
                
                //const logMessage = "adding certificate to cache: subject=" + getSubject(certificate) +
                //    ", serial=" + intToHexString(certificate.tbsCertificate.serialNumber, ":") +
                //    ", validity=" + notValidBefore + "-" + notValidAfter +
                //    ", hash=" + hash +
                //    ", subjectPublicKeyInfoHash=" + publicKeyHash +
                //    ", parentHash=" + parentHash +
                //    ", cache size=" + certificateCache.size +
                //    ", time to parse=" + (performance.now() - startParsing);
                
                //cLog(requestId, logMessage);
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
        console.log("OLD: " + (performance.now() - startParsing) + " ENTRIES: " + certificateCache.size);
    }
    return { hash: fullChainHashes[0], nCertificatesParsed };
}
