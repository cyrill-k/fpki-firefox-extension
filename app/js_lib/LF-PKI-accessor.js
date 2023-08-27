import * as domainFunc from "./domain.js"
import * as verifier from "./verifier.js"
import { cLog, convertArrayBufferToBase64, hashPemCertificateWithoutHeader } from "./helper.js"
import { addCertificateChainToCacheIfNecessary, getCertificateChainFromCacheByHash } from "./cache.js"

// get map server response and check the connection
async function getMapServerResponseAndCheck(url, needVerification, remoteInfo) {
    // get domain name
    let domainName = await domainFunc.getDomainNameFromURL(url)
    // get map server response
    const mapResponse = await queryMapServer(domainName)

    // if map server response needs verification
    if (needVerification) {
        await verifier.verifyProofs(mapResponse)
    }

    // get policies from map server response
    var policies = extractPolicy(mapResponse)

    // check connection
    checkConnection(policies, remoteInfo, domainName)
}

// check connection using the policies
function checkConnection(policies, remoteInfo, domainName) {
    // countries to CA map
    // map countries => CAs in that country
    let countryToCAMap = new Map()
    countryToCAMap.set("US CA", ["CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
                                 "CN=GTS Root R1,O=Google Trust Services LLC,C=US",
                                 "CN=Amazon,OU=Server CA 1B,O=Amazon,C=US",
                                 "CN=Amazon Root CA 1,O=Amazon,C=US",
                                 "CN=DigiCert Global CA G2,O=DigiCert Inc,C=US",
                                 "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US"])

    var CertificateException = "invalid CA"
    var DomainNotAllowed = "domain not allowed"

    // iterate all policies
    // for example: video.google.com, the policies will contain "video.google.com" and "google.com"
    policies.forEach((value, key) => {
        // check certificate's CA
        // in example, check policies for "video.google.com"
        if (key == domainName) {
            value.forEach((policyMap, _) => {
                remoteInfo.certificates.forEach((certificate, i) => {
                    // check if CA is in the trusted list
                    let caIsFound = false
                    policyMap.TrustedCA.forEach((CAName, key) => {
                        if (countryToCAMap.get(CAName).includes(certificate.issuer)) {
                            caIsFound = true
                        }
                    })

                    if (!caIsFound) {
                        throw CertificateException + ": " + certificate.issuer
                    }
                });
            });
            // check parent domain policies
            // in example, check policies for "google.com"
            // only check the direct parent domain
        } else if (domainFunc.getParentDomain(domainName) == key) {
            // check if domain is allowed
            let domainIsFound = false
            value.forEach((policyMap, _) => {
                policyMap.AllowedSubdomains.forEach((allowedDomain, key) => {
                    if (domainName == allowedDomain) {
                        domainIsFound = true
                    }
                })
            });

            if (!domainIsFound) {
                throw DomainNotAllowed + ": " + domainName
            }
        }
    });

}

//extract policies into map
function extractPolicy(mapResponse) {
    // trusted PCA map
    let trustedPCAMap = new Map()
    trustedPCAMap.set("pca", "description: ...")

    // result
    const allPolicies = new Map()
    for (var i = 0; i < mapResponse.length; i++) {
        // if domain policies exist
        if (mapResponse[i].PoI.ProofType == 1) {
            // parse it
            let entry = JSON.parse(mapResponse[i].DomainEntryBytes)

            // policies of one specific domain
            const policiesOfCurrentDomain = new Map()
            for (var j = 0; j < entry.CAEntry.length; j++) {
                if (trustedPCAMap.has(entry.CAEntry[j].CAName)) {
                    // group policies by CAs
                    policiesOfCurrentDomain.set(entry.CAEntry[j].CAName,
                                                {
                                                    TrustedCA: entry.CAEntry[j].CurrentPC.Policies.TrustedCA,
                                                    AllowedSubdomains: entry.CAEntry[j].CurrentPC.Policies.AllowedSubdomains
                                                })
                }
            }
            allPolicies.set(mapResponse[i].Domain, policiesOfCurrentDomain)
        }
    }
    return allPolicies
}

function extractRawCertificates(mapResponse) {
    // trusted CA map
    const trustedCAMap = new Map();
    // TODO: pass the domain under validation to this function (not sure if that is actually necessary) and then infer the trusted CA map from the user's trust preference
    trustedCAMap.set("GTS CA 1C3", "description: ...");
    trustedCAMap.set("DigiCert Global Root CA", "description: ...");
    trustedCAMap.set("TrustAsia TLS RSA CA", "description: ...");
    trustedCAMap.set("DigiCert SHA2 Secure Server CA", "description: ...");
    trustedCAMap.set("DigiCert Secure Site CN CA G3", "description: ...");
    trustedCAMap.set("GlobalSign Organization Validation CA - SHA256 - G2", "description: ...");
    trustedCAMap.set("DigiCert TLS Hybrid ECC SHA384 2020 CA1", "description: ...");

    const certificateMap = new Map();
    for (var i = 0; i < mapResponse.length; i++) {
        // if domain policies exist
        if (mapResponse[i].PoI.ProofType == 1) {
            // parse it
            const entry = JSON.parse(mapResponse[i].DomainEntryBytes);

            // policies of one specific domain
            const certificatesOfCurrentDomain = new Map();
            for (var j = 0; j < entry.CAEntry.length; j++) {
                // TODO: check validity of CAs specified in the CA entry
                // if (trustedCAMap.has(entry.CAEntry[j].CAName)) {
                // group certificates by CAs
                certificatesOfCurrentDomain.set(entry.CAEntry[j].CAName,
                                                {certs: entry.CAEntry[j].DomainCerts, certChains: entry.CAEntry[j].DomainCertChains});
                // }
            }
            certificateMap.set(mapResponse[i].Domain, certificatesOfCurrentDomain);
        }
    }
    return certificateMap;
}

async function extractCertificates(mapResponse, requestId) {
    const startRawExtraction = performance.now();
    const rawDomainMap = extractRawCertificates(mapResponse);
    const endRawExtraction = performance.now();
    const startParse = performance.now();
    const hashMap = new Map();

    // NOTE: the following code is used to create "mock" map server responses of 
    // the new interface based on responses via the old interface
    // TODO: remove this once new map server interface is available 
    if(window.GOCACHEV2) {
        var hashToPEMMap = {};
        for (const [domain, rawCaMap] of rawDomainMap) {
            for (const [ca, {certs, certChains}] of rawCaMap) {
                if (certs !== null) {
                    // don't use promise.all(...) since then the intermediate certificates will be parsed multiple times. `addCertificateChainToCacheIfNecessary` checks if the certificate is already cached and if not it starts parsing. The problem arises if multiple intermediate certificates for one domain use the same intermediate certificate and do this check before waiting for the other functions to parse and add the certificate to the cache.
                    for (const [i, c] of certs.entries()) {
                        let chain = certChains[i];
                        if (chain === null) {
                            chain = [];
                        }
                        const fullChain = [c].concat(chain.map(c => c === null ? [] : c));
                        const fullChainHashes = await Promise.all(fullChain.map(async c => convertArrayBufferToBase64(await hashPemCertificateWithoutHeader(c)))); 
                        for (let i = 0; i < fullChainHashes.length; i++) {
                            let certificate = fullChain[i];
                            hashToPEMMap[fullChainHashes[i]] = certificate;
                        }
                    };
                }
            }
        }

        var enc = new TextEncoder(); 
           
        // create input JSON for getMissingCertificatesList
        var hashes = [];
        for (var hash in hashToPEMMap) {
            hashes.push(hash);
        }
        let obj = {
            hashesb64: hashes
        }
        let json = JSON.stringify(obj);

        //var jsonDecodeStart = performance.now();
        hashes = enc.encode(json);
        //var jsonDecodeEnd = performance.now();
        //window.jsGetMissingCertificatesListJSONDecode.push(jsonDecodeEnd - jsonDecodeStart);
        //console.log("[JS] getMissingCertificatesList unmarshalling JSON took ", jsonDecodeEnd - jsonDecodeStart, "ms");

        // check which of the certificate hashes are not yet cached
        //const getMissingCertificatesListStart = performance.now();
        var missingCertificateHashes = getMissingCertificatesList(hashes, hashes.length);
        //const getMissingCertificatesListEnd = performance.now();
    
        //console.log("[Go] getMissingCertificatesList took ", getMissingCertificatesListEnd - getMissingCertificatesListStart, " ms, #certificates missing: ", missingCertificateHashes.length );
        //window.GoGetMissingCertificatesListTime.push(getMissingCertificatesListEnd - getMissingCertificatesListStart);
        //window.domains.push(this.domain);
        //window.GoGetMissingCertificatesListb64Decode.push(window.Gob64Decode):
        //window.GoGetMissingCertificatesListJSONDecode.push(window.GoJSONDecode);
        //window.GoGetMissingCertificatesListCopyBytes.push(window.GoCopy);

        // TODO: in the new map server interface version, need to make a second request 
        // here to get the PEM encodings of the certificates corresponding to the 
        // missing certificates

        // create input for addCertificatesToCache
        var missingCertificatesArray = [];
        for (var i in missingCertificateHashes) {
            missingCertificatesArray.push(hashToPEMMap[missingCertificateHashes[i]]);
        }
        obj = {
            certificatesb64: missingCertificatesArray
        };
        json = JSON.stringify(obj);

        //jsonDecodeStart = performance.now();
        var jsonBytes = enc.encode(json); 
        //jsonDecodeEnd = performance.now();
        //window.jsAddCertificatesToCacheJSONDecode.push(jsonDecodeEnd - jsonDecodeStart);
        //console.log("[JS] addCertificatesToCache unmarshalling JSON took ", jsonDecodeEnd - jsonDecodeStart, "ms");

        //base64DecodeStart = performance.now();
        //base64DecodeEnd = performance.now();
        //window.jsAddCertificatesToCacheb64Decode.push(base64DecodeEnd - base64DecodeStart);
        //console.log("[JS] addCertificatesToCache base64decode took ", base64DecodeEnd - base64DecodeStart, "ms");



        // add the missing certificates to the cache
        //const addCertificatesToCacheStart = performance.now();
        addCertificatesToCache(jsonBytes, jsonBytes.length);
        //const addCertificatesToCacheEnd = performance.now();
        //window.GoAddCertificatesToCacheTime.push(addCertificatesToCacheEnd - addCertificatesToCacheStart);
        //window.GoAddCertificatesSignatureTime.push(window.GoSignature);
        //window.GoAddCertificatesToCacheb64Decode.push(window.Gob64Decode);
        //window.GoAddCertificatesToCacheJSONDecode.push(window.GoJSONDecode);
        //window.GoAddCertificatesToCacheCopyBytes.push(window.GoCopy);
        //window.GoAddCertificatesToCacheParseCertificates.push(window.GoParseCertificates);
        //window.GoNCertificatesAdded.push(window.GoNCertsAdded);

        //console.log("[Go] addCertificatesToCache took ", window.GoAddCertificatesToCacheTime, " ms");   
        
        // to prevent crash of the addMapserverResponse call
        // in fpki-request.js LOC 135
        return new Map([]); 
    }

    let totalCertificatesParsed = 0;
    for (const [domain, rawCaMap] of rawDomainMap) {
        const caMap = new Map();
        for (const [ca, {certs, certChains}] of rawCaMap) {
            let certHashes = [];
            if (certs !== null) {
                // don't use promise.all(...) since then the intermediate certificates will be parsed multiple times. `addCertificateChainToCacheIfNecessary` checks if the certificate is already cached and if not it starts parsing. The problem arises if multiple intermediate certificates for one domain use the same intermediate certificate and do this check before waiting for the other functions to parse and add the certificate to the cache.
                for (const [i, c] of certs.entries()) {
                    let chain = certChains[i];
                    if (chain === null) {
                        chain = [];
                    }
                    const {hash, nCertificatesParsed} = await addCertificateChainToCacheIfNecessary(c, chain);
                    totalCertificatesParsed += nCertificatesParsed;
                    certHashes.push(hash);
                };
            }
            caMap.set(ca, {certHashes: certHashes});
        }
        hashMap.set(domain, caMap);
    }
    const endParse = performance.now();
    const nEntries = Array.from(hashMap.values()).reduce((a, caMap) => {
        return a + Array.from(caMap.values()).reduce((aa, {certHashes}) => {
            return aa + certHashes.length;
        }, 0);
    }, 0);

    // Fetch the certificate for each of the certificate hashes
    const startFetchCert = performance.now();
    const domainMap = new Map();
    for (const [domain, hashMapCa] of hashMap) {
        const caMap = new Map();
        for (const [ca, {certHashes}] of hashMapCa) {
            const certs = [];
            const certChains = [];
            certHashes.forEach(hash => {
                const certChainWithLeaf = getCertificateChainFromCacheByHash(hash);
                certs.push(certChainWithLeaf[0]);
                certChains.push(certChainWithLeaf.slice(1));
            });
            caMap.set(ca, {certs, certChains});
        }
        domainMap.set(domain, caMap);
    }
    const endFetchCert = performance.now();

    cLog(requestId, `LF-PKI response parsing (${nEntries} entries): raw=${endRawExtraction - startRawExtraction} ms, hash (and parse ${totalCertificatesParsed} certs)=${endParse - startParse} ms, fetch cert from cache=${endFetchCert-startFetchCert} ms`);

    return domainMap;
}

// query map server
async function queryMapServer(domainName) {
    let resp = await fetch("http://localhost:8080/?domain=" + domainName)
    let domainEntries = await resp.json()

    let base64decodedEntries = base64DecodeDomainEntry(domainEntries)

    return domainEntries
}

var fetchCounter = 1;

function wait(delay){
    return new Promise((resolve) => setTimeout(resolve, delay));
}

async function fetchRetry(url, delay, tries, timeout, requestId, fetchIndex=0, fetchOptions = {}) {
    if (fetchIndex === 0) {
        fetchIndex = fetchCounter
        fetchCounter += 1;
        cLog(requestId, "["+fetchIndex+"] starting... triesLeft="+tries+", url="+url);
    }
    // function onError(err){
    //     const triesLeft = tries - 1;
    //     if(!triesLeft){
    //         cLog(requestId, "failed... "+fetchIndex+", triesLeft="+triesLeft);
    //         throw err;
    //     }
    //     return wait(delay).then(() => fetchRetry(url, delay, triesLeft, requestId, fetchIndex, fetchOptions));
    // }
    const controller = new AbortController();
    const id = setTimeout(() => {
        cLog(requestId, "["+fetchIndex+"] aborting after timeout... triesLeft="+tries);
        controller.abort();
    }, timeout);
    cLog(requestId, "["+fetchIndex+"] fetching... triesLeft="+tries);
    try {
        const response = await fetch(url,{ ...fetchOptions, signal: controller.signal });
        cLog(requestId, "["+fetchIndex+"] finished... triesLeft="+tries);
        return {response, triesLeft: tries};
    } catch(err) {
        const triesLeft = tries - 1;
        if(!triesLeft){
            cLog(requestId, "["+fetchIndex+"] failed... triesLeft="+triesLeft);
            throw err;
        }
        return wait(delay).then(() => fetchRetry(url, delay, triesLeft, timeout, requestId, fetchIndex, fetchOptions));
    } finally {
        // TODO: check if the timeout is cleared at the correct time (i.e., before waiting for the recursive call in the catch block
        clearTimeout(id);
    }
}

async function fetchWithTimeout(resource, options = {}) {
    const { timeout = 60000, requestId } = options;

    const currentFetchId = fetchCounter;
    fetchCounter += 1;

    const controller = new AbortController();
    const id = setTimeout(() => {
        cLog(requestId, "aborting... "+currentFetchId);
        cLog(requestId, resource);
        controller.abort();
    }, timeout);
    cLog(requestId, "starting... "+currentFetchId);
    const response = await fetch(resource, {
        ...options,
        signal: controller.signal
    });
    cLog(requestId, "cancelling... "+currentFetchId);
    clearTimeout(id);
    return response;
}

// query map server
async function queryMapServerHttp(mapServerUrl, domainName, options) {
    const fetchUrl = mapServerUrl+"/?domain="+domainName;
    // let resp = await fetchWithTimeout(fetchUrl, options);
    const { delay=0, timeout=60000, maxTries=3, requestId } = options;
    let {response, triesLeft} = await fetchRetry(fetchUrl, delay, maxTries, timeout, requestId, 0, { keepalive: true });
    let domainEntries = await response.json();

    let base64decodedEntries = base64DecodeDomainEntry(domainEntries);

    return {response: domainEntries, fetchUrl: fetchUrl, nRetries: maxTries-triesLeft};
}

function base64DecodeDomainEntry(response) {
    for (var i = 0; i < response.length; i++) {
        let replaced = response[i].DomainEntryBytes.replace("+", "-")
        let domainEntryDecoded = atob(replaced)
        response[i].DomainEntryBytes = domainEntryDecoded
    }
    return response
}

export {
    queryMapServer,
    queryMapServerHttp,
    extractPolicy,
    extractCertificates,
    checkConnection
}
