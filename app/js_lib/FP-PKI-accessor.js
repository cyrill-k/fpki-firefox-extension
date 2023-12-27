import {errorTypes, FpkiError} from "./errors.js"
import * as domainFunc from "./domain.js"
import * as verifier from "./verifier.js"
import { cLog, convertArrayBufferToBase64, hashPemCertificateWithoutHeader, arrayToHexString, base64ToHex, trimString } from "./helper.js"
import { addCertificateChainToCacheIfNecessary, getCertificateChainFromCacheByHash } from "./cache.js"
import {config} from "./config.js"

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

function* splitIntoIDs(base64IDs) {
    const rawIds = atob(base64IDs);
    const nHashes = rawIds.length / 32
    for (let i = 0; i < nHashes; i++) {
        yield btoa(rawIds.slice(i * 32, (i + 1) * 32))
    }
}

function extractIDsFromMapserverResponse(mapResponse, requestId) {
    const requiredHashes = new Set();
    const requiredPolicyHashes = new Set();
    let nTotalHashes = 0;
    let nTotalPolicyHashes = 0;
    for (const entry of mapResponse) {
        if (entry.DomainEntry.CertIDs !== null) {
            const base64IDs = entry.DomainEntry.CertIDs;
            let nHashes = 0;
            for (const id of splitIntoIDs(base64IDs)) {
                requiredHashes.add(id);
                nHashes += 1;
            }
            nTotalHashes += nHashes;
            cLog(requestId, `entry for ${entry.DomainEntry.DomainName} contains ${nHashes} ids`);
        }
        if (entry.DomainEntry.PolicyIDs !== null) {
            const base64IDs = entry.DomainEntry.PolicyIDs;
            let nHashes = 0;
            for (const id of splitIntoIDs(base64IDs)) {
                requiredPolicyHashes.add(id);
                nHashes += 1;
            }
            nTotalPolicyHashes += nHashes;
            cLog(requestId, `[policy] entry for ${entry.DomainEntry.DomainName} contains ${nHashes} ids`);
        }
    }
    cLog(requestId, `total: ${nTotalHashes} ids (${requiredHashes.size} unique ids)`);
    cLog(requestId, `[policy] total: ${nTotalPolicyHashes} ids (${requiredPolicyHashes.size} unique ids)`);
    return { requiredCertificateIDs: requiredHashes, requiredPolicyIDs: requiredPolicyHashes };
}

export class VerifyAndGetMissingIDsResponseGo {
    constructor(verificationResult, certificateIDs, policyIDs) {
        this.verificationResult = verificationResult;
        this.certificateIDs = certificateIDs;
        this.policyIDs = policyIDs;
    }
}

export class AddMissingPayloadsResponseGo {
    constructor(processedCertificateIDs, processedPolicyIDs) {
        this.processedCertificateIDs = processedCertificateIDs;
        this.processedPolicyIDs = processedPolicyIDs;
    }
}

async function retrieveMissingCertificatesAndPolicies(mapResponse, requestId, mapResponseNew, mapserverDomain) {
    const startRawExtraction = performance.now();
    const rawDomainMap = new Map()
    const endRawExtraction = performance.now();
    const startParse = performance.now();
    const hashMap = new Map();

    if (window.GOCACHEV2) {
        cLog(requestId, "Verifying MHT inclusion proof and finding missing IDs");
        let json = JSON.stringify(mapResponseNew);
        const enc = new TextEncoder();
        let jsonBytes = enc.encode(json);
        const { verificationResult, certificateIDs: missingCertificateIDs, policyIDs: missingPolicyIDs } = verifyAndGetMissingIDs(jsonBytes, jsonBytes.length);
        // TODO: check verification result

        const missingIDs = missingCertificateIDs.concat(missingPolicyIDs);
        if (missingIDs.length > 0) {
            cLog(requestId, `Detected ${missingIDs.length} missing IDs (${missingCertificateIDs.length} certs, ${missingPolicyIDs.length} policies): Fetching missing payloads...`);
            // fetch missing certificates
            let getParameter = "";
            for (const hash of missingIDs) {
                getParameter += base64ToHex(hash);
            }
            let result;
            try {
                result = await queryMapServerPayloads(mapserverDomain, getParameter, { timeout: config.get("proof-fetch-timeout"), requestId: requestId, maxTries: config.get("proof-fetch-max-tries") });
            } catch (error) {
                throw new FpkiError(errorTypes.MAPSERVER_NETWORK_ERROR, error);
            }
            const obj = {
                certificateIDs: missingCertificateIDs,
                policyIDs: missingPolicyIDs,
                payloads: [...result.response]
            };
            json = JSON.stringify(obj);
            jsonBytes = enc.encode(json);

            cLog(requestId, `Adding ${obj.payloads.length} payloads to the cache...`);
            const { processedCertificateIDs, processedPolicyIDs } = addMissingPayloads(jsonBytes, jsonBytes.length);
            cLog(requestId, `Added ${processedCertificateIDs.length} certificates and ${processedPolicyIDs.length} policies to the cache`);

            const processedCertificatesSet = new Set(processedCertificateIDs)
            const unprovidedCertificates = missingCertificateIDs.filter((value, index) => !processedCertificatesSet.has(value));
            if (unprovidedCertificates.length > 0) {
                console.log(`The response from map server ${mapserverDomain} is missing ${unprovidedCertificates.length} certificates: ${unprovidedCertificates}`);
                throw new FpkiError(errorTypes.MAPSERVER_NETWORK_ERROR, "map server did not provide all certificate payloads");
            }
            const processedPoliciesSet = new Set(processedPolicyIDs)
            const unprovidedPolicies = missingPolicyIDs.filter((value, index) => !processedPoliciesSet.has(value));
            if (unprovidedPolicies.length > 0) {
                console.log(`The response from map server ${mapserverDomain} is missing ${unprovidedPolicies.length} policies: ${unprovidedPolicies}`);
                throw new FpkiError(errorTypes.MAPSERVER_NETWORK_ERROR, "map server did not provide all policy payloads");
            }
        }

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

    return { certificatesOld: domainMap };
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
        cLog(requestId, "["+fetchIndex+"] starting... triesLeft="+tries+", url="+trimString(url));
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

// query map server for certificate and policy IDs
async function queryMapServerIdsWithProof(mapServerUrl, domainName, options) {
    const fetchUrl = mapServerUrl+"/getproof?domain="+domainName;
    console.log(`initiating request: ${trimString(fetchUrl)}`);
    const { delay=0, timeout=60000, maxTries=3, requestId } = options;
    const {response, triesLeft} = await fetchRetry(fetchUrl, delay, maxTries, timeout, requestId, 0, { keepalive: true });
    const decodedResponse = await response.json();

    return {response: decodedResponse, fetchUrl: fetchUrl, nRetries: maxTries-triesLeft};
}

// query map server for certificate and policy payloads
async function queryMapServerPayloads(mapServerUrl, ids, options) {
    const fetchUrl = mapServerUrl+"/getpayloads?ids="+ids;
    const { delay=0, timeout=60000, maxTries=3, requestId } = options;
    const {response, triesLeft} = await fetchRetry(fetchUrl, delay, maxTries, timeout, requestId, 0, { keepalive: true });
    const decodedResponse = await response.json();

    return {response: decodedResponse, fetchUrl: fetchUrl, nRetries: maxTries-triesLeft};
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
    queryMapServerIdsWithProof,
    queryMapServerPayloads,
    extractPolicy,
    retrieveMissingCertificatesAndPolicies,
    checkConnection
}
