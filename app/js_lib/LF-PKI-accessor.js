import * as domainFunc from "./domain.js"
import * as verifier from "./verifier.js"
import {cLog} from "./helper.js"

// imports the function ParsePemCertificate as an object of the global variable certificateparser
import * as mymodule from "../js_lib/bundledparser.js"

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

function extractCertificates(mapResponse) {
    const rawDomainMap = extractRawCertificates(mapResponse);
    const domainMap = new Map();
    for (const [domain, rawCaMap] of rawDomainMap) {
        const caMap = new Map();
        for (const [ca, {certs, certChains}] of rawCaMap) {
            var parsedCerts = [];
            if (certs !== null) {
                parsedCerts = certs.map(c => certificateparser.parsePemCertificate("-----BEGIN CERTIFICATE-----\n"+c+"\n-----END CERTIFICATE-----"));
            }
            var parsedCertChains = [];
            if (certChains !== null) {
                parsedCertChains = certChains.map(cc => {
                    if (cc === null) {
                        return [];
                    } else {
                        return cc.map(c => certificateparser.parsePemCertificate("-----BEGIN CERTIFICATE-----\n"+c+"\n-----END CERTIFICATE-----"))
                    }
                });
            }
            caMap.set(ca, {certs: parsedCerts, certChains: parsedCertChains});
        }
        domainMap.set(domain, caMap);
    }
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
        cLog(requestId, "starting... "+fetchIndex+", triesLeft="+tries+", url="+url);
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
        cLog(requestId, "aborting after timeout... "+fetchIndex+", triesLeft="+tries);
        cLog(requestId, url);
        controller.abort();
    }, timeout);
    cLog(requestId, "fetching... "+fetchIndex+", triesLeft="+tries);
    try {
        const response = await fetch(url,{ ...fetchOptions, signal: controller.signal });
        cLog(requestId, "finished... "+fetchIndex+", triesLeft="+tries);
        return {response, triesLeft: tries};
    } catch(err) {
        const triesLeft = tries - 1;
        if(!triesLeft){
            cLog(requestId, "failed... "+fetchIndex+", triesLeft="+triesLeft);
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
