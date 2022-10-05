import * as domainFunc from "./domain.js"
import * as verifier from "./verifier.js"

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
    // trusted pca map
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

// query map server
async function queryMapServer(domainName) {
    let resp = await fetch("http://localhost:8080/?domain=" + domainName)
    let domainEntries = await resp.json()

    let base64decodedEntries = base64DecodeDomainEntry(domainEntries)

    return domainEntries
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
    getMapServerResponseAndCheck
}
