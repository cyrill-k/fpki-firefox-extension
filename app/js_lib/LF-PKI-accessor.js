import * as domainFunc from "./domain.js"
import * as verifier from "./verifier.js"

async function getMapServerResponseAndCheck(url, needVerification, remoteInfo, details) {
    let domainName = await domainFunc.getDomainNameFromURL(url)
    const mapResponse = await queryMapServer(domainName)

    if (needVerification) {
        await verifier.verifyProofs(mapResponse)
    }

    var policies = extractPolicy(mapResponse)

    checkConnection(policies, remoteInfo, domainName)
}

function checkConnection(policies, remoteInfo, domainName) {
    let countryToCAMap = new Map()
    countryToCAMap.set("US CA", ["CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
        "CN=GTS Root R1,O=Google Trust Services LLC,C=US",
        "CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE"])

    var CertificateException = "invalid CA"
    var DomainNotAllowed = "domain not allowed"

    policies.forEach((value, key) => {
         // check certificate
        if (key == domainName) {
            value.forEach((policyMap, _) => {
                remoteInfo.certificates.forEach((certificate, i) => {
                    let caIsFound = false
                    policyMap.TrustedCA.forEach((CAName, key)=>{
                        if(countryToCAMap.get(CAName).includes(certificate.issuer)){
                            caIsFound = true
                        }
                    })
                    
                    if (!caIsFound) {
                        throw CertificateException + ": " + certificate.issuer
                    }
                });
            });
            // check parent domain policies
        }else if(domainFunc.getParentDomain(domainName) == key){
            let domainIsFound = false
            value.forEach((policyMap, _) => {
                policyMap.AllowedSubdomains.forEach((allowedDomain, key)=>{
                    if(domainName == allowedDomain){
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
    let trustedPCAMap = new Map()
    trustedPCAMap.set("pca", "description: ...")
    const allPolicies = new Map()
    for (var i = 0; i < mapResponse.length; i++) {

        if (mapResponse[i].PoI.ProofType == 1) {
            let entry = JSON.parse(mapResponse[i].DomainEntryBytes)

            const policiesOfCurrentDomain = new Map()
            for (var j = 0; j < entry.CAEntry.length; j++) {
                if (trustedPCAMap.has(entry.CAEntry[j].CAName)) {

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

/*
function deserialiseJsonDomainEntryBytes(response) {
    for (var i = 0; i < response.length; i++) {
        let domainEntryDecode = atob(response[i].DomainEntryBytes)
        let entry = JSON.parse(domainEntryDecode)
        response[i].DomainEntryBytes = entry
    }
    return response
}*/

export {
    getMapServerResponseAndCheck
}
