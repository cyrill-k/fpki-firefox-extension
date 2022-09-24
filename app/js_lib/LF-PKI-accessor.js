import * as domainFunc from "./domain.js"
import * as verifier from "./verifier.js"

async function getMapServerResponseAndAnalyse(url, needVerification) {
    const mapResponse = await queryMapServer(domainFunc.getDomainNameFromURL(url))

    if (needVerification) {
        let isVerified = await verifier.verifyProofs(mapResponse)
        if (isVerified) {
            console.log("succeed!")
        }
    }

    var currentPolicies = extractPolicy(mapResponse)
    console.log(...currentPolicies.keys())
}

//extract policies into map
function extractPolicy(mapResponse) {
    const allPolicies = new Map()
    for (var i = 0; i < mapResponse.length; i++) {
        try {
            if (mapResponse[i].PoI.ProofType == 1) {
                let entry = JSON.parse(mapResponse[i].DomainEntryBytes)

                const policiesOfCurrentDomain = new Map()
                for (var j = 0; j < entry.CAEntry.length; j++) {
                    policiesOfCurrentDomain.set(entry.CAEntry[j].CAName,
                        {
                            TrustedCA: entry.CAEntry[j].CurrentPC.Policies.TrustedCA,
                            AllowedSubdomains: entry.CAEntry[j].CurrentPC.Policies.AllowedSubdomains
                        })
                }
                allPolicies.set(mapResponse[i].Domain, policiesOfCurrentDomain)
            }
        }
        catch (error) {
            console.error(error)
        }
    }

    return allPolicies
}



async function queryMapServer(domainName) {
    try {
        let resp = await fetch("http://localhost:8080/?domain=" + domainName)
        let domainEntries = await resp.json()

        let base64decodedEntries = base64DecodeDomainEntry(domainEntries)

        return domainEntries
    } catch (error) {
        console.error(error)
    }
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
    getMapServerResponseAndAnalyse
}
