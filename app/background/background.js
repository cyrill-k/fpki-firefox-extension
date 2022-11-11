'use strict'

import * as domainFunc from "../js_lib/domain.js"
import * as error from "../js_lib/errors.js"
import * as LFPKI_accessor from "../js_lib/LF-PKI-accessor.js"

var config = new Map();
// TODO: remove duplicate local mapserver (only used for testing)
config.set("mapservers", [
    {"identity": "local-mapserver", "domain": "http://localhost:8080", "querytype": "lfpki-http-get"},
    {"identity": "local-mapserver-2", "domain": "http://localhost:8080", "querytype": "lfpki-http-get"}
]);
// cache timeout in ms
config.set("cache-timeout", 10000);
// max amount of time in ms that a connection setup takes. Used to ensure that a cached policy that is valid at the onBeforeRequest event is still valid when the onHeadersReceived event fires.
config.set("max-connection-setup-time", 1000);
// quorum of trusted map servers necessary to accept their result
config.set("mapserver-quorum", 2);
// number of mapservers queried per validated domain (currently always choosing the first n entries in the mapserver list)
config.set("mapserver-instances-queried", 2);

class FpkiRequest {
    constructor(mapserver, domain) {
        this.mapserver = mapserver;
        this.domain = domain;
        this.requestInitiated = new Date();
    }

    initiateFetchingPoliciesIfNecessary() {
        this.policiesPromise = this.initiateFetchPolicies(config.get("max-connection-setup-time"));
        return this.policiesPromise;
    }

    fetchPolicies() {
        this.policiesPromise = this.initiateFetchPolicies();
        return this.policiesPromise;
    }

    async initiateFetchPolicies(maxTimeToExpiration=0) {
        const cachedValidEntries = !shouldFetchPcaPoliciesForMapserver(this.domain, this.mapserver, maxTimeToExpiration);
        const mapserver = this.mapserver;
        let activeRequest = null;
        if (fpkiRequests.has(this.domain)) {
            fpkiRequests.get(this.domain).forEach(function(request) {
                if (request.mapserver === mapserver) {
                    activeRequest = request;
                    return false;
                }
            })
        }

        if (cachedValidEntries) {
            console.log("using cached entry ["+this.domain+", "+this.mapserver.identity+"]");
            return getLatestPcaPolicies(this.domain).get(this.mapserver).pcaPolicies;
        } else if (activeRequest !== null) {
            console.log("reusing existing active request ["+this.domain+", "+this.mapserver.identity+"]");
            return activeRequest.policiesPromise;
        } else {
            console.log("create new fetching request ["+this.domain+", "+this.mapserver.identity+"]");

            // add this request to ensure that no other request is scheduled for the same domain
            fpkiRequests.set(this.domain, map_get_list(fpkiRequests, this.domain).concat(this));

            let mapResponse;
            // fetch policy for the mapserver over the configured channel (e.g., http get)
            switch (this.mapserver.querytype) {
            case "lfpki-http-get":
                mapResponse = await LFPKI_accessor.queryMapServerHttp(this.mapserver.domain, this.domain);
                break;
            default:
                throw new error.FpkiError(error.errorTypes.INVALID_CONFIG, "Invalid mapserver config: "+this.mapserver.querytype)
                break;
            }

            // extract policies from payload
            const policies = LFPKI_accessor.extractPolicy(mapResponse);

            // add policies to policy cache
            addPcaPolicies(this.requestInitiated, this.domain, this.mapserver, policies);

            // now that the request is finished and the result is cached, the request can be removed from the list of active requests
            fpkiRequests.delete(this.domain);

            return policies;
        }
    }
};

var fpkiRequests = new Map();

var pcaPoliciesCache = new Map();

class PcaPoliciesCacheEntry {
    constructor(timestamp, mapserver, pcaPolicies) {
        this.timestamp = timestamp;
        this.mapserver = mapserver;
        this.pcaPolicies = pcaPolicies;
    }
}

function addPcaPolicies(timestamp, domain, mapserver, pcaPolicies) {
    const cacheEntry = [timestamp, mapserver, pcaPolicies];
    pcaPoliciesCache.set(domain, map_get_list(pcaPoliciesCache, domain).concat([cacheEntry]));
}

function getLatestPcaPolicies(domain) {
    const latestPolicies = new Map();
    if (pcaPoliciesCache.has(domain)) {
        for (const [timestamp, mapserver, pcaPolicies] of pcaPoliciesCache.get(domain)) {
            // see if this really works of if we need some kind of mapserver identity
            const replacePolicies = !latestPolicies.has(mapserver) || timestamp > latestPolicies.get(mapserver).timestamp;
            if (replacePolicies) {
                latestPolicies.set(mapserver, {timestamp: timestamp, pcaPolicies: pcaPolicies});
            }
        }
    }
    return latestPolicies;
}

function shouldFetchPcaPoliciesForMapserver(domain, mapserver, maxTimeToExpiration=0) {
    return getValidPcaPoliciesForMapserver(domain, mapserver, maxTimeToExpiration).length === 0;
}

function getValidPcaPoliciesForMapserver(domain, mapserver, maxTimeToExpiration=0) {
    return getAllValidPcaPolicies(domain, maxTimeToExpiration).
        filter(
            ([, entryMapserver, ]) => entryMapserver === mapserver
        );
}

function getAllValidPcaPolicies(domain, maxTimeToExpiration=0) {
    const currentTime = new Date();
    const validPcaPolicies = [];
    getLatestPcaPolicies(domain).forEach(function(value, mapserver) {
        const {timestamp:timestamp, pcaPolicies:pcaPolicies} = value;
        if (currentTime-timestamp < config.get("cache-timeout")-maxTimeToExpiration) {
            validPcaPolicies.push([timestamp, mapserver, pcaPolicies]);
        }
    });
    return validPcaPolicies;
}

function map_get_list(map, key) {
    return map.get(key) || [];
};

function redirect(details, error) {
    console.log("verification failed! -> redirecting. Reason: " + error+ " ["+details.url+"]")
    // if any error is caught, redirect to the blocking page, and show the error page
    let { tabId } = details;
    chrome.tabs.update(tabId, {
        url: browser.runtime.getURL("../htmls/block.html") + "?reason=" + error
    })
}

async function requestInfo(details) {
    console.log("requestInfo ["+details.url+"]");

    for (const [index, mapserver] of config.get("mapservers").entries()) {
        if (index === config.get("mapserver-instances-queried")) {
            break;
        }
        // could randomize the queried mapservers and remember which were queried by keeping a global map of the form [details.requestId: Array[index]]
        // const mapserver = config.get("mapservers")[0];
        const domain = await domainFunc.getDomainNameFromURL(details.url);
        const fpkiRequest = new FpkiRequest(mapserver, domain);

        const policiesPromise = fpkiRequest.initiateFetchingPoliciesIfNecessary();
        // the following is necessary to prevent a browser warning: Uncaught (in promise) Error: ...
        policiesPromise.catch((error) => {
            // do not redirect here for now since we want to have a single point of redirection to simplify logging
            // console.log("initiateFetchingPoliciesIfNecessary redirect");
            // redirect(details, error);
        });
    }
}

function printMap(m) {
    function replacer(key, value) {
        if(value instanceof Map) {
            return {
                dataType: 'Map',
                value: Array.from(value.entries()), // or with spread: value: [...value]
            };
        } else {
            return value;
        }
    }
    return JSON.stringify(m, replacer);
}

async function checkInfo(details) {
    console.log("checkInfo ["+details.url+"]");
    const domain = await domainFunc.getDomainNameFromURL(details.url);

    const remoteInfo = await browser.webRequest.getSecurityInfo(details.requestId, {
        certificateChain: true,
        rawDER: true
    })

    try {
        const policiesMap = new Map();
        for (const [index, mapserver] of config.get("mapservers").entries()) {
            if (index === config.get("mapserver-instances-queried")) {
                break;
            }
            const fpkiRequest = new FpkiRequest(mapserver, domain);
            policiesMap.set(mapserver, await fpkiRequest.fetchPolicies());
        }

        // check each policy and throw an error if one of the verifications fails
        policiesMap.forEach((p, m) => {
            console.log("starting verification for ["+domain+", "+m.identity+"] with policies: "+printMap(p));
            LFPKI_accessor.checkConnection(p, remoteInfo, domain);
        });

        // TODO: check connection for all policies and continue if at least config.get("mapserver-quorum") responses exist

        // TODO: what happens if a response is invalid? we should definitely log it, but we could ignore it if enough other valid responses exist

        // LFPKI_accessor.checkConnection(policies, remoteInfo, domain);
        console.log("verification succeeded! ["+details.url+"]");
    }
    catch (error) {
        // TODO: in case that an exception was already thrown in requestInfo, then the redirection occurs twice (but this is not an issue since they both redirect to the same error url)
        redirect(details, error);
    }
}

// add listener to header-received.
browser.webRequest.onBeforeRequest.addListener(
    requestInfo, {
        urls: ["https://www.amazon.com/*",
               "https://pay.amazon.com/*",
               "https://www.baidu.com/*",
               "https://sellercentral.amazon.com/*",
               "https://m.media-amazon.com/*",
               "http://127.0.0.1/*"]
    },
    [])

// add listener to header-received. 
browser.webRequest.onHeadersReceived.addListener(
    checkInfo, {
        urls: ["https://www.amazon.com/*",
               "https://pay.amazon.com/*",
               "https://www.baidu.com/*",
               "https://sellercentral.amazon.com/*",
               "https://m.media-amazon.com/*",
               "http://127.0.0.1/*"]
    },
    ['blocking'])
