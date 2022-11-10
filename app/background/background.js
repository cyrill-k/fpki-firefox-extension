'use strict'

import * as domainFunc from "../js_lib/domain.js"
import * as error from "../js_lib/errors.js"
import * as LFPKI_accessor from "../js_lib/LF-PKI-accessor.js"

var config = new Map();
config.set("mapservers", [{"domain": "http://localhost:8080", "querytype": "lfpki-http-get"}]);

class FpkiRequest {
    constructor(mapserver, domain) {
        this.mapserver = mapserver;
        this.domain = domain;
        this.requestInitiated = new Date();
    }

    initiateFetchPolicies() {
        this.policiesPromise = this.fetchPolicies();
    }

    async fetchPolicies() {
        let mapResponse;
        switch (this.mapserver.querytype) {
        case "lfpki-http-get":
            mapResponse = await LFPKI_accessor.queryMapServerHttp(this.mapserver.domain, this.domain);
            break;
        default:
            throw new error.FpkiError(error.errorTypes.INVALID_CONFIG, "Invalid mapserver config: "+this.mapserver.querytype)
            break;
        }
        let policies = LFPKI_accessor.extractPolicy(mapResponse);
        return policies;
    }
};
var fpkiRequests = new Map();

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
    let mapserver = config.get("mapservers")[0];
    let domain = await domainFunc.getDomainNameFromURL(details.url)
    let fpkiRequest = new FpkiRequest(mapserver, domain);
    fpkiRequest.initiateFetchPolicies();
    fpkiRequest.policiesPromise.catch((error) => {
        // do not redirect here for now since we want to have a single point of redirection to simplify logging
        // console.log("initiateFetchPolicies redirect");
        // redirect(details, error);
    });
    fpkiRequests.set(domain, map_get_list(fpkiRequests, domain).concat(fpkiRequest));
}

async function checkInfo(details) {
    console.log("checkInfo ["+details.url+"]");
    let domain = await domainFunc.getDomainNameFromURL(details.url);
    // TODO: fetch policies from multiple map servers
    let policiesPromise = fpkiRequests.get(domain)[0].policiesPromise;

    // TODO: combine policies into strictest policy
    // get remote server information
    const remoteInfo = await browser.webRequest.getSecurityInfo(details.requestId, {
        certificateChain: true,
        rawDER: true
    })

    try {
        // get map server response and check the connection
        const policies = await policiesPromise;
        LFPKI_accessor.checkConnection(policies, remoteInfo, domain);
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
