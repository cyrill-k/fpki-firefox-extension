'use strict'

import {getDomainNameFromURL} from "../js_lib/domain.js"
import {checkConnection} from "../js_lib/LF-PKI-accessor.js"
import {FpkiRequest} from "../js_lib/fpki-request.js"
import {printMap} from "../js_lib/helper.js"
import {config} from "../js_lib/config.js"

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
        const domain = await getDomainNameFromURL(details.url);
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

async function checkInfo(details) {
    console.log("checkInfo ["+details.url+"]");
    const domain = await getDomainNameFromURL(details.url);

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
            checkConnection(p, remoteInfo, domain);
        });

        // TODO: check connection for all policies and continue if at least config.get("mapserver-quorum") responses exist

        // TODO: what happens if a response is invalid? we should definitely log it, but we could ignore it if enough other valid responses exist

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
