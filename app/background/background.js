'use strict'

import {getDomainNameFromURL} from "../js_lib/domain.js"
import {checkConnection} from "../js_lib/LF-PKI-accessor.js"
import {FpkiRequest} from "../js_lib/fpki-request.js"
import {printMap} from "../js_lib/helper.js"
import {config} from "../js_lib/config.js"
import {LogEntry, getLogEntryForRequest, downloadLog, printLogEntriesToConsole} from "../js_lib/log.js"

// communication between browser plugin popup and this background script
browser.runtime.onConnect.addListener(function(port) {
    port.onMessage.addListener(function(msg) {
        switch (msg) {
        case 'printLog':
            printLogEntriesToConsole();
            break;
        case 'downloadLog':
            downloadLog();
            break;
        }
    });
})

// TODO: remove duplicate local mapserver (only used for testing)
// use 127.0.0.11 instead of localhost to distinguish the second test server from the first one (although it is the same instance)
// also, using 127.0.0.11 ensures that the mapserver IPs do not clash with the local test webpage at 127.0.0.1
config.set("mapservers", [
    {"identity": "local-mapserver", "domain": "http://localhost:8080", "querytype": "lfpki-http-get"},
    {"identity": "local-mapserver-2", "domain": "http://127.0.0.11:8080", "querytype": "lfpki-http-get"}
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

function shouldValidateDomain(domain) {
    // ignore mapserver addresses since otherwise there would be a circular dependency which could not be resolved
    return config.get("mapservers").every(({ domain: d }) => getDomainNameFromURL(d) !== domain);
}

async function requestInfo(details) {
    const perfStart = performance.now();
    const startTimestamp = new Date();
    console.log("requestInfo ["+details.url+"]: "+JSON.stringify(details));

    const domain = getDomainNameFromURL(details.url);
    if (!shouldValidateDomain(domain)) {
        // console.log("ignoring (no requestInfo): " + domain);
        return;
    }
    const logEntry = new LogEntry(startTimestamp, domain, details.tabId, details.method, details.type, perfStart);
    for (const [index, mapserver] of config.get("mapservers").entries()) {
        if (index === config.get("mapserver-instances-queried")) {
            break;
        }
        // could randomize the queried mapservers and remember which were queried by keeping a global map of the form [details.requestId: Array[index]]
        const fpkiRequest = new FpkiRequest(mapserver, domain, details.requestId);

        const policiesPromise = fpkiRequest.initiateFetchingPoliciesIfNecessary();
        // the following is necessary to prevent a browser warning: Uncaught (in promise) Error: ...
        policiesPromise.catch((error) => {
            logEntry.fpkiRequestInitiateError(mapserver.identity, error.message);
            // do not redirect here for now since we want to have a single point of redirection to simplify logging
            // console.log("initiateFetchingPoliciesIfNecessary redirect");
            // redirect(details, error);
        });
    }
    console.log("tracking request: "+JSON.stringify(details));
    logEntry.trackRequest(details.requestId);
}

async function checkInfo(details) {
    const onHeadersReceived = performance.now();
    const logEntry = getLogEntryForRequest(details.requestId);
    console.log("checkInfo ["+details.url+"]: "+JSON.stringify(details));
    const domain = getDomainNameFromURL(details.url);
    if (!shouldValidateDomain(domain)) {
        // console.log("ignoring (no checkInfo): " + domain);
        return;
    }
    if (typeof logEntry === "undefined") {
        // ensure that if checkInfo is called multiple times for a single request, logEntry is ignored
        console.log("UNDEFINED log entry: "+details);
    }

    const remoteInfo = await browser.webRequest.getSecurityInfo(details.requestId, {
        certificateChain: true,
        rawDER: true
    })

    let decision = "accept";
    try {
        const policiesMap = new Map();
        for (const [index, mapserver] of config.get("mapservers").entries()) {
            if (index === config.get("mapserver-instances-queried")) {
                break;
            }
            const fpkiRequest = new FpkiRequest(mapserver, domain, details.requestId);
            console.log("await fpki request for +["+domain+", "+mapserver.identity+"]: rid="+details.requestId);
            const {policies, metrics} = await fpkiRequest.fetchPolicies();
            policiesMap.set(mapserver, policies);
            logEntry.fpkiResponse(mapserver, policies, metrics);
            console.log("await finished for fpki request for +["+domain+", "+mapserver.identity+"]: rid="+details.requestId);
        }

        // check each policy and throw an error if one of the verifications fails
        policiesMap.forEach((p, m) => {
            console.log("starting verification for ["+domain+", "+m.identity+"] with policies: "+printMap(p));
            checkConnection(p, remoteInfo, domain);
        });

        // TODO: check connection for all policies and continue if at least config.get("mapserver-quorum") responses exist

        // TODO: what happens if a response is invalid? we should definitely log it, but we could ignore it if enough other valid responses exist

        console.log("verification succeeded! ["+details.url+"]");
    } catch (error) {
        // TODO: in case that an exception was already thrown in requestInfo, then the redirection occurs twice (but this is not an issue since they both redirect to the same error url)
        decision = "reject: "+error
        redirect(details, error);
    } finally {
        const onHeadersReceivedFinished = performance.now();
        logEntry.validationFinished(decision, onHeadersReceived, onHeadersReceivedFinished);
        logEntry.finalizeLogEntry(details.requestId);
    }
}

// function extractTimings(timingEntry) {
//     return {
//         dnsLookup: timingEntry.domainLookupEnd-timingEntry.domainLookupStart,
//         transportSetup: timingEntry.connectEnd - timingEntry.connectStart,
//         secureTransportSetup: timingEntry.connectEnd - timingEntry.secureConnectionStart
//     };
// }

async function onCompleted(details) {
    const domain = getDomainNameFromURL(details.url);
    if (!shouldValidateDomain(domain)) {
        // console.log("ignoring (no requestInfo): " + domain);
        return;
    }
    console.log("onCompleted: "+JSON.stringify(details));
    console.log(printLogEntriesToConsole());
    const remoteInfo = await browser.webRequest.getSecurityInfo(details.requestId, {
        certificateChain: true,
        rawDER: true
    });
    console.log(remoteInfo);
}

// add listener to header-received.
browser.webRequest.onBeforeRequest.addListener(
    requestInfo, {
        urls: ["*://*/*"]
    },
    [])

// add listener to header-received. 
browser.webRequest.onHeadersReceived.addListener(
    checkInfo, {
        urls: ["*://*/*"]
    },
    ['blocking', 'responseHeaders'])

browser.webRequest.onCompleted.addListener(
    onCompleted, {
        urls: ["*://*/*"]
    })
