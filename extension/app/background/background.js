'use strict'

import { getDomainNameFromURL } from "../js_lib/domain.js";
import { FpkiRequest } from "../js_lib/fpki-request.js";
import { printMap, cLog, mapGetList, mapGetMap, mapGetSet, trimString, trimUrlToDomain } from "../js_lib/helper.js";
import { config, downloadConfig, initializeConfig, getConfig, saveConfig, resetConfig, setConfig, exportConfigToJSON, getConfigRequest, convertMapsToObjects, convertMapsToSerializableObject } from "../js_lib/config.js";
import { LogEntry, getLogEntryForRequest, printLogEntriesToConsole, getSerializedLogEntries } from "../js_lib/log.js";
import { FpkiError, errorTypes } from "../js_lib/errors.js";
import { policyValidateConnection, legacyValidateConnection, legacyValidateConnectionGo, policyValidateConnectionGo } from "../js_lib/validation.js";
import { hasApplicablePolicy, getShortErrorMessages, hasFailedValidations, LegacyTrustDecisionGo, PolicyTrustDecisionGo, getLegacyValidationErrorMessageGo, getPolicyValidationErrorMessageGo } from "../js_lib/validation-types.js";
import "../js_lib/wasm_exec.js";
import { VerifyAndGetMissingIDsResponseGo, AddMissingPayloadsResponseGo } from "../js_lib/FP-PKI-accessor.js";
import { getUserId, logError, logInfo, REMOTE_LOKI_HOST } from "../js_lib/loki_logger.js";

async function initialize() {
    try { 
        await initializeConfig();
        await getUserId();
        globalThis.GOCACHE = await getConfig("wasm-certificate-parsing");
        globalThis.GOCACHEV2 = await getConfig("wasm-certificate-caching");
        
        // add listener to header-received.
        chrome.webRequest.onBeforeRequest.addListener(
            requestInfo, { urls: ["*:/\/*\/*"] },[]
        );

        // add listener to header-received. 
        chrome.webRequest.onHeadersReceived.addListener(
            checkInfo, {urls: ["*:/\/*\/*"]}, ['responseHeaders']
        );

        chrome.webRequest.onCompleted.addListener(
            onCompleted, { urls: ["*:/\/*\/*"] }
        )

        // flag whether to use Go cache
        // instance to call Go Webassembly functions
        if (globalThis.GOCACHE) {
            const go = new Go();
            const parsePemCertificateWasm = await fetch(chrome.runtime.getURL("js_lib/wasm/parsePEMCertificate.wasm"));
            const parsePemCertificateBytes = await parsePemCertificateWasm.arrayBuffer();
            const parsePemCertificateResult = await WebAssembly.instantiate(parsePemCertificateBytes, go.importObject);
            go.run(parsePemCertificateResult.instance);
        } else if (globalThis.GOCACHEV2) {
            const go = new Go();
            const gocachev2Wasm = await fetch(chrome.runtime.getURL("go_wasm/gocachev2.wasm"));
            const gocachev2Bytes = await gocachev2Wasm.arrayBuffer();
            const gocachev2Result = await WebAssembly.instantiate(gocachev2Bytes, go.importObject);
            go.run(gocachev2Result.instance);
            const nCertificatesAdded = initializeGODatastructures("embedded/ca-certificates", "embedded/pca-certificates", exportConfigToJSON(await getConfig()));
            logInfo(`[Go] Initialize cache with trust roots: #certificates = ${nCertificatesAdded[0]}, #policies = ${nCertificatesAdded[1]}`);
            // make js classes for encapsulating return values available to WASM
            globalThis.LegacyTrustDecisionGo = LegacyTrustDecisionGo;
            globalThis.PolicyTrustDecisionGo = PolicyTrustDecisionGo;
            globalThis.VerifyAndGetMissingIDsResponseGo = VerifyAndGetMissingIDsResponseGo;
            globalThis.AddMissingPayloadsResponseGo = AddMissingPayloadsResponseGo;
        }
    } catch (e) {
        logError("Error during initialization: " + e);
    }
}

chrome.runtime.onInstalled.addListener(async () => {
    await initialize();
    logInfo("User initialized extention");
});
/** 
 * Receive one way messages from extension pages
 */
chrome.runtime.onConnect.addListener((port) => {
    logInfo("Connected to port: " + port.name);
    port.onMessage.addListener((msg, _sender, sendResponse) => {
        logInfo("Received message: " + JSON.stringify(msg));
        switch (msg.type) {
        case "acceptCertificate":
            const {domain, certificateFingerprint, tabId, url} = msg;
            trustedCertificates.set(domain, mapGetSet(trustedCertificates, domain).add(certificateFingerprint));
            chrome.tabs.update(tabId, {url: url});
            break;
        case 'postConfig':
            (async () => { 
                await setConfig(msg.value);
                await saveConfig();
                await clearCaches();
            })()
            getConfigRequest().then(sendResponse);
            return true;
        default:
            switch (msg) {
            case 'initFinished':
                (async () => {
                    const cfg = await getConfig();
                    if (!cfg) {
                        logError("Config is undefined");
                    } else {
                        port.postMessage({ msgType: "config", value: JSON.stringify(cfg) });
                        sendResponse({});
                    }
                })()
                return true;
            case 'printConfig':
                (async () => {
                    const cfg = await getConfig();
                    if (!cfg) {
                        logError("Config is undefined");
                    } else {
                        port.postMessage({ msgType: "config", value: JSON.stringify(cfg) });
                        sendResponse({});
                    }
                })()
                return true;
            case 'downloadConfig':
                logInfo("MSG RECV: downloadConfig");
                downloadConfig()
                break;
            case 'resetConfig':
                exit(1);
                logInfo("MSG RECV: resetConfig");
                (async () => {
                    await resetConfig();
                })()
                sendResponse({});
                return true;
            case 'showValidationResult':
                getConfigRequest().then((cfg) => {
                    if (!cfg) {
                        logError("Config is undefined");
                    } else {
                        port.postMessage({ msgType: "validationResults", value: convertMapsToSerializableObject(trustDecisions), config: cfg });
                    }
                }).then(sendResponse);
                return true;
            case 'printLog':
                printLogEntriesToConsole();
                break;
            case 'getLogEntries':
                port.postMessage({msgType: "logEntries", value: getSerializedLogEntries()});
                break;
            case 'requestConfig':
                port.postMessage("Hi there");
                break;
            }
        }
    });
})

/**
 * Receive messages with possibility of direct response
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'log') {
        sendResponse({});
        return true;
    };

    switch(request) {
        case 'requestConfig':
            getConfigRequest().then(sendResponse);
            return true;
        case 'resetConfig':
            (async () => { 
                await resetConfig();
                await saveConfig();
                await clearCaches();
            })()
            getConfigRequest().then(sendResponse);
            return true;
        
        default:
            switch (request['type']) {
                case "uploadConfig":
                    logInfo("Received new config value: " + JSON.stringify(request['value']));
                    (async () => {
                    await setConfig(request['value']);
                    await saveConfig();
                    await clearCaches();
                    })()
                    return true;
                default:
                    logError(`Received unknown message: ${request} ${JSON.stringify(request)}`);
                    break;
                    
            }
    }

    return true;
});

async function clearCaches() {
    logInfo("Clearing js and golang (WASM) caches...");
    trustDecisions = new Map();
    legacyTrustDecisionCache = new Map();
    policyTrustDecisionCache = new Map();
    const config = await getConfig();
    const jsonStringConfig = exportConfigToJSON(config);
    initializeGODatastructures("embedded/ca-certificates", "embedded/pca-certificates", jsonStringConfig);
}

// window.addEventListener('unhandledrejection', function(event) {
//   // the event object has two special properties:
//   alert(event.promise); // [object Promise] - the promise that generated the error
//   alert(event.reason); // Error: Whoops! - the unhandled error object
// });


let trustDecisions = new Map();

// cache mapping (domain, leaf certificate fingerprint) tuples to legacy trust decisions.
let legacyTrustDecisionCache = new Map();

// cache mapping (domain, leaf certificate fingerprint) tuples to policy trust decisions.
let policyTrustDecisionCache = new Map();

// contains certificates that are trusted even if legacy (and policy) validation fails
// data structure is a map [domain] => [x509 fingerprint]
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/CertificateInfo
const trustedCertificates = new Map();

function redirect(details, error, certificateChain=null) {
    cLog(details.requestId, "verification failed! -> redirecting. Reason: " + error+ " ["+details.url+"]");
    logError("verification failed! -> redirecting. Reason: " + error+ " ["+details.url+"]", {requestId: details.requestId});
    // if any error is caught, redirect to the blocking page, and show the error page
    let { tabId } = details;
    let htmlErrorFile;
    let reason = error.toString();
    let stacktrace = null;
    if (error.errorType === errorTypes.MAPSERVER_NETWORK_ERROR) {
        htmlErrorFile = "../htmls/map-server-error/block.html";
    } else if (error.errorType === errorTypes.LEGACY_MODE_VALIDATION_ERROR) {
        htmlErrorFile = "../htmls/validation-error-warning/block.html";
    } else if (error.errorType === errorTypes.POLICY_MODE_VALIDATION_ERROR) {
        htmlErrorFile = "../htmls/validation-error-blocking/block.html";
    } else {
        htmlErrorFile = "../htmls/other-error/block.html";
        stacktrace = error.stack;
    }

    let url = chrome.runtime.getURL(htmlErrorFile) + "?reason=" + encodeURIComponent(reason) + "&domain=" + encodeURIComponent(getDomainNameFromURL(details.url));

    if (stacktrace !== null) {
        url += "&stacktrace="+encodeURIComponent(stacktrace);
    }

    // set the gobackurl such that if the user accepts the certificate of the main page, he is redirected to this same main page.
    // But if a resource such as an embedded image is blocked, the user should be redirected to the document url of the main page (and not the resource)
    if (typeof details.documentUrl === "undefined") {
        url += "&url=" + encodeURIComponent(details.url);
    } else {
        url += "&url=" + encodeURIComponent(details.documentUrl);
    }

    if (certificateChain !== null) {
        url += "&fingerprint="+encodeURIComponent(certificateChain[0].fingerprintSha256);
    }

    chrome.tabs.update(tabId, {url: url});
}

async function shouldValidateDomain(domain) {
    if (!await getConfig()) {
        logError("Config is not initialized");
        return false;
    }
    // Have to check before log, since we log the mapservers to loki and that brings circular dependency
    if (domain === REMOTE_LOKI_HOST) {
        return false;
    }

    const mapServers = await getConfig("mapservers");
    logInfo("Mapservers", {mapservers: mapServers});
    // ignore mapserver addresses since otherwise there would be a circular dependency which could not be resolved
    const notMapServer = mapServers.every(({ domain: d }) => getDomainNameFromURL(d) !== domain);
    return notMapServer;
}

function addTrustDecision(details, trustDecision) {
    // find document url of this request
    const url = typeof details.documentUrl === "undefined" ? details.url : details.documentUrl;
    const urlMap = mapGetMap(trustDecisions, details.tabId);
    const tiList = mapGetList(urlMap, url);
    urlMap.set(url, tiList.concat(trustDecision));
    trustDecisions.set(details.tabId, urlMap);
}

async function requestInfo(details) {
    const perfStart = performance.now();
    const startTimestamp = new Date();

    const domain = getDomainNameFromURL(details.url);
    if (!await shouldValidateDomain(domain)) {
        // cLog(details.requestId, "ignoring (no requestInfo): " + domain);
        return;
    }
    cLog(details.requestId, "requestInfo ["+trimString(details.url)+"]");
    logInfo("requestInfo ["+trimString(trimUrlToDomain(details.url))+"]", {requestId: details.requestId});

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
            cLog(details.requestId, "initiateFetchingPoliciesIfNecessary catch");
            logInfo("initiateFetchingPoliciesIfNecessary catch: " + JSON.stringify(error), {requestId: details.requestId});
            redirect(details, error);
            throw error;
        });
    }
    // cLog(details.requestId, "tracking request: "+JSON.stringify(details));
    logEntry.trackRequest(details.requestId);
}

async function getTlsCertificateChain(securityInfo) {
    const chain = securityInfo.certificates.map(c => ({pem: globalThis.btoa(String.fromCharCode(...c.rawDER)), fingerprintSha256: c.fingerprint.sha256, serial: c.serialNumber, isBuiltInRoot: c.isBuiltInRoot, subject: c.subject, issuer: c.issuer}));
    // Note: the string representation of the subject and issuer as presented by the browser may differ from the string representation of the golang library. Only use this information for output and not for making decisions.
    return chain;
}

async function checkInfo(details) {
    const onHeadersReceived = performance.now();
    const logEntry = getLogEntryForRequest(details.requestId);
    const domain = getDomainNameFromURL(details.url);
    if (!await shouldValidateDomain(domain)) {
        // cLog(details.requestId, "ignoring (no checkInfo): " + domain);
        return;
    }

    cLog(details.requestId, "checkInfo ["+trimString(details.url)+"]");
    logInfo("checkInfo ["+trimString(trimUrlToDomain(details.url))+"]", {requestId: details.requestId});
    
    if (logEntry === null && details.fromCache) {
        // ensure that if checkInfo is called multiple times for a single request, logEntry is ignored
        cLog(details.requestId, "skipping log entry for cached request: "+details);
        logInfo("skipping log entry for cached request: "+details, {requestId: details.requestId});
    }
    if (logEntry === null && !details.fromCache) {
        // ensure that if checkInfo is called multiple times for a single request, logEntry is ignored
        cLog(details.requestId, "no log entry for uncached request: "+details);
        logInfo("no log entry for uncached request: "+details, {requestId: details.requestId});
        throw new FpkiError(errorTypes.INTERNAL_ERROR);
    }   

    let remoteInfo = null;
    try {
        remoteInfo = await getSecurityInfoFromNativeApp(domain);
        logInfo("Received remote info: " + JSON.stringify(remoteInfo), {requestId: details.requestId});
        //! TODO getSecurityInfo works only in Firefox, not in any other browser
        // For use in other browsers we need to create a server that will handle this api request and call it from extension
        // const remoteInfo = await chrome.webRequest.getSecurityInfo(details.requestId, {
        //     certificateChain: true,
        //     rawDER: true
        // });
    } catch (error) {
        cLog(details.requestId, "Error during getSecurityInfo: " + error);
        logError("Error during getSecurityInfo: " + error, {requestId: details.requestId});
    }


    if (remoteInfo && remoteInfo.certificates === undefined) {
        cLog(details.requestId, "establishing non-secure http connection");
        logInfo("establishing non-secure http connection", {requestId: details.requestId});
        // TODO: could also implement protection against http downgrade
        return;
    }

    const certificateChain = await getTlsCertificateChain(remoteInfo);
    cLog(details.requestId, "certificate chain: "+JSON.stringify(certificateChain));
    logInfo("certificate chain: "+JSON.stringify(certificateChain), {requestId: details.requestId});
    if (logEntry !== null) {
        logEntry.certificateChainReceived(certificateChain);
    }

    let decision = "accept";
    try {
        // check if this certificate for this domain was accepted despite the F-PKI legacy (or policy) warning
        const certificateFingerprint = certificateChain[0].fingerprintSha256;
        if (mapGetSet(trustedCertificates, domain).has(certificateFingerprint)) {
            cLog(details.requestId, "skipping validation for domain ("+domain+") because of the trusted certificate: "+certificateFingerprint);
            logInfo("skipping validation for domain ("+domain+") because of the trusted certificate: "+certificateFingerprint, {requestId: details.requestId});
        } else {
            const policiesMap = new Map();
            const certificatesMap = new Map();
            for (const [index, mapserver] of config.get("mapservers").entries()) {
                if (index === config.get("mapserver-instances-queried")) {
                    break;
                }
                const fpkiRequest = new FpkiRequest(mapserver, domain, details.requestId);
                cLog(details.requestId, "await fpki request for ["+domain+", "+mapserver.identity+"]");
                logInfo("await fpki request for ["+domain+", "+mapserver.identity+"]", {requestId: details.requestId});
                const {policies, certificates, metrics} = await fpkiRequest.fetchPolicies();
                policiesMap.set(mapserver, policies);
                certificatesMap.set(mapserver, certificates);
                if (logEntry !== null) {
                    logEntry.fpkiResponse(mapserver, policies, certificates, metrics);
                }
                cLog(details.requestId, "await finished for fpki request for ["+domain+", "+mapserver.identity+"]");
                logInfo("await finished for fpki request for ["+domain+", "+mapserver.identity+"]", {requestId: details.requestId});
            }

            // remember if policy validations has been performed
            let policyChecksPerformed = false;

            if (globalThis.GOCACHEV2) {
                // check if have a cached trust decision for this domain+leaf certificate
                const key = domain + certificateChain[0].fingerprintSha256;
                var trustDecision = null;
                trustDecision = policyTrustDecisionCache.get(key);
                var currentTime = new Date();
                if (trustDecision === undefined || currentTime > trustDecision.validUntil) {
                    trustDecision = await policyValidateConnectionGo(certificateChain, domain);
                    if (trustDecision.policyChain.length > 0 && !trustDecision.domainExcluded) {
                        policyChecksPerformed = true;
                    }
                    policyTrustDecisionCache.set(key, trustDecision)

                }
                cLog(details.requestId, "trustDecision: "+JSON.stringify(trustDecision));
                logInfo("trustDecision: "+JSON.stringify(trustDecision), {requestId: details.requestId});
                if (!trustDecision.domainExcluded) {
                    addTrustDecision(details, trustDecision);
                    if (trustDecision.evaluationResult !== 1) {
                        throw new FpkiError(errorTypes.POLICY_MODE_VALIDATION_ERROR, getPolicyValidationErrorMessageGo(trustDecision));
                    }
                }
            } else {
                // check each policy and throw an error if one of the verifications fails
                policiesMap.forEach((p, m) => {
                    // cLog(details.requestId, "starting policy verification for ["+domain+", "+m.identity+"] with policies: "+printMap(p));

                    const { trustDecision } = policyValidateConnection(certificateChain, config, domain, p, m);
                    addTrustDecision(details, trustDecision);

                    if (hasApplicablePolicy(trustDecision)) {
                        policyChecksPerformed = true;
                    }
                    if (hasFailedValidations(trustDecision)) {
                        throw new FpkiError(errorTypes.POLICY_MODE_VALIDATION_ERROR, getShortErrorMessages(trustDecision)[0]);
                    }
                });
            }

            // don't perform legacy validation if policy validation has already taken place
            if (!policyChecksPerformed) {
                if(globalThis.GOCACHEV2) {
                    // check if have a cached trust decision for this domain+leaf certificate
                    const key = domain+certificateChain[0].fingerprintSha256;
                    var trustDecision = null;
                    trustDecision = legacyTrustDecisionCache.get(key);
                    var currentTime = new Date();
                    if (trustDecision === undefined || currentTime > trustDecision.validUntil) {
                        trustDecision = legacyValidateConnectionGo(certificateChain, domain);
                        legacyTrustDecisionCache.set(key, trustDecision)

                    }
                    addTrustDecision(details, trustDecision);
                    if (trustDecision.evaluationResult !== 1) {
                        throw new FpkiError(errorTypes.LEGACY_MODE_VALIDATION_ERROR, getLegacyValidationErrorMessageGo(trustDecision));
                    }
                } else {
                    // check each policy and throw an error if one of the verifications fails
                    certificatesMap.forEach((c, m) => {
                        cLog(details.requestId, "starting legacy verification for ["+domain+", "+m.identity+"] with policies: "+printMap(c));
                        logInfo("starting legacy verification for ["+domain+", "+m.identity+"] with policies: "+printMap(c), {requestId: details.requestId});
                        const {trustDecision} = legacyValidateConnection(certificateChain, config, domain, c, m);
                        addTrustDecision(details, trustDecision);
                        if (hasFailedValidations(trustDecision)) {
                            throw new FpkiError(errorTypes.LEGACY_MODE_VALIDATION_ERROR, getShortErrorMessages(trustDecision)[0]);
                        }
                    });
                }
            }

            // TODO: legacy (i.e., certificate-based) validation

            // TODO: check connection for all policies and continue if at least config.get("mapserver-quorum") responses exist

            // TODO: what happens if a response is invalid? we should definitely log it, but we could ignore it if enough other valid responses exist

            cLog(details.requestId, "verification succeeded! ["+details.url+"]");
            logInfo("verification succeeded! ["+trimUrlToDomain(details.url)+"]", {requestId: details.requestId});
        }
    } catch (error) {
        // TODO: in case that an exception was already thrown in requestInfo, then the redirection occurs twice (but this is not an issue since they both redirect to the same error url)
        decision = "reject: "+error
        redirect(details, error, certificateChain);
        throw error;
    } finally {
        if (logEntry !== null) {
            const onHeadersReceivedFinished = performance.now();
            logEntry.validationFinished(decision, onHeadersReceived, onHeadersReceivedFinished);
            logEntry.finalizeLogEntry(details.requestId);
        }
    }
}


async function getSecurityInfoFromNativeApp(domain) {
    return new Promise((resolve, reject) => {
        try {
            const port = chrome.runtime.connectNative("unibonn.netsec.fpki.extension");
            port.onMessage.addListener((response) => {
                if (response.error) {
                    reject(response.error)
                } else {
                    resolve(response.securityInfo)
                }
            });
            port.onDisconnect.addListener(() => {
                reject(new Error("Failed to connect to native app"));
            });
            port.postMessage({type: 'getSecurityInfo', domain: domain});
        }
        catch (e) {
            logError("Error during getSecurityInfoFromNativeApp: " + e)
            reject(e);
        }
    })
}

async function onCompleted(details) {
    const onCompleted = performance.now();
    const domain = getDomainNameFromURL(details.url);
    if (!await shouldValidateDomain(domain)) {
        // cLog(details.requestId, "ignoring (no requestInfo): " + domain);
        return;
    }
    cLog(details.requestId, "onCompleted ["+trimString(details.url)+"]");
    logInfo("onCompleted ["+trimString(trimUrlToDomain(details.url))+"]", {requestId: details.requestId});

    const logEntry = getLogEntryForRequest(details.requestId);
    if (logEntry !== null) {
        cLog(details.requestId, "validation skipped (invoked onCompleted without onHeadersReceived)");
        logInfo("validation skipped (invoked onCompleted without onHeadersReceived)", {requestId: details.requestId});
        logEntry.validationSkipped(onCompleted);
        logEntry.finalizeLogEntry(details.requestId);
    }
    if (config.get("send-log-entries-via-event") && details.type === "main_frame") {
        // uncomment to communicate log entries with puppeteer instance
        // browser.tabs.executeScript(details.tabId, { file: "../content/sendLogEntries.js" })
    }
}