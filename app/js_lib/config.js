import {download} from "./helper.js"

export var config = new Map();

function defaultConfig() {
    let c = new Map();
    // TODO: remove duplicate local mapserver (only used for testing)
    // use 127.0.0.11 instead of localhost to distinguish the second test server from the first one (although it is the same instance)
    // also, using 127.0.0.11 ensures that the mapserver IPs do not clash with the local test webpage at 127.0.0.1
    c.set("mapservers", [
        // {"identity": "local-mapserver", "domain": "http://localhost:8080", "querytype": "lfpki-http-get"},
        {"identity": "ETH-mapserver-top-100k", "domain": "http://129.132.55.210:8080", "querytype": "lfpki-http-get"}
    ]);
    // cache timeout in ms
    c.set("cache-timeout", 10000);
    // max amount of time in ms that a connection setup takes. Used to ensure that a cached policy that is valid at the onBeforeRequest event is still valid when the onHeadersReceived event fires.
    c.set("max-connection-setup-time", 1000);
    // timeout for fetching a proof from a mapserver in ms
    c.set("proof-fetch-timeout", 10000);
    // max number of attempted fetch operations before aborting
    c.set("proof-fetch-max-tries", 3);
    // quorum of trusted map servers necessary to accept their result
    c.set("mapserver-quorum", 2);
    // number of mapservers queried per validated domain (currently always choosing the first n entries in the mapserver list)
    c.set("mapserver-instances-queried", 1);
    c.set("ca-sets", (()=>{
        const caSet = new Map();
        caSet.set("US CA", ["CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
                            "CN=GTS Root R1,O=Google Trust Services LLC,C=US",
                            "CN=Amazon,OU=Server CA 1B,O=Amazon,C=US",
                            "CN=Amazon Root CA 1,O=Amazon,C=US",
                            "CN=DigiCert Global CA G2,O=DigiCert Inc,C=US",
                            "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US"]);
        // don't include "C=US,O=Microsoft Corporation,CN=Microsoft RSA TLS CA 02"
        caSet.set("Microsoft CA", ["CN=Microsoft RSA Root Certificate Authority 2017,O=Microsoft Corporation,C=US",
                                   "CN=Microsoft ECC Root Certificate Authority 2017,O=Microsoft Corporation,C=US",
                                   "CN=Microsoft RSA TLS CA 01,O=Microsoft Corporation,C=US"]);
        return caSet;
    })());
    // the default level of a root certificate is 0
    // CAs with higher levels take precedence over CAs with lower levels
    c.set("legacy-trust-preference", (()=>{
        const tp = new Map();
        tp.set("google.com", [{caSet: "US CA", level: 1}]);
        tp.set("qq.com", [{caSet: "US CA", level: 1}]);
        tp.set("azure.microsoft.com", [{caSet: "Microsoft CA", level: 1}]);
        tp.set("bing.com", [{caSet: "Microsoft CA", level: 1}]);
        return tp;
    })());
    // the default level of a root certificate is 0
    // CAs with higher levels take precedence over CAs with lower levels
    c.set("policy-trust-preference", (()=>{
        const tp = new Map();
        tp.set("*", [{pca: "pca", level: 1}]);
        return tp;
    })());
    c.set("root-pcas", (()=>{
        const rootPcas = new Map();
        rootPcas.set("pca", "local PCA for testing purposes");
        return rootPcas;
    })());
    c.set("root-cas", (()=>{
        // TODO (cyrill): change this configuration to take the complete subject name into accound (not only CN)
        const rootCas = new Map();
        rootCas.set("GTS CA 1C3", "description: ...");
        rootCas.set("DigiCert Global Root CA", "description: ...");
        rootCas.set("TrustAsia TLS RSA CA", "description: ...");
        rootCas.set("DigiCert SHA2 Secure Server CA", "description: ...");
        rootCas.set("DigiCert Secure Site CN CA G3", "description: ...");
        rootCas.set("GlobalSign Organization Validation CA - SHA256 - G2", "description: ...");
        rootCas.set("DigiCert TLS Hybrid ECC SHA384 2020 CA1", "description: ...");
        return rootCas;
    })());
    return c;
}

// either reads the config from storage or uses the default config
export function initializeConfig() {
    let c = loadConfig();
    if (c === null) {
        console.log("initializing using default config");
        c = defaultConfig();
    } else {
        console.log("initialize using stored config");
    }
    config = c;
}

function loadConfig() {
    return localStorage.getItem("config");
}

export function saveConfig() {
    console.log("saving config...");
    localStorage.setItem("config", exportConfigToJSON(config));
}

export function exportConfigToJSON(configMap, indent=false) {
    let jsonConfig = new Map();
    configMap.forEach((value, key) => {
        if (["ca-sets", "legacy-trust-preference", "policy-trust-preference", "root-pcas", "root-cas"].includes(key)) {
            jsonConfig.set(key, Object.fromEntries(value));
        } else {
            jsonConfig.set(key, value);
        }
        // could try to implement using the datatype: e.g., if (typeof value === "map")
    });
    if (indent) {
        return JSON.stringify(Object.fromEntries(jsonConfig), null, 4);
    } else {
        return JSON.stringify(Object.fromEntries(jsonConfig));
    }
}

var oldConfig;
export function importConfigFromJSON(jsonConfig) {
    const c = new Map();
    const parsedMap = new Map(Object.entries(JSON.parse(jsonConfig)));
    // convert necessary fields to Map type
    parsedMap.forEach((value, key) => {
        if (["ca-sets", "legacy-trust-preference", "policy-trust-preference", "root-pcas", "root-cas"].includes(key)) {
            c.set(key, new Map(Object.entries(value)));
        } else {
            c.set(key, value);
        }
    });
    config = c;
}

export function downloadConfig() {
    download("config.json", exportConfigToJSON(config, true));
}

export function resetConfig() {
    config = defaultConfig();
    saveConfig();
}
