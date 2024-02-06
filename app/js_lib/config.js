import {download} from "./helper.js"

export var config = new Map();

function defaultConfig() {
    let c = new Map();
    // TODO: remove duplicate local mapserver (only used for testing)
    // use 127.0.0.11 instead of localhost to distinguish the second test server from the first one (although it is the same instance)
    // also, using 127.0.0.11 ensures that the mapserver IPs do not clash with the local test webpage at 127.0.0.1
    c.set("mapservers-old", [
        // {"identity": "local-mapserver", "domain": "http://localhost:8080", "querytype": "lfpki-http-get"},
        {"identity": "ETH-mapserver-top-100k", "domain": "http://129.132.55.210:8080", "querytype": "lfpki-http-get"}
    ]);
    c.set("mapservers", [
        {"identity": "local-mapserver", "domain": "http://127.0.0.1:8443", "querytype": "lfpki-http-get", "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArrrQ5MN4mdcp5XouqmcmPG489eRtbkIn9elKOCDLgpA9OFASKM26Vskm0jwR9unrVE8NXXdRbotQfVpL7iAPGOPfoSglBXKmiAdmRG0idw6+xRlpffgHE3CDhNnz1tpVXBTE+U84f48v+sVd1gnK4oA/uT7X7D6vO5cHK1M9rmpo+SiKlcYSHvF19/qgiwF9cc1z3ug6M4SciqEbUNdW1R3BSW+9ulTZluT4Hbml4C8hkktN9zlHUpWdHzH1NlcRqzObBp7ZvB/OrKh8iA0WBXLXNzlBdB9EXSHjqJcI/sKn0Zf/5RO9QYT8wjDDbj8H+4+/wRd2q8Y10yQomIy6WQIDAQAB"},
    ]);
    // cache timeout in ms
    c.set("cache-timeout", 60*60*1000);
    // max amount of time in ms that a connection setup takes. Used to ensure that a cached policy that is valid at the onBeforeRequest event is still valid when the onHeadersReceived event fires.
    c.set("max-connection-setup-time", 1000);
    // timeout for fetching a proof from a mapserver in ms
    c.set("proof-fetch-timeout", 10000);
    // max number of attempted fetch operations before aborting
    c.set("proof-fetch-max-tries", 3);
    // quorum of trusted map servers necessary to accept their result
    c.set("mapserver-quorum", 1);
    // number of mapservers queried per validated domain (currently always choosing the first n entries in the mapserver list)
    c.set("mapserver-instances-queried", 1);
    // send the log entries as a custom event after fetching a webpage (used to debug/measure the extension)
    c.set("send-log-entries-via-event", true);
    // enable parsing X.509 certificates using web assembly (golang)
    c.set("wasm-certificate-parsing", false);
    // enable caching X.509 certificates and legacy validation using web assembly (golang)
    c.set("wasm-certificate-caching", true);

    c.set("ca-sets", (()=>{
        const caSet = new Map();
        // note that this is simply a subset of all US CAs for testing purposes
        caSet.set("US CA", ["CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
                            "CN=GTS Root R1,O=Google Trust Services LLC,C=US",
                            "CN=Amazon,OU=Server CA 1B,O=Amazon,C=US",
                            "CN=Amazon Root CA 1,O=Amazon,C=US",
                            "CN=DigiCert Global CA G2,O=DigiCert Inc,C=US",
                            "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US"]);
        // don't include the currently used root CA for testing purposes: "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US"
        caSet.set("Microsoft CA",
                  ["CN=Baltimore CyberTrust Root,OU=CyberTrust,O=Baltimore,C=IE",
                   "CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US"]);
        return caSet;
    })());
    // the default level of a root certificate is 0
    // CAs with higher levels take precedence over CAs with lower levels
    c.set("legacy-trust-preference", (()=>{
        const tp = new Map();
        tp.set("microsoft.com", [{caSet: "Microsoft CA", level: 1}]);
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
