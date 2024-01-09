import {download, clone} from "./helper.js"
import {defaultConfig} from "./default_config.js"

/*
    Original Live Config Object is maintained by the background script.
    Pages can request the current state of the config via 'requestConfig' msg
*/
export let config = null;  // Map Object

// function defaultConfig() {
//     let c = new Map();
//     // TODO: remove duplicate local mapserver (only used for testing)
//     // use 127.0.0.11 instead of localhost to distinguish the second test server from the first one (although it is the same instance)
//     // also, using 127.0.0.11 ensures that the mapserver IPs do not clash with the local test webpage at 127.0.0.1
//     c.set("mapservers-old", [
//         // {"identity": "local-mapserver", "domain": "http://localhost:8080", "querytype": "lfpki-http-get"},
//         {"identity": "ETH-mapserver-top-100k", "domain": "http://129.132.55.210:8080", "querytype": "lfpki-http-get"}
//     ]);
//     c.set("mapservers", [
//         {"identity": "local-mapserver", "domain": "http://127.0.0.1:8443", "querytype": "lfpki-http-get", "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArrrQ5MN4mdcp5XouqmcmPG489eRtbkIn9elKOCDLgpA9OFASKM26Vskm0jwR9unrVE8NXXdRbotQfVpL7iAPGOPfoSglBXKmiAdmRG0idw6+xRlpffgHE3CDhNnz1tpVXBTE+U84f48v+sVd1gnK4oA/uT7X7D6vO5cHK1M9rmpo+SiKlcYSHvF19/qgiwF9cc1z3ug6M4SciqEbUNdW1R3BSW+9ulTZluT4Hbml4C8hkktN9zlHUpWdHzH1NlcRqzObBp7ZvB/OrKh8iA0WBXLXNzlBdB9EXSHjqJcI/sKn0Zf/5RO9QYT8wjDDbj8H+4+/wRd2q8Y10yQomIy6WQIDAQAB"},
//     ]);
//     // cache timeout in ms
//     c.set("cache-timeout", 60*60*1000);
//     // max amount of time in ms that a connection setup takes. Used to ensure that a cached policy that is valid at the onBeforeRequest event is still valid when the onHeadersReceived event fires.
//     c.set("max-connection-setup-time", 1000);
//     // timeout for fetching a proof from a mapserver in ms
//     c.set("proof-fetch-timeout", 10000);
//     // max number of attempted fetch operations before aborting
//     c.set("proof-fetch-max-tries", 3);
//     // quorum of trusted map servers necessary to accept their result
//     c.set("mapserver-quorum", 1);
//     // number of mapservers queried per validated domain (currently always choosing the first n entries in the mapserver list)
//     c.set("mapserver-instances-queried", 1);
//     // send the log entries as a custom event after fetching a webpage (used to debug/measure the extension)
//     c.set("send-log-entries-via-event", true);
//     // enable parsing X.509 certificates using web assembly (golang)
//     c.set("wasm-certificate-parsing", false);
//     // enable caching X.509 certificates and legacy validation using web assembly (golang)
//     c.set("wasm-certificate-caching", true);

//     c.set("ca-sets", (()=>{
//         const caSet = new Map();
//         // note that this is simply a subset of all US CAs for testing purposes
//         caSet.set("US CA", ["CN=GTS CA 1C3,O=Google Trust Services LLC,C=US",
//                             "CN=GTS Root R1,O=Google Trust Services LLC,C=US",
//                             "CN=Amazon,OU=Server CA 1B,O=Amazon,C=US",
//                             "CN=Amazon Root CA 1,O=Amazon,C=US",
//                             "CN=DigiCert Global CA G2,O=DigiCert Inc,C=US",
//                             "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US"]);
//         // don't include the currently used root CA for testing purposes: "CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US"
//         caSet.set("Microsoft CA",
//                   ["CN=Baltimore CyberTrust Root,OU=CyberTrust,O=Baltimore,C=IE",
//                    "CN=DigiCert Global Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US"]);
//         return caSet;
//     })());
//     // the default level of a root certificate is 0
//     // CAs with higher levels take precedence over CAs with lower levels
//     c.set("legacy-trust-preference", (()=>{
//         const tp = new Map();
//         tp.set("microsoft.com", [{caSet: "Microsoft CA", level: 1}]);
//         tp.set("bing.com", [{caSet: "Microsoft CA", level: 1}]);
//         return tp;
//     })());
//     // the default level of a root certificate is 0
//     // CAs with higher levels take precedence over CAs with lower levels
//     c.set("policy-trust-preference", (()=>{
//         const tp = new Map();
//         tp.set("*", [{pca: "pca", level: 1}]);
//         return tp;
//     })());
//     c.set("root-pcas", (()=>{
//         const rootPcas = new Map();
//         rootPcas.set("pca", "local PCA for testing purposes");
//         return rootPcas;
//     })());
//     c.set("root-cas", (()=>{
//         // TODO (cyrill): change this configuration to take the complete subject name into accound (not only CN)
//         const rootCas = new Map();
//         rootCas.set("GTS CA 1C3", "description: ...");
//         rootCas.set("DigiCert Global Root CA", "description: ...");
//         rootCas.set("TrustAsia TLS RSA CA", "description: ...");
//         rootCas.set("DigiCert SHA2 Secure Server CA", "description: ...");
//         rootCas.set("DigiCert Secure Site CN CA G3", "description: ...");
//         rootCas.set("GlobalSign Organization Validation CA - SHA256 - G2", "description: ...");
//         rootCas.set("DigiCert TLS Hybrid ECC SHA384 2020 CA1", "description: ...");
//         return rootCas;
//     })());
//     return c;

/*
    Config Formats:

    1. Old Config (Map)
    2. New Config (JSON + Map for preferences), used by config_page.js
*/

/**
 * Convert new config format to previous format for compatibility.
 * 
 * In: new format config json+maps  
 * Out: old format map config.
 */
export function toOldConfig(pass_json_config) {

    let json_config = clone(pass_json_config);
    
    console.log("NEW CONFIG FORMAT:");
    console.log(pass_json_config);
    // Convert ca-sets settings to old format
    let ca_sets_old = {};
    let ca_sets_descriptions = {};
    Object.entries(json_config['ca-sets']).forEach(caset => {
        const [set_name, set_value] = caset;
        ca_sets_old[set_name] = set_value['cas'];
        ca_sets_descriptions[set_name] = set_value['description'];
    })
    // Convert legacy-trust-preference settings to old format
    let lts_old = {}
    Object.entries(json_config['legacy-trust-preference']).forEach(elem => {
        const [domain_name, preferences] = elem;
        lts_old[domain_name] = [];

        console.log("PREFS:")
        console.log(elem);

        preferences.forEach((trustlevel, caset) => {
            //const [caset, trustlevel] = elem;
            let new_pref = {
                'caSet': caset,
                'level': json_config['trust-levels'][trustlevel]
            }
            lts_old[domain_name].push(new_pref);
        });
    });

    // Save reversed trust level mappings for easier re-conversion
    let trust_levels_rev = {};
    Object.entries(json_config['trust-levels']).forEach(elem => {
        const [level_name, level] = elem;
        console.log(level_name + ": " + level);
        trust_levels_rev[level] = level_name;
    });

    json_config['ca-sets'] = ca_sets_old;
    json_config['legacy-trust-preference'] = lts_old;
    json_config['trust-levels-rev'] = trust_levels_rev;
    // no information loss on conversion
    json_config['ca-sets-descriptions'] = ca_sets_descriptions;

    json_config = convertJSONConfigToMap(JSON.stringify(json_config));

    console.log("OLD CONFIG FORMAT:");
    console.log(json_config);

    return json_config;
}


/**
 * Convert previous config format to new format for compatibility.
 * 
 * In: old config map format  
 * Out: new config json+map format
 */
export function toNewConfig(pass_json_config) {
    let json_config = JSON.parse(exportConfigToJSON(pass_json_config));

    console.log("OLD CONFIG FORMAT:");
    console.log(pass_json_config);

    // Convert ca-sets settings to new format
    let ca_sets_new = {};
    Object.entries(json_config['ca-sets']).forEach(caset => {
        const [set_name, ca_list] = caset;
        ca_sets_new[set_name] = {
            description: json_config['ca-sets-descriptions'][set_name],
            cas: ca_list
        }
    });

    // Convert legacy-trust-preference settings to new format
    let lts_new = {}
    Object.entries(json_config['legacy-trust-preference']).forEach(elem => {
        const [domain_name, preferences] = elem;
        lts_new[domain_name] = new Map();
        // Preferences sind hier in einem array, also (hoffentlich) schon in
        // richtiger priorisierungs-reihenfolge gespeichert.
        //
        // Reihenfolge von maps geht nach reihenfolge der insertions. sollte
        // also passen..
        console.log("test:")
            console.log(elem);
        preferences.forEach(pref => {
            
            lts_new[domain_name].set(pref['caSet'], json_config['trust-levels-rev'][pref['level']]);
        });
    });

    json_config['ca-sets'] = ca_sets_new;
    json_config['legacy-trust-preference'] = lts_new;

    console.log("NEW CONFIG FORMAT:");
    console.log(json_config);

    return json_config;
}


/**
 * Returns config and initializes it first if neccessary
 */
export function getConfig() {
    console.log("getConfig: config is " + config);
    if (config === null) {
        initializeConfig();
        return config;
    } else {
        return config;
    }
}


/**
 * Loads config from local storage (across browser sessions) OR 
 * initializes live config object with default config settings
 */
function initializeConfig() {
    try {
        console.log("JUST WHY");
        console.log(defaultConfig);
        let c = localStorage.getItem("config");
        if (c === null) {
            console.log("initializing using default config");
            importConfigFromJSON(JSON.stringify(defaultConfig));
        } else {
            console.log("initialize using stored config");
            importConfigFromJSON(c);
        }
        saveConfig();

        console.log("INITIALIZED:");
        console.log(config);
    } catch (e) {
        console.log(e);
    }
}


/**
 * Saves old config format. unchanged
 */
export function saveConfig() {
    /*
        Makes live config object persistent across browser sessions using the 
        local storage of the browser
    */
    console.log("saving config: ");
    console.log(config);
    localStorage.setItem("config", exportConfigToJSON(config));

    //console.log("savin new format config:\n" + new_format_config);
    //localStorage.setItem("new_format_config", new_format_config);  // save as string
}


/**
 * Returns a JSON string of the passed config Map object (old format)
 */
export function exportConfigToJSON(configMap, indent=false) {
    let jsonConfig = new Map();
    console.log("ACHTUNG\n" + configMap);
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


/**
 * 
 * @returns Config Object as JSON object
 */
export function getJSONConfig() {JSON.parse(JSON.stringify(json_object))
    return JSON.parse(exportConfigToJSON(config));
}


/**
 * Converts the JSON string to a Map object and replaces the live config object
 */
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


/**
 * importConfigFromJSON, but returns instead of setting the config.
 * 
 * In: JSON string  
 * Out: Old Config Map Object
 */
export function convertJSONConfigToMap(jsonConfig) {
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

    return c;
}


/**
 * Lets user export config in shareable json format.
 */
export function downloadConfig() {
    download("config.json", exportConfigToJSON(config, true));
}


/**
 * Reset config to default settings
 */
export function resetConfig() {
    try {
        console.log("CALLED: resetConfig()\n");

        importConfigFromJSON(JSON.stringify(defaultConfig));
        saveConfig();
    } catch (e) {
        console.log(e);
    }
}
