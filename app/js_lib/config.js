import {download, clone} from "./helper.js"
import {defaultConfig} from "./default_config.js"

// config keys for which the values are represented as Maps
const configMapKeys = ["ca-sets", "legacy-trust-preference", "policy-ca-sets", "policy-trust-preference", "policy-cas", "trust-levels", "trust-levels-rev"]

/*
    Original Live Config Object is maintained by the background script.
    Pages can request the current state of the config via 'requestConfig' msg
*/
export let config = null;  // Map Object

/*
    Config Formats:

    1. Default config format (Map of Maps)
    2. js object config format used by config_page.js and to convert from/to JSON
*/

/**
 * Returns config and initializes it first if neccessary
 */
export function getConfig(key = "") {
    if (config === null) {
        initializeConfig();
    }
    if (key === "") {
        return config;
    } else {
        return config.get(key);
    }
}

/**
 * Manually Set a new config value
 */
export function setConfig(newConfig) {
    config = newConfig;
    console.log("setting config to:");
    console.log(config);
}

/**
 * Loads config from local storage (across browser sessions) OR 
 * initializes live config object with default config settings
 */
export function initializeConfig() {
    let storedConfig = localStorage.getItem("config");
    if (storedConfig === null) {
        console.log("initializing using default config:");
        config = convertObjectsToMaps(defaultConfig);
    } else {
        console.log("initializing using stored config:");
        config = importConfigFromJSON(storedConfig);
    }
    console.log(config);
}


/**
 * Saves config
 */
export function saveConfig() {
    /*
        Makes live config object persistent across browser sessions using the 
        local storage of the browser
    */
    console.log("saving config:");
    console.log(config);
    localStorage.setItem("config", exportConfigToJSON(config));
}


/**
 * Returns a JSON string of the passed config
 */
export function exportConfigToJSON(mapsConfig, indent=false) {
    const objectsConfig = convertMapsToObjects(mapsConfig);
    if (indent) {
        return JSON.stringify(objectsConfig, null, 4);
    } else {
        return JSON.stringify(objectsConfig);
    }
}

/**
 * imports a config in a JSON representation
 */
function importConfigFromJSON(jsonConfig) {
    return convertObjectsToMaps(JSON.parse(jsonConfig))
}

/**
 * Converts config in the form of a js object (used for config page and to import from JSON) to a Map of Maps
 * 
 * In: config consisting of js objects
 * Out: config consisting of Maps
 */
export function convertObjectsToMaps(jsonConfig) {
    const c = new Map();
    const parsedMap = new Map(Object.entries(jsonConfig));
    parsedMap.forEach((value, key) => {
        if (configMapKeys.includes(key)) {
            c.set(key, new Map(Object.entries(value)));
        } else {
            c.set(key, value);
        }
    });
    return c;
}

/**
 * Converts config consisting of a Map of Maps to a js object (used for the config page and to convert to JSON)
 * 
 * In: config consisting of Maps
 * Out: config consisting of js objects
 */
export function convertMapsToObjects(jsonConfig) {
    let objectsConfig = {};
    jsonConfig.forEach((value, key) => {
        if (configMapKeys.includes(key)) {
            objectsConfig[key] = Object.fromEntries(value);
        } else {
            objectsConfig[key] = value;
        }
    });
    return objectsConfig;
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
    config = convertObjectsToMaps(defaultConfig);
    console.log("reseting config to:");
    console.log(config);
}
