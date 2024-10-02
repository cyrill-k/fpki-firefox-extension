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
export async function getConfig(key = "") {
    if (config === null) {
        await initializeConfig();
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
export async function setConfig(newConfig) {
    console.log("Setting config to:", newConfig);
    if (isJSONString(newConfig)) {
        console.log("Setting config from JSON string");
        config = convertObjectsToMaps(JSON.parse(newConfig));
        return;
    } else if (isMap(newConfig)) {
        console.log("Setting config from Map");
        config = newConfig;
        await saveConfig();
        return;
    } else if (typeof newConfig === 'object') {
        console.log("config is json object");
        config = convertObjectsToMaps(newConfig);
        await saveConfig();
        return;
    }
    console.log('Error while setting config, received config: ', newConfig)
}

/**
 * Loads config from local storage (across browser sessions) OR 
 * initializes live config object with default config settings
 */
export async function initializeConfig() {
    if (config !== null) {
        return;
    }

    const storedConfig = await chrome.storage.local.get(["config"]);
    console.log({storedConfig})
    if (storedConfig.config) {
        console.log("initializing config using storage:", storedConfig.config);
        config = importConfigFromJSON(storedConfig.config);
    } else {
        console.log("initializing config using default settings:", defaultConfig);
        config = convertObjectsToMaps(defaultConfig);
    }
    await saveConfig();
}

/**
 * Saves config
 */
export async function saveConfig() {
    /*
        Makes live config object persistent across browser sessions using the 
        local storage of the browser
    */
    console.log("saving config:", config);
    await chrome.storage.local.set({config: exportConfigToJSON(config)});
}


export async function getConfigRequest() {
    const config = await getConfig();
    const jsonConfig = convertMapsToObjects(config);
    return jsonConfig;
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

export function convertMapsToSerializableObject(map) {
    const obj = {};
    for (let [key, value] of map.entries()) {
        if (value instanceof Map) {
            obj[key] = convertMapsToSerializableObject(value);
        } else {
            obj[key] = value;
        }
    }
    return obj;
}

export function serializableObjectToMaps(obj) {
    const map = new Map();
    for (let key in obj) {
        if (obj[key] && typeof obj[key] === 'object' && !Array.isArray(obj[key])) {
            map.set(key, serializableObjectToMaps(obj[key]));
        } else {
            map.set(key, obj[key]);
        }
    }
    return map;
}


function isJSONString(str) {
    if (typeof str !== 'string') {
        return false;
    }
    try {
        JSON.parse(str);
        return true;
    } catch (e) {
        return false;
    }
}

function isMap(val) {
    return val instanceof Map;
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
export async function resetConfig() {
    config = convertObjectsToMaps(defaultConfig);
    console.log("reseting config to:");
    console.log(config);
    await saveConfig();
}
