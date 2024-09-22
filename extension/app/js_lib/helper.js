// Map helper functions

/**
 * Get the value for specified key in map OR return a new empty list.
 * 
 */
export function mapGetList(map, key) {
    return map.get(key) || [];
};

/**
 * Get the value for specified key in map OR return a new empty Map.
 * 
 */
export function mapGetMap(map, key) {
    return map.get(key) || new Map();
};

/**
 * Get the value for specified key in map OR return a new empty Set.
 * 
 */
export function mapGetSet(map, key) {
    return map.get(key) || new Set();
};

export function printMap(m) {
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


// Logging

export function cLog(requestId, ...args) {
    console.log("rid=["+requestId+"]: "+args.reduce((a, b) => a+", "+b));
}


// HTTP GET

export function getUrlParameter(param) {
    // const queryString = window.location.search;
    const queryString = new URL(document.URL).search;
    const urlParams = new URLSearchParams(queryString);
    return urlParams.get(param);
}

export function download(filename, text) {
  var element = document.createElement('a');
  element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
  element.setAttribute('download', filename);

  element.style.display = 'none';
  document.body.appendChild(element);

  element.click();

  document.body.removeChild(element);
}


// Hashing

export async function sha256Hash_arrayBuffer_1(input) {
    let output = await globalThis.crypto.subtle.digest('SHA-256', input);
    return output;
}

export async function sha256Hash_1(input) {
    let output = await globalThis.crypto.subtle.digest('SHA-256', stringToArrayBuf(input))
    return output
}

export async function sha256Hash_2(input1, input2) {
    let output = await globalThis.crypto.subtle.digest('SHA-256', appendTwoArrayBuf(input1, input2))
    return output
}

export async function sha256Hash_3(input1, input2, input3) {
    let output = await globalThis.crypto.subtle.digest('SHA-256', appendThreeArrayBuf(input1, input2, input3))
    return output
}

export async function hashPemCertificateWithoutHeader(c) {
    return new Uint8Array(await sha256Hash_arrayBuffer_1(stringToArrayBufNoEncoding(globalThis.atob(c))));
}


// Conversion

export function convertArrayBufferToBase64(input) {
    const inputAsString = String.fromCharCode(...new Uint8Array(input));
    return globalThis.btoa(inputAsString);
}

function encode_utf8(s) {
    return unescape(encodeURIComponent(s));
}

export function stringToArrayBuf(str) {
    var s = encode_utf8(str)
    var buf = new ArrayBuffer(s.length);
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = s.length; i < strLen; i++) {
        bufView[i] = s.charCodeAt(i)
    }
    return buf;
}

export function stringToArrayBufNoEncoding(str) {
    var buf = new ArrayBuffer(str.length);
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i)
    }
    return buf;
}

// append two array buffer; for hashing
function appendTwoArrayBuf(str1, str2) {
    let str1View = new Uint8Array(str1)
    let str2View = new Uint8Array(str2)

    var buf = new ArrayBuffer(str1View.length + str2View.length);
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = str1View.length; i < strLen; i++) {
        bufView[i] = str1View[i];
    }
    for (var i = 0, strLen = str2View.length; i < strLen; i++) {
        bufView[i + str1View.length] = str2View[i];
    }
    return buf;
}

// append three array buffer; for hashing
function appendThreeArrayBuf(str1, str2, str3) {
    let str1View = new Uint8Array(str1)
    let str2View = new Uint8Array(str2)
    let str3View = new Uint8Array(str3)

    var buf = new ArrayBuffer(str1View.length + str2View.length + str3View.length);
    var bufView = new Uint8Array(buf);
    for (var i = 0, strLen = str1View.length; i < strLen; i++) {
        bufView[i] = str1View[i];
    }
    for (var i = 0, strLen = str2View.length; i < strLen; i++) {
        bufView[i + str1View.length] = str2View[i];
    }
    for (var i = 0, strLen = str3View.length; i < strLen; i++) {
        bufView[i + str2View.length + str1View.length] = str3View[i];
    }
    return buf;
}

export function arrayToHexString(arrayValue, separator = "") {
    return Array.from(arrayValue, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join(separator).toUpperCase();
}

export function intToHexString(intValue, separator = "") {
    let hex = intValue.toString(16).toUpperCase();
    if (hex.length % 2) { hex = '0' + hex; }
    const components = []
    for (let i = 0; i < hex.length / 2; i++) {
        components.push(hex.substring(i * 2, (i + 1) * 2));
    }
    return components.join(separator);
}


export function base64ToHex(base64Value, separator = "") {
    const raw = atob(base64Value);
    let result = '';
    for (let i = 0; i < raw.length; i++) {
        const hex = raw.charCodeAt(i).toString(16);
        if (i > 0) {
            result += separator;
        }
        result += (hex.length === 2 ? hex : '0' + hex);
    }
    return result.toUpperCase();
}

export function trimString(string, maxLength = 100) {
    const trimmedString = string.length > maxLength ?
        string.substring(0, maxLength - 3) + "..." :
        string;
    return trimmedString;
}

/**
 * Deep copy of new_format_config
 */
export function clone(json_object) {
    const cloned_config = JSON.parse(JSON.stringify(json_object));

    Object.entries(cloned_config['legacy-trust-preference']).forEach(elem => {
        const [domain_name, _] = elem;
        cloned_config['legacy-trust-preference'][domain_name] = new Map(
            // trying to deep copy maps
            JSON.parse(JSON.stringify(Array.from(json_object['legacy-trust-preference'][domain_name])))
        );
    });

    return cloned_config;
}

export function trimUrlToDomain(url) {
    const regex = /\/\/([^\/,\s]+\.[^\/,\s]+?)(?=\/|,|\s|$|\?|#)/g

    const match = regex.exec(url);

    return match ? match[1] : url;
}
