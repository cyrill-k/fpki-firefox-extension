export function mapGetList(map, key) {
    return map.get(key) || [];
};

export function mapGetMap(map, key) {
    return map.get(key) || new Map();
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

export function cLog(requestId, ...args) {
    console.log("rid=["+requestId+"]: "+args.reduce((a, b) => a+", "+b));
}

export function getUrlParameter(param) {
    // const queryString = window.location.search;
    const queryString = new URL(document.URL).search;
    const urlParams = new URLSearchParams(queryString);
    return urlParams.get(param);
}
