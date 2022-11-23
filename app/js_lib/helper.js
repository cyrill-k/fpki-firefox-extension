export function mapGetList(map, key) {
    return map.get(key) || [];
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
