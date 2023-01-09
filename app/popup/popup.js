var synchronizedConfig = null;
var port = browser.runtime.connect({
    name: "popup to background communication"
});
function updateConfig() {
    const configCodeElement = document.getElementById("config");
    const printableConfig = new Map();
    synchronizedConfig.forEach((value, key) => {
        if (["ca-sets", "legacy-trust-preference", "policy-trust-preference", "root-pcas", "root-cas"].includes(key)) {
            printableConfig.set(key, Object.fromEntries(value));
        } else {
            printableConfig.set(key, value);
        }
        // could try to implement using the datatype: e.g., if (typeof value === "map")
    });
    configCodeElement.innerHTML = "config = "+JSON.stringify(Object.fromEntries(printableConfig), null, 4);
}
document.addEventListener('DOMContentLoaded', function() {
    try {
    document.getElementById('printLog').addEventListener('click', function() {
        port.postMessage("printLog");
        updateConfig();
    });
    document.getElementById('downloadLog').addEventListener('click', function() {
        port.postMessage("downloadLog");
    });
    } catch (e) {
        console.log("popup button setup: "+e);
    }
});

// communication from background script to popup
port.onMessage.addListener(function(msg) {
    const {msgType, value} = msg;
    if (msgType === "config") {
        synchronizedConfig = value;
        updateConfig();
    }
    console.log("message received: " + JSON.stringify(msg));
});
