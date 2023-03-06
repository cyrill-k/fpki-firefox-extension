import {exportConfigToJSON} from "../../js_lib/config.js"

var synchronizedConfig = null;
var port = browser.runtime.connect({
    name: "config to background communication"
});

document.addEventListener('DOMContentLoaded', function() {
    try {
        document.getElementById('printConfig').addEventListener('click', function() {
            port.postMessage("printConfig");
            // updateConfig();
        });
        document.getElementById('downloadConfig').addEventListener('click', function() {
            port.postMessage("downloadConfig");
        });
        document.getElementById('resetConfig').addEventListener('click', function() {
            port.postMessage("resetConfig");
        });
        document.getElementById('uploadConfig').addEventListener('click', function() {
            let file = document.getElementById("file").files[0];
            let reader = new FileReader();
            
            reader.onload = function(e){
                port.postMessage({type: "uploadConfig", value: e.target.result});
            }
            reader.readAsText(file);
        });
    } catch (e) {
        console.log("config button setup: "+e);
    }
});

// communication from background script to popup
port.onMessage.addListener(async function(msg) {
    const {msgType, value} = msg;
    if (msgType === "config") {
        console.log("receiving config...");
        synchronizedConfig = value;
        updateConfig();
    }
});

function updateConfig() {
    const configCodeElement = document.getElementById("config-code");
    configCodeElement.innerHTML = "config = "+exportConfigToJSON(synchronizedConfig, true);
}
