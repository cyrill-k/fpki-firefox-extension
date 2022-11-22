var port = browser.runtime.connect({
    name: "popup to background communication"
});
document.addEventListener('DOMContentLoaded', function() {
    try {
    document.getElementById('printLog').addEventListener('click', function() {
        port.postMessage("printLog");
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
    console.log("message recieved: " + msg);
});
