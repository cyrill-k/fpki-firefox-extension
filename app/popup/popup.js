var port = browser.runtime.connect({
    name: "popup to background communication"
});
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('printLog').addEventListener('click', function() {
        port.postMessage("printLog");
    });
    document.getElementById('downloadLog').addEventListener('click', function() {
        port.postMessage("downloadLog");
    });
});

// communication from background script to popup
port.onMessage.addListener(function(msg) {
    console.log("message recieved: " + msg);
});
