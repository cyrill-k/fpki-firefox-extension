var port = browser.runtime.connect({
    name: "popup to background communication"
});
document.addEventListener('DOMContentLoaded', function() {
    const link = document.getElementById('printLog');
    link.addEventListener('click', function() {
        port.postMessage("printLog");
    });
});

// communication from background script to popup
port.onMessage.addListener(function(msg) {
    console.log("message recieved: " + msg);
});
