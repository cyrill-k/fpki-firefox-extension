var port = browser.runtime.connect({
    name: "content to background communication"
});

// communication from background script to this content script
port.onMessage.addListener(async function(msg) {
    const {msgType, value} = msg;
    if (msgType === "logEntries") {
        console.log("received log entries from background script; sending pageloadfinished event");
        var pageLoadFinishedEvent = new CustomEvent('pageloadfinished',
                                                    {'detail': JSON.stringify(value)});
        document.dispatchEvent(pageLoadFinishedEvent);
    }
});

// this function sends all log entries as a custom event. This event can then be received by the selenium driver.
function sendLogEntriesAsCustomEvent() {
    // send message to background script requesting the current log entries
    port.postMessage("getLogEntries");
}

// continuously (every 1 second) send the log entries as a custom event
function continuouslySendLogEntriesAsCustomEvent() {
    setInterval(() => sendLogEntriesAsCustomEvent(), 1000);
}

continuouslySendLogEntriesAsCustomEvent()
