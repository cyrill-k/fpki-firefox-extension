chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg.request === 'get_dom_url') {
        sendResponse({ domUrl: document.URL.toString() });
    }
});
