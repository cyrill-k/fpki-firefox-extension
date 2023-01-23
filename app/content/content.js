browser.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg.request === 'get_dom_url') {
        return Promise.resolve({ domUrl: document.URL });
    }
});
