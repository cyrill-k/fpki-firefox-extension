export const log = async (...args) => chrome.runtime.sendMessage({
    target: 'background',
    type: 'log',
    data: args,
});