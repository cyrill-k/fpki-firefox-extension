export const REMOTE_LOKI_HOST = '188.245.115.147'
const LOKI_ENDPOINT = `http://${REMOTE_LOKI_HOST}:3100/loki/api/v1/push`;
const EXTENSION_ID = chrome.runtime.id;
const USER_AGENT = navigator.userAgent;


function getTimestampNanoseconds() {
  return `${Date.now() * 1e6}`; // Convert milliseconds to nanoseconds
}

// Shamelessly stolen from stackoverflow
function generateUUIDv4() {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const length = 12;
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    for (let i = 0; i < length; i++) {
        result += charset[array[i] % charset.length];
    }
    return result;
}

function getUserId(callback) {
  chrome.storage.local.get(['userId'], function(result) {
    if (result.userId) {
      callback(result.userId);
    } else {
      const newUserId = generateUUIDv4();
      chrome.storage.local.set({ userId: newUserId }, function() {
        callback(newUserId);
      });
    }
  });
}

function sendLogToLoki(level, message, additionalLabels = {}) {
  getUserId(function(userId) {
    const logEntry = {
      streams: [
        {
          stream: {
            host: "FPKI_EXTENSION",
            level,
            extension_id: EXTENSION_ID,
            user_id: userId,
            user_agent: USER_AGENT,
            ...additionalLabels
          },
          values: [
            [getTimestampNanoseconds(), message]
          ]
        }
      ]
    };

    fetch(LOKI_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(logEntry)
    }).catch(error => {
      console.error('Failed to send log to Loki:', error);
    });
  });
}

export function logInfo(message, additionalLabels = {}) {
  console.log("LOGGING TO LOKI: ", message);
  sendLogToLoki('info', message, additionalLabels);
}

export function logError(error, additionalLabels = {}) {
  console.error("LOGGING TO LOKI: ", error);
  const message = error instanceof Error ? error.stack : String(error);
  sendLogToLoki('error', message, additionalLabels);
}

// TODO Buffering logs and sending them in batches so not to overload Loki
// let LOG_BUFFER = [];
// const MAX_BUFFER_SIZE = 50;
// const FLUSH_INTERVAL = 60000;

// let flushTimer = null;

// export function startFlushTimer() {
//   if (flushTimer === null) {
//     flushTimer = setInterval(() => {
//       flushLogBuffer();
//     }, FLUSH_INTERVAL_MS);
//   }
// }

// export function stopFlushTimer() {
//   if (flushTimer !== null) {
//     clearInterval(flushTimer);
//     flushTimer = null;
//   }
// }

// export function loadLogBuffer() {
//   chrome.storage.local.get(['logBuffer'], function(result) {
//     if (result.logBuffer && Array.isArray(result.logBuffer)) {
//       LOG_BUFFER = result.logBuffer;
//     }
//   });
// }

// function saveLogBuffer() {
//   chrome.storage.local.set({ logBuffer: LOG_BUFFER });
// }