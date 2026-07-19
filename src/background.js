// Background Script: Acts as a bridge between the content script and the DevTools panel

const connections = {};

chrome.runtime.onConnect.addListener((port) => {
  const extensionListener = (message, sender, sendResponse) => {
    // The original connection event doesn't include the tab ID of the
    // inspected page, so we expect the devtools page to send it explicitly.
    if (message.name === 'init') {
      connections[message.tabId] = port;
      console.log(`[Workflow Detector] DevTools panel connected for tab: ${message.tabId}`);
      return;
    }
  };

  // Listen to messages sent from the DevTools panel
  port.onMessage.addListener(extensionListener);

  port.onDisconnect.addListener((port) => {
    port.onMessage.removeListener(extensionListener);

    const tabs = Object.keys(connections);
    for (let i = 0, len = tabs.length; i < len; i++) {
      if (connections[tabs[i]] === port) {
        delete connections[tabs[i]];
        console.log(`[Workflow Detector] DevTools panel disconnected for tab: ${tabs[i]}`);
        break;
      }
    }
  });
});

// NEW TAB tracking intents (short-lived) + tracked tab state
const newTabIntents = [];
const trackedTabIds = new Set();
const trackedUntilMs = 5000; // keep intents for 5s

// Cleanup intents periodically
setInterval(() => {
  const now = Date.now();
  while (newTabIntents.length && now - newTabIntents[0].timestamp > trackedUntilMs) {
    newTabIntents.shift();
  }
}, 1000);

function urlLooksLikeMatch(haystackUrl, needleUrl) {
  // Compare by exact or by hostname match.
  if (!haystackUrl || !needleUrl) return false;
  try {
    const h = new URL(haystackUrl);
    const n = new URL(needleUrl);
    if (h.toString() === n.toString()) return true;
    if (h.host === n.host) return true;
  } catch (_) {
    // Fallback: substring
  }
  return haystackUrl.includes(needleUrl) || needleUrl.includes(haystackUrl);
}

chrome.tabs.onCreated.addListener((tab) => {
  // Tab url may be empty initially; onUpdated will handle it.
  if (tab && typeof tab.id === 'number') {
    // no-op
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!tabId || !changeInfo) return;
  if (changeInfo.status && changeInfo.status !== 'complete') return;

  const tabUrl = tab && tab.url;
  if (!tabUrl) return;

  // Match intents
  for (let i = 0; i < newTabIntents.length; i++) {
    const intent = newTabIntents[i];
    if (intent && urlLooksLikeMatch(tabUrl, intent.destUrl)) {
      trackedTabIds.add(tabId);
      // Notify any connected devtools panels so they can start receiving events.
      // Panels are keyed by inspected tab id; we simply broadcast.
      Object.keys(connections).forEach((tid) => {
        try {
          connections[tid].postMessage({ type: 'TRACKED_TAB', tabId, url: tabUrl });
        } catch (_) {}
      });
      break;
    }
  }
});

// Receive messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Messages from content scripts should have sender.tab
  if (sender.tab) {
    const tabId = sender.tab.id;

    // If the devtools panel for this exact tab is connected, route to it.
    if (tabId in connections) {
      connections[tabId].postMessage(message);
      return true;
    }

    // Minimal fix: when workflows happen in newly opened tabs,
    // there may not be a connected devtools panel for that tab.
    // Broadcast so the currently-open panel can still sessionize based on timestamps.
    sendToPanel(message);

    console.log(`[Workflow Detector] Received event from tab ${tabId}, no panel for that tab; broadcasted to existing panel(s).`);
    return true;
  }

  console.log('[Workflow Detector] Received message without sender tab:', message);
  return true;
});


// =========================
// Background network capture (webRequest) for tracked tabs
// =========================

// requestId -> start info
const pendingWebRequests = new Map();

function toPlainHeaders(headers) {
  // webRequest gives headers as array-like of {name,value}
  if (!Array.isArray(headers)) return [];
  return headers.map(h => ({ name: h.name, value: h.value }));
}

function getStartedDateTimeMs(startEpochMs) {
  return new Date(startEpochMs).toISOString();
}

function sendToPanel(message) {
  // Broadcast to all connected devtools panels
  Object.keys(connections).forEach((tid) => {
    try {
      connections[tid].postMessage(message);
    } catch (_) {}
  });
}

// Capture request start
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const tabId = details.tabId;
    if (tabId < 0) return; // e.g. browser/internal

    if (!trackedTabIds.has(tabId)) return; // only tracked tabs

    const startedMs = Date.now();
    pendingWebRequests.set(details.requestId, {
      tabId,
      startedMs,
      url: details.url,
      method: details.method,
      requestHeaders: toPlainHeaders(details.requestHeaders),
      // We only support queryString-derived routing; postData is not accessible in webRequest without extra.
      // Keep compatibility for heuristics by setting empty postData.
    });
  },
  { urls: ['<all_urls>'] },
  ['extraHeaders']
);

// Capture request end (success)
chrome.webRequest.onCompleted.addListener(
  (details) => {
    const entry = pendingWebRequests.get(details.requestId);
    if (!entry) return;

    pendingWebRequests.delete(details.requestId);

    const responseHeaders = []; // not available without extra permissions/option in MV3

    const requestObj = {
      method: entry.method || 'GET',
      url: entry.url,
      headers: entry.requestHeaders || [],
      queryString: [],
      postData: null
    };

    const responseObj = {
      status: details.statusCode || 0,
      headers: responseHeaders,
      bodySize: 0,
      content: null
    };

    const startedEpochMs = entry.startedMs;
    const nowMs = Date.now();

    sendToPanel({
      type: 'WEBREQUEST',
      request: {
        // Match the shape the panel expects for handleNetworkRequest()
        request: requestObj,
        response: responseObj,
        time: Math.max(0, nowMs - startedEpochMs),
        startedDateTime: getStartedDateTimeMs(startedEpochMs),
        tabId: entry.tabId,
        _graphql: null
      }
    });
  },
  { urls: ['<all_urls>'] }
);

// Capture request errors
chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    const entry = pendingWebRequests.get(details.requestId);
    if (!entry) return;

    pendingWebRequests.delete(details.requestId);

    const requestObj = {
      method: entry.method || 'GET',
      url: entry.url,
      headers: entry.requestHeaders || [],
      queryString: [],
      postData: null
    };

    const responseObj = {
      status: 0,
      headers: [],
      bodySize: 0,
      content: null
    };

    const startedEpochMs = entry.startedMs;
    const nowMs = Date.now();

    sendToPanel({
      type: 'WEBREQUEST',
      request: {
        request: requestObj,
        response: responseObj,
        time: Math.max(0, nowMs - startedEpochMs),
        startedDateTime: getStartedDateTimeMs(startedEpochMs),
        tabId: entry.tabId,
        _graphql: null
      }
    });
  },
  { urls: ['<all_urls>'] }
);

console.log('[Workflow Detector] Background script initialized (with webRequest capture).');
