// Background Script: Acts as a bridge between the content script and the DevTools panel

const connections = {};

chrome.runtime.onConnect.addListener((port) => {
  const extensionListener = (message, sender, sendResponse) => {
    // The original connection event doesn't include the tab ID of the
    // inspected page, so we expect the devtools page to send it explicitly.
    if (message.name === 'init') {
      connections[message.tabId] = port;
      // Add the inspected tab to trackedTabIds so webRequest events
      // from this tab are captured immediately.
      if (typeof message.tabId === 'number') {
        trackedTabIds.add(message.tabId);
      }
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

// Helper: send message to all connected DevTools panels
function sendToPanel(message) {
  Object.keys(connections).forEach((tid) => {
    try {
      connections[tid].postMessage(message);
    } catch (_) {}
  });
}

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
  // Process NEW_TAB_INTENT messages: populate newTabIntents so that
  // onCreated/onUpdated can correlate new tabs to tracked traffic.
  if (message.type === 'NEW_TAB_INTENT' && message.intent) {
    newTabIntents.push({
      destUrl: message.intent.destUrl || message.intent.href,
      href: message.intent.href,
      sourceUrl: message.intent.sourceUrl,
      timestamp: message.intent.timestamp || Date.now()
    });
  }

  // Messages from content scripts should have sender.tab
  if (sender.tab) {
    const tabId = sender.tab.id;

    // If the devtools panel for this exact tab is connected, route to it.
    if (tabId in connections) {
      connections[tabId].postMessage(message);
      return true;
    }

    // For tracked tabs or any tab with events, add to tracked set
    // so webRequest events are captured.
    if (typeof tabId === 'number' && !trackedTabIds.has(tabId)) {
      trackedTabIds.add(tabId);
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
      requestBody: details.requestBody || null
    });
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders', 'requestBody', 'extraHeaders']
);

// Helper to extract postData text from webRequest requestBody
function extractPostData(requestBody) {
  if (!requestBody) return null;
  if (requestBody.formData) {
    // Form data: convert to URL-encoded string
    const params = new URLSearchParams();
    Object.keys(requestBody.formData).forEach(key => {
      const vals = requestBody.formData[key];
      if (Array.isArray(vals)) {
        vals.forEach(v => params.append(key, v));
      } else {
        params.append(key, vals);
      }
    });
    return { text: params.toString() };
  }
  if (requestBody.raw && requestBody.raw.length > 0) {
    // Raw bytes: convert first chunk to text (UTF-8)
    try {
      const decoder = new TextDecoder('utf-8', { fatal: false });
      let text = '';
      for (const chunk of requestBody.raw) {
        if (chunk.bytes) {
          text += decoder.decode(chunk.bytes, { stream: true });
        }
      }
      text += decoder.decode();
      if (text) {
        return { text };
      }
    } catch (_) {}
  }
  if (requestBody.error) {
    return null;
  }
  return null;
}

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
      postData: extractPostData(entry.requestBody)
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
      postData: extractPostData(entry.requestBody)
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
