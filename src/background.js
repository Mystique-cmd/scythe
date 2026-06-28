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

// Receive messages from content script and redirect to the appropriate DevTools panel
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Messages from content scripts should have sender.tab
  if (sender.tab) {
    const tabId = sender.tab.id;
    if (tabId in connections) {
      connections[tabId].postMessage(message);
    } else {
      console.log(`[Workflow Detector] Received event from tab ${tabId}, but no DevTools panel is connected.`);
    }
  } else {
    console.log('[Workflow Detector] Received message without sender tab:', message);
  }
  return true;
});

console.log('[Workflow Detector] Background script initialized.');
