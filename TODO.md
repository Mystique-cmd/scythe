# Fix Plan: System Not Working

## Issues
1. **Network traffic not captured** - `newTabIntents` never populated, `trackedTabIds` empty, webRequest events filtered out
2. **GUI for flaw modules not appearing** - No requests captured = no data for flaw engine = nothing rendered
3. **User interactions not working** - Content script events not properly routed, inspected tab not tracked

## Steps

### Step 1: Fix `background.js`
- [x] Process `NEW_TAB_INTENT` messages to populate `newTabIntents`
- [x] Add inspected tab's `tabId` to `trackedTabIds` on DevTools panel init
- [x] Fix `webRequest.onBeforeRequest` extraInfoSpec to include `['requestHeaders', 'requestBody', 'extraHeaders']`
- [x] Route `USER_ACTION` messages to panels even when no panel for that exact tab
- [x] Add `chrome.runtime.onMessage` listener for `NEW_TAB_INTENT` before the existing listener
- [x] Add `sendToPanel()` helper before it's used (moved up)
- [x] Add `extractPostData()` helper to decode request body from webRequest
- [x] Pass `postData` and `requestBody` to panel for flaw detection engines

### Step 2: Fix `panel.js`
- [x] Remove duplicate `WEBREQUEST` listener
- [x] Ensure single unified message listener for all message types

### Step 3: Fix `content.js`
- [x] Add `.catch(() => {})` to `chrome.runtime.sendMessage` for graceful handling

### Step 4: Verify and test
- [x] Review all changes for consistency
- [x] Verified background.js, panel.js, content.js are all consistent with each other



