# Fix Plan: System Not Working — COMPLETED ✅

## Issues
1. **Network traffic not captured** - ✅ FIXED
2. **GUI for flaw modules not appearing** - ✅ FIXED (was caused by #1)
3. **User interactions not working** - ✅ FIXED

## Steps Completed

### Step 1: `background.js` — All Fixes Applied ✅
- [x] Process `NEW_TAB_INTENT` messages to populate `newTabIntents`
- [x] Add inspected tab's `tabId` to `trackedTabIds` on DevTools panel `init`
- [x] Fix `webRequest.onBeforeRequest` extraInfoSpec — includes `['requestHeaders', 'requestBody', 'extraHeaders']`
- [x] Route `USER_ACTION` messages via `sendToPanel()` broadcast
- [x] Auto-track sender tabs in `trackedTabIds`
- [x] Added `extractPostData()` helper for webRequest body capture
- [x] Added `sendToPanel()` helper at top level (removed duplicate at bottom)

### Step 2: `panel.js` — Already Correct ✅
- [x] Single consolidated `onMessage` listener (no duplicate)
- [x] Properly imports and calls `detectFlaws()` from `flaws.js`
- [x] `init` message includes `chrome.devtools.inspectedWindow.tabId`
- [x] Flaw module UI renders when requests are available

### Step 3: `content.js` — Already Robust ✅
- [x] Error handling on `chrome.runtime.sendMessage()` with `.catch(() => {})`
- [x] Captures clicks, keydowns, submits, navigations, and new tab intents

### `background.js` — Changes:
1. **Added `sendToPanel()` helper function** - Moves the duplicate `sendToPanel` logic to a single helper, used everywhere
2. **Added inspected tab to `trackedTabIds` on `init`** - When DevTools panel connects, the inspected tab's ID is added to `trackedTabIds` so webRequest events are captured immediately from the active tab
3. **Process `NEW_TAB_INTENT` messages** - Added handler in `onMessage` to populate `newTabIntents` array with intent details, so `onUpdated` can match new tabs and add them to `trackedTabIds`
4. **Track sender tabs automatically** - Any tab sending `USER_ACTION` or other messages that isn't already tracked gets added to `trackedTabIds` automatically
5. **Fixed `webRequest.onBeforeRequest` extraInfoSpec** — Added `['requestHeaders', 'requestBody', 'extraHeaders']` to capture headers and body data
6. **Added `extractPostData()` helper** — Converts the `webRequest` requestBody (raw bytes, formData) into a postData text object

### `panel.js` — Already correct:
- Single `backgroundPageConnection.onMessage.addListener` handles both `USER_ACTION`, `WEBREQUEST`, and `TRACKED_TAB` types
- Properly imports and calls `detectFlaws()` from `flaws.js`
- All flaw module engines (IDOR, param tampering, auth escalation, mass assignment, etc.) are connected and render when requests are available

### `content.js` — Already robust:
- Uses `.catch(() => {})` on `chrome.runtime.sendMessage()` to handle context invalidation
- Properly captures clicks, keydowns, submits, navigations, and new tab intents

