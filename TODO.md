# TODO - Follow new tab opened by links and continue complete workflow detection

## Step 1: Replace DevTools network capture
- [x] Update `manifest.json` to add required `webRequest` permissions.
- [ ] Refactor `src/ui/panel.js` to stop using `chrome.devtools.network.*` and instead rely on requests coming from `background.js`.


## Step 2: Background capture only for tracked tabs
- [ ] Add new message protocol between `content.js` and `background.js` for link/new-tab intent (`NEW_TAB_INTENT`).
- [ ] Implement tracking of newly created tab IDs in `src/background.js` using `chrome.tabs.onCreated/onUpdated` and matching against intent.
- [ ] Implement `chrome.webRequest.onBeforeRequest` + `onCompleted/onErrorOccurred` to build request objects and forward to the panel.

## Step 3: Content script intent detection
- [ ] Enhance `src/content.js` to detect `_blank` clicks / window.open and send `NEW_TAB_INTENT`.

## Step 4: Testing
- [ ] Load unpacked, open DevTools, click a `_blank` link, confirm workflows appear for the new tab without needing to open DevTools again.
- [ ] Smoke-test existing heuristics.

