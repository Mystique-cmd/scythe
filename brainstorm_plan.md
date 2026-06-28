# Brainstorm Plan: Browser DevTools Multi-Flow Workflow Detector

## What we’re building
A **developer tool** (likely a **browser extension + optional local UI**) that watches **Network** activity (XHR/fetch + GraphQL requests) and flags patterns consistent with **multi-step / orchestrated workflows**, using criteria like:
- Multi sequential requests per single user action
- Check-then-act sequences
- Cross-domain/service orchestration
- Mixed status codes within a single action cluster
- Partial/staged responses (phased backend)
- Counters/threshold-like behavior
- Multiple GraphQL mutations
- Analytics/telemetry mixed with core logic

## Assumptions
- We can correlate requests by time and by browser-side triggers (click/submit/navigation) via event listeners.
- If the user enables “Preserve log”, we can still work with limited correlation.
- We’ll focus first on **detection + reporting** rather than fully reconstructing backend logic.

## Detection Model (initial)
### 1) Sessionize requests around user actions
- Track user events: click, keypress(Enter), form submit, route change (history pushState/replaceState), navigation.
- For each event, define a window (e.g., from event time to eventTime+N ms; N configurable).
- Assign each request to the nearest preceding user event within the window.

### 2) Create a “workflow cluster” per user event
Each cluster contains:
- request timeline
- URL domains
- method/status
- request/response sizes (if available)
- graphql operationName + type when present
- correlation heuristics

### 3) Heuristics scoring
For each cluster, compute score and emit findings:
- **Sequential fan-out**: >1 request within a small delta after first request
- **Check-then-act**: request A then request B where A response appears to gate B (heuristic: B occurs only after A completes; status/validation keywords)
- **Cross-domain**: multiple hostnames
- **Mixed status**: >=2 different status codes
- **Staged**: multiple phases detected via content-type changes, response sizes, or repeating “polling/ready” endpoints
- **Counters/thresholds**: request params like `offset`, `limit`, `page`, `attempt`, `retry`, `count`, `threshold` evolve
- **GraphQL mutations**: multiple mutation operations
- **Telemetry alongside core**: presence of known analytics endpoints (segment, ga, mixpanel, datadog, sentry, amplitude) mixed with core business endpoints

### 4) Output
- In-extension panel UI listing recent detected workflows:
  - user event summary
  - key requests (ordered)
  - evidence per heuristic
  - estimated workflow type (likely multi-step)

## Implementation Plan (phases)
### Phase A — Minimal viable extension
- Background/service worker intercepts webRequest or observes network from content script.
- Track user actions + correlate to network.
- Basic UI panel to show timeline + cluster score.

### Phase B — Better GraphQL parsing
- Parse request bodies for `/graphql` POSTs.
- Extract `operationName`, `query/mutation` type (mutation vs query).
- Track variables like `input`, `id` consistency across requests.

### Phase C — Better orchestration inference
- Add cross-domain correlation and mixed status emphasis.
- Detect staged patterns and analytics mixing.

### Phase D — Packaging and polish
- README, install instructions, configuration options (time window, thresholds).

## Project layout
- `manifest.json`
- `src/` for extension code
  - `background.js` / `service_worker.js`
  - `content.js` (event listener)
  - `ui/panel.html`, `panel.js`, `panel.css`
- `package.json` if we use a bundler (optional)

## Key technical choices
- Prefer **Chrome/Firefox extension**.
- For devtools-like UX, use a **side panel** or **devtools panel**.
- Start with Chrome MV3 (service worker).

## Milestones / Success criteria
- Detect at least one known multi-step pattern in real sites.
- Show clear evidence lines for each heuristic.
- Keep overhead minimal.

