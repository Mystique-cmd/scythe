# Browser DevTools Multi-Flow Workflow Detector

A Chrome developer tool extension (Manifest V3) that monitors network activity (XHR, fetch, and GraphQL requests) and correlates them with browser-side user interactions. It automatically analyzes request patterns to flag and diagnose multi-step, orchestrated backend workflows.

## Features
- **Sessionization**: Correlates network requests to user-driven events (clicks, form submissions, Enter keypresses, and navigation).
- **Workflow Orchestration Timeline**: Visualizes request ordering, start offsets, and durations relative to the correlated user action.
- **Diagnostic Heuristic Engine**: Flags common multi-step orchestration patterns:
  - **Sequential Fan-out**: Rapid cascades of requests.
  - **Check-then-act**: Guard/verification calls (typically GET) followed by a mutating operation (typically POST/PUT/DELETE or GraphQL mutation).
  - **Cross-Domain Orchestration**: Requests spanning multiple service hostnames.
  - **Mixed Status Codes**: A cluster containing both successful responses and failures.
  - **Staged Polling Loops**: Repeated status/readiness polling.
  - **Pagination/Thresholding**: Evolving `offset/limit/page/attempt/retry/...` parameters.
  - **Multiple GraphQL Mutations**: Multiple write operations under a single correlated action.
  - **Mixed Telemetry**: Analytics/logging triggered alongside core business logic.
- **GraphQL Parser**: Extracts GraphQL operation type (query/mutation/subscription), operation name, and variables (including batched payloads).
- **Interactive Inspector**: Lets you open a request “drawer” to review headers, payloads, and response content.


---

## File Structure
```
scythe/
├── manifest.json                 # Extension Manifest V3 configuration
├── README.md                     # Documentation
├── icons/                        # Generated PNG icons
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── src/
    ├── background.js             # Runtime message broker service worker
    ├── content.js                # Interaction listeners injected into web pages
    ├── devtools.html             # Entry point for the browser DevTools page
    ├── devtools.js               # Registration script for DevTools panel
    └── ui/
        ├── panel.html            # DevTools panel structure (split-pane workspace)
        ├── panel.css             # High-fidelity dark mode stylesheet (glassmorphism)
        ├── panel.js              # State engine, sessionizer, heuristics & UI renderer
        ├── test_bench.html       # Sandbox UI to trigger mock scenarios
        ├── test_bench.js         # HTTP simulation triggers
        └── mock_responses/       # Local JSON fixtures for offline testing
            ├── check_permissions.json
            ├── job_status_pending.json
            ├── job_status_complete.json
            ├── users.json
            ├── items.json
            ├── config.json
            └── analytics.json
```

---

## Installation & Setup

1. **Download / Clone** this project folder to your local machine.
2. Open **Google Chrome** (or any Chromium browser).
3. Navigate to `chrome://extensions/`.
4. Enable **Developer mode** (toggle in the top-right corner).
5. Click **Load unpacked** in the top-left corner.
6. Select the `scythe` project root directory.

---

## How to use it on real websites (multi-step detection)

## Current project status
This repo is currently set up as a Chrome DevTools extension with a built-in “Test Bench” and a live heuristics engine.

### Implemented capabilities (latest)
- Multi-step workflow heuristics (fan-out, check-then-act, polling, pagination/counters, multi-mutation, telemetry).
- GraphQL request body parsing (operation type/name/variables).
- **Concurrency anomaly detection**: the detector now flags *racey concurrent mutations* when overlapping mutation requests (start-gap < 120ms) target the same mutation-path group, which is useful for identifying multi-step flows that collide under concurrent execution.
- Test Bench scenario: **Concurrent Check-Then-Act** simulates multiple guarded flows running in parallel to exercise the concurrency heuristic.



### 1) Enable the detector
1. Load the extension in Chrome (`chrome://extensions/` → **Load unpacked**).
2. Open DevTools for the website you want to inspect.
3. Click the **Workflow Detector** tab in the DevTools UI.

### 2) Run a user flow
1. Interact with the page: click buttons, submit forms, use keyboard Enter, or navigate.
2. The extension automatically correlates your interaction to network requests made shortly after it.

### 3) Tell whether the site is “multi-step” (how to interpret the output)
When the extension detects a clustered workflow, it will show it in the left sidebar.

This tool is a **heuristic analyzer**: it correlates requests to user actions (sessionization) and then flags evidence-based orchestration patterns. Treat each finding as “strong evidence” rather than a guarantee.

#### What the sidebar items represent
- **Workflow item (left sidebar)**: a sessionized cluster of requests associated with a user action (click/keypress/etc.) within the **Association Window**.
- **Unassociated traffic**: requests that don’t match any action in the time window (background jobs, browser noise, long-delayed requests).
- **Severity pill**: derived from the heuristic findings for that workflow.

#### Interpreting a workflow cluster step-by-step
For each workflow cluster, do this:

1. **Look for a severity badge** (low / medium / high).
   - **High** generally means the heuristics strongly match multi-step orchestration patterns (e.g., check-then-act around critical operations, unstable mixed-status flows, multiple GraphQL mutations).
2. **Open the workflow details** by clicking the item in the sidebar.
3. Review **Workflow Diagnostics**:
   - Each card explains the matched heuristic (e.g., *Sequential Fan-out*, *Check-then-act*, *Staged Polling Loop*).
4. Use the **Network Orchestration Timeline**:
   - Bars are request spans.
   - The x-axis is the offset from the correlated user action.
   - If you see multiple bars grouped after the same user action (especially with guard/poll/cascade patterns), it strongly indicates an orchestrated multi-step backend flow.
5. Confirm with **HTTP Operations (HAR)**:
   - Click a row or timeline bar to open the **Request Details** drawer.
   - Inspect request method, endpoint/path, payload (including GraphQL body), and response code.

### Notes / expectations
- The detector is a **heuristic analyzer**, not a perfect oracle. Flags are evidence-based (timeline + diagnostics) and you validate by checking the inspected requests.
- The “association window” (default **2500ms**) controls how tightly the tool links requests to your interaction.

---

## Configuration Settings
Click the **Gear** icon in the panel header to edit:
- **Association Window (ms)**: The threshold for linking network requests to a preceding click or keypress (default: `2500ms`).
- **Heuristic Severity Threshold**: Filter out minor findings (e.g. only show Medium/High alerts).
- **Preserve Log**: Retain session logs across browser navigation events.

### Troubleshooting
- If you see fewer/no workflow clusters, increase **Association Window (ms)**.
- If you see too many clusters, decrease the window and/or raise **Heuristic Severity Threshold**.

