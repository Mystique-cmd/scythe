# Scythe — Browser DevTools Multi-Flow Workflow Detector

A Chrome DevTools extension (Manifest V3) that monitors network activity (XHR, fetch, and GraphQL requests) and correlates them with browser-side user interactions. It automatically analyzes request patterns to flag and diagnose multi-step, orchestrated backend workflows **and** detects common business logic vulnerabilities (IDOR, parameter tampering, privilege escalation, mass assignment, process bypass, injection, and race conditions).

---

## Features

### Orchestration Detection
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
  - **Concurrency Anomaly Detection**: Flags *racey concurrent mutations* when overlapping mutation requests (start-gap < 120ms) target the same mutation-path group — useful for identifying multi-step flows that collide under concurrent execution.
- **GraphQL Parser**: Extracts GraphQL operation type (query/mutation/subscription), operation name, and variables (including batched payloads).
- **Atomicity Traversal (HIGH-only)**: For high-severity workflow clusters, computes an output-anchored atomicity analysis — checks if a guard/check, polling loop, or multiple mutations exist before the final mutating (producing) request.
- **Interactive Inspector**: Opens a request "drawer" to review headers, payloads, and response content.

### Logic Flaws Detection Engine
Eight heuristic detectors that analyze request parameters, body payloads, and cross-request sequencing for common business logic vulnerabilities:

| Detector | Description | Severity Factors |
|----------|-------------|-----------------|
| **IDOR (Insecure Direct Object Reference)** | Detects sequential/predictable resource IDs (numeric, UUID, hex) across requests, missing auth headers on mutating requests with path-based IDs, and direct object references without authentication. | Sequential ID gaps <= 10 -> `medium`; 5+ predictable IDs -> `high`; No auth on ID-mutation -> `high` |
| **Parameter Tampering** | Flags suspicious financial values (negative prices, zero amounts, extreme numbers), quantity manipulation (negative/excessive), and client-supplied discount/coupon fields. | Negative/zero price -> `high`; Suspicious quantity -> `medium`/`high`; Hidden discount fields -> `medium` |
| **Auth / Privilege Escalation** | Detects client-supplied role/privilege parameters (`role=admin`, `isAdmin=true`), admin endpoint access without authorization, weak/short tokens, and user enumeration via varying auth endpoint status codes. | Client-controlled role -> `high`; Admin no-auth -> `high`; Enumeration -> `medium` |
| **Mass Assignment** | Identifies protected/internal fields sent from the client (`isAdmin`, `balance`, `credit_limit`, `role`, `isVerified`) and unexpected parameters beyond what's typical for the endpoint resource type. | Admin/balance fields -> `high`; Other protected fields -> `medium`; >=3 unexpected params -> `medium` |
| **Business Process Bypass** | Detects workflow step-skipping: payment without cart/checkout, write operations without validation, privileged operations without authentication, and out-of-order process execution. | All patterns -> `high` |
| **Input Validation Flaws** | Detects SQL injection, NoSQL injection (`$ne`, `$gt`, `$regex`), XSS, path traversal, null/undefined boundary values, type confusion, and control character injection in request parameters. | Injection/traversal/control chars -> `high`; Null fields/type confusion -> `medium` |
| **Race Condition / TOCTOU** | Analyzes check-then-act timing windows (gap > 50ms between guard completion and mutation start), missing optimistic locking headers (`If-Match`, `ETag`), and rapid concurrent mutations on the same resource path group. | Gap > 500ms -> `high`; Gap > 200ms -> `medium`; Missing versioning -> `medium`; Racey concurrent mutations -> `medium`/`high` |
| **Deserialization Bugs** | Detects serialized object payloads across multiple frameworks: Java (ACED0005 magic bytes, Base64 `rO0AB`), PHP (O: syntax, a: arrays), Python Pickle (opcodes, GLOBAL+REDUCE), .NET (`$type`, `__type`), Ruby Marshal (`\\x04\\x08`), YAML deserialization tags (`!!javax`, `!!python`), Node.js prototype pollution (`__proto__`), and XML deserialization gadgets. Also flags serialization-specific Content-Types, endpoint extensions, and custom headers. | High-confidence serialization match -> `high`; Medium-confidence -> `high`/`medium`; Path/Content-Type hints -> `medium`/`low` |

### Import, Export & Offline Analysis
- **Import File**: Upload **HAR (HTTP Archive)** logs or previously exported **Scythe JSON** files for offline analysis.
- **Atomicity Dashboard**: After importing, renders a dashboard with:
  - **Atomicity Score**: Percentage of high-severity flows that are atomic (single-request).
  - **Total Flows / Non-Atomic Flows / Orchestration Alerts** metric cards.
  - **Orchestration Pattern Prevalence** bar charts.
  - **Consolidation Recommendations**: For non-atomic flows, suggests backend endpoint consolidation strategies (e.g., "Consolidate guard-check + mutation into a single backend endpoint").
- **Export Data**: Export all captured workflows as a downloadable JSON file.

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
        ├── flaws.js              # Logic flaws detection engine (7 detectors)
        ├── flaws.css             # Logic flaws UI styles (cards, badges, severity colors)
        ├── test_bench.html       # Sandbox UI to trigger mock scenarios
        ├── test_bench.js         # HTTP simulation triggers (orchestration + flaw scenarios)
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

## How To Use

### 1) Enable the detector
1. Load the extension in Chrome (`chrome://extensions/` -> **Load unpacked**).
2. Open DevTools for the website you want to inspect.
3. Click the **Workflow Detector** tab in the DevTools UI.

### 2) Run a user flow
1. Interact with the page: click buttons, submit forms, use keyboard Enter, or navigate.
2. The extension automatically correlates your interaction to network requests made shortly after it.

### 3) Interpret the output

This tool is a **heuristic analyzer**: it correlates requests to user actions (sessionization) and then flags evidence-based orchestration patterns. Treat each finding as "strong evidence" rather than a guarantee.

#### What the sidebar items represent
- **Workflow item (left sidebar)**: A sessionized cluster of requests associated with a user action (click/keypress/etc.) within the **Association Window**.
- **Unassociated traffic**: Requests that don't match any action in the time window (background jobs, browser noise, long-delayed requests).
- **Severity pill**: Derived from the heuristic findings for that workflow.
- **Flaw pill** (shield flaw): Indicates that the logic flaws engine detected vulnerabilities in this workflow.

#### Interpreting a workflow cluster step-by-step

1. **Look for a severity badge** (low / medium / high).
   - **High** generally means the heuristics strongly match multi-step orchestration patterns.
2. **Open the workflow details** by clicking the item in the sidebar.
3. Switch between the **Diagnostics** tab (orchestration heuristics) and **Logic Flaws** tab (vulnerability findings).
4. Review **Workflow Diagnostics**:
   - Each card explains the matched heuristic (e.g., *Sequential Fan-out*, *Check-then-act*, *Staged Polling Loop*).
   - Each flaw card shows the vulnerability category, severity, description, and evidence (raw parameter values).
5. Use the **Network Orchestration Timeline**:
   - Bars are request spans; the x-axis is the offset from the correlated user action.
   - Bars that start soon after **0s** and cluster together indicate orchestrated requests.

   **Poll Guard Pattern ("verify -> readiness polling -> act")**
   - **What you should see**: A guard/check bar near 0s -> one or more polling bars (same path) -> a final mutation bar later.
   - **Timeline cue**: Multiple bars to the same-ish endpoint before the final mutating bar.

   **Cascade Pattern ("fan-out / chained steps")**
   - **What you should see**: A first kick-off bar near 0s -> dense burst of subsequent bars with small start-to-start gaps.
   - **Timeline cue**: A dense left-to-right progression of bars with distinct endpoints.

6. Confirm with **HTTP Operations (HAR)**:
   - Click a row or timeline bar to open the **Request Details** drawer.
   - Inspect request method, endpoint/path, payload, and response code.

### 4) Using the Test Bench
The extension includes a built-in **Test Bench** (`src/ui/test_bench.html`) for testing all features without a live website:

1. Open `src/ui/test_bench.html` directly in the browser (or serve it locally).
2. Click any scenario button to simulate a workflow.

**Orchestration Scenarios:**
| Button | Pattern | What it simulates |
|--------|---------|-------------------|
| **Parallel Burst** | Sequential Fan-out | 3 parallel fetch requests (users, items, config) |
| **Concurrent Check-Then-Act** | Concurrency Anomaly | 3 guarded flows running concurrently with interleaved check+mutate |
| **Check-Then-Act** | Guard + Mutation | GET permission check -> 300ms delay -> POST checkout |
| **Multi-Domain Sync** | Cross-Domain | Multiple fixture requests in sequence |
| **GraphQL Checkout** | GraphQL Mutations | Simulated multi-mutation GraphQL flow |
| **Faulty Transaction** | Mixed Status Codes | One successful request + one intentional 404 |
| **Staged Polling** | Polling Loop | Job start -> 3 status polls (pending -> pending -> complete) |

**Logic Flaw Scenarios:**
| Button | Flaw Type | What it simulates |
|--------|-----------|-------------------|
| **IDOR Sequential IDs** | IDOR | GET /api/users/1001, 1002, 1003 + POST to admin with no auth |
| **Price Manipulation** | Parameter Tampering | POST with negative price, zero quantity, negative discount, negative total |
| **Priv Escalation** | Auth Escalation | POST registration with `role=admin`, `isAdmin=true`, admin permissions |
| **Mass Assignment** | Mass Assignment | PUT profile with `isAdmin`, `balance`, `credit_limit`, internal notes |
| **Process Bypass** | Process Bypass | POST payment with no preceding cart/checkout steps |
| **Injections** | Input Validation | POST login with SQL injection (`' OR '1'='1' --`) and NoSQL operator (`$ne`) |
| **Race Condition** | Race Condition / TOCTOU | GET balance check -> 600ms gap -> POST withdraw (wide TOCTOU window) |

### 5) Offline Analysis with Import File
Upload HAR logs or previously exported JSON for atomicity analysis:

1. Click the **Import File** button in the toolbar.
2. Drag-and-drop a `.har` or `.json` file onto the upload zone (or click Browse).
3. The extension will:
   - Parse the requests into sessionized workflow clusters.
   - Run all heuristic detectors and the logic flaws engine.
   - Compute **output-anchored atomicity** for high-severity clusters.
   - Display the **Atomicity Dashboard** with metrics, pattern prevalence charts, and consolidation recommendations.
4. Click **Live Mode** to return to normal live-capture mode.

### 6) Export Data
1. Click the **Export** button in the toolbar.
2. A JSON file (`workflow-detector-export-{timestamp}.json`) is downloaded.
3. This file can be re-imported later for offline analysis.

---

## Configuration Settings
Click the **Gear** icon in the panel header to edit:
- **Association Window (ms)**: The threshold for linking network requests to a preceding click or keypress (default: `2500ms`). Increase if you see fewer clusters; decrease if you see too many.
- **Heuristic Severity Threshold**: Filter findings by minimum severity -- `Low+`, `Medium and High only`, or `High only`.
- **Preserve Log**: Retain session logs across browser navigation events.

---

## UI Reference

### Header Toolbar
| Button | Action |
|--------|--------|
| **Clear** | Clear all recorded events and requests |
| **Import File** | Upload HAR or Scythe JSON for offline analysis |
| **Export** | Download captured workflow data as JSON |
| **Gear icon** | Open settings modal |

### Details Pane Tabs
| Tab | Content |
|-----|---------|
| **Diagnostics** (default) | Orchestration heuristic findings with severity-coded cards |
| **Logic Flaws** | Vulnerability detection results with category, severity, and raw evidence |

### Request Inspector Drawer
Click any request row in the timeline or HTTP Operations table to open the side drawer with tabs:
- **Headers**: Request URL, request headers, response headers.
- **Payload**: Parsed request body (formatted JSON).
- **Response**: Response body content.
- **GraphQL** (shown only for GraphQL requests): Operation type, name, variables, and raw query.

---

## Notes / Expectations
- The detector is a **heuristic analyzer**, not a perfect oracle. Flags are evidence-based (timeline + diagnostics) and you validate by checking the inspected requests.
- The **Logic Flaws Engine** examines *parameters and patterns in requests*, not actual server responses -- treat findings as potential vulnerabilities requiring manual verification.
- The "association window" (default **2500ms**) controls how tightly the tool links requests to your interaction.

### Troubleshooting
- **Few/no workflow clusters**: Increase **Association Window (ms)**.
- **Too many clusters**: Decrease the window and/or raise **Heuristic Severity Threshold**.
- **Test Bench not capturing**: The Test Bench is an offline sandbox -- network requests go to local fixtures, not real servers. Ensure the extension is loaded and DevTools panel is open.
- **Logic Flaws not showing**: Flaw detection only runs on workflows that have captured requests. Use the Test Bench flaw scenarios to verify the engine works.
- **Import parsing errors**: Ensure the file is valid JSON (`.json`) or a valid HAR archive (`.har` with `log.entries` array).

---

## Current Project Status

This repo is a fully functional Chrome DevTools extension with:
- **Live heuristics engine** (8 orchestration patterns + concurrency anomaly detection)
- **Logic flaws detection engine** (7 vulnerability categories)
- **GraphQL request body parser** (operation type, name, variables, batched payloads)
- **Output-anchored atomicity traversal** for HIGH-severity workflows
- **Test Bench** with 7 orchestration scenarios and 7 flaw scenarios
- **HAR / JSON import** with atomicity analysis dashboard
- **JSON export** for offline sharing and re-analysis
- **High-fidelity dark mode UI** with glassmorphism design

