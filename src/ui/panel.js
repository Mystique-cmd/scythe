// DevTools Panel JS: Handles sessionization, heuristic evaluation, timeline rendering, and user interaction

import { detectFlaws } from './flaws.js';

// Global State
let workflows = [];
let selectedWorkflowId = null;
let activeFilters = { text: '' };
// Track current section tab in details pane
let activeSectionTab = 'heuristics';
// Track flaws-only view mode
let flawsViewMode = false;

// Settings State
let settings = {
  associationWindow: 2500, // ms
  severityThreshold: 'medium', // 'low', 'medium', 'high'
  preserveLog: true
};

// Imported Mode State
let isImportedMode = false;
let importedFilename = '';
let liveStateBackup = null;

// Background connection
let backgroundPageConnection = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  setupConnection();
  setupUIEventListeners();
  renderWorkflowList();
  updateDetailsPane();
  updateStatusBadge();
});

// Load Settings from storage
function loadSettings() {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['detectorSettings'], (result) => {
      if (result.detectorSettings) {
        settings = { ...settings, ...result.detectorSettings };
        updateSettingsUI();
      }
    });
  }
}

// Update Settings UI values
function updateSettingsUI() {
  document.getElementById('setting-window').value = settings.associationWindow;
  document.getElementById('setting-threshold').value = settings.severityThreshold;
  document.getElementById('preserve-log-checkbox').checked = settings.preserveLog;
}

// Save Settings
function saveSettings() {
  settings.associationWindow = parseInt(document.getElementById('setting-window').value, 10) || 2500;
  settings.severityThreshold = document.getElementById('setting-threshold').value;
  settings.preserveLog = document.getElementById('preserve-log-checkbox').checked;

  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.set({ detectorSettings: settings }, () => {
      console.log('[Workflow Detector] Settings saved.');
    });
  }
  
  // Re-run heuristics on all workflows with new settings
  workflows.forEach(w => {
    runHeuristics(w);
    w.flaws = detectFlaws(w);
    updateFlawSeverity(w);
  });
  renderWorkflowList();
  updateDetailsPane();
  
  closeModal('settings-modal');
}

// Setup background communication channel
function setupConnection() {
  if (typeof chrome === 'undefined' || !chrome.runtime) {
    console.warn('[Workflow Detector] Not running in extension context.');
    return;
  }

  backgroundPageConnection = chrome.runtime.connect({
    name: "devtools-page"
  });

  // Register this DevTools panel to receive tab events
  backgroundPageConnection.postMessage({
    name: 'init',
    tabId: chrome.devtools.inspectedWindow.tabId
  });

// Listen to messages from the background script (user actions + web requests)
  backgroundPageConnection.onMessage.addListener((message) => {
    if (!message || !message.type) return;

    if (message.type === 'USER_ACTION') {
      handleUserAction(message.action);
      return;
    }

    // webRequest network feed (background)
    if (message.type === 'WEBREQUEST' && message.request) {
      handleNetworkRequest(message.request);
      return;
    }

    // tracked tab info (optional; current code uses only network feed)
    if (message.type === 'TRACKED_TAB') {
      // no-op for now
      return;
    }
  });
}

// === END of setupConnection ===

// Helper: Generate Unique ID
function generateId() {
  return Math.random().toString(36).substr(2, 9);
}

// Handle User Actions (Sessionization Trigger)
function handleUserAction(action) {
  // Prevent duplicate events (e.g. double clicks within 150ms)
  const lastAction = workflows[workflows.length - 1];
  if (lastAction && lastAction.type === action.type && 
      lastAction.detail === action.detail && 
      (action.timestamp - lastAction.timestamp < 150)) {
    return;
  }

  const newWorkflow = {
    id: generateId(),
    type: action.type,
    detail: action.detail,
    timestamp: action.timestamp,
    url: action.url,
    requests: [],
    heuristics: [],
    flaws: [],
    severity: 'none',
    flawSeverity: 'none',
    score: 0
  };

  workflows.push(newWorkflow);
  
  // Max limit of 100 sessions to keep UI fast
  if (workflows.length > 100) {
    workflows.shift();
  }

  renderWorkflowList();
  
  // Auto-select if nothing selected
  if (!selectedWorkflowId) {
    selectWorkflow(newWorkflow.id);
  }
}

// Get or create the special Background/Unassociated Activity cluster
function getUnassociatedCluster(requestTime) {
  let unassociated = workflows.find(w => w.type === 'unassociated');
  if (!unassociated) {
    unassociated = {
      id: 'unassociated-group',
      type: 'unassociated',
      detail: 'Background & Unassociated Traffic',
      timestamp: requestTime,
      url: 'Multiple background tasks',
      requests: [],
      heuristics: [],
      flaws: [],
      severity: 'none',
      flawSeverity: 'none',
      score: 0
    };
    workflows.push(unassociated);
  }
  return unassociated;
}

// Handle Network Request
function handleNetworkRequest(request) {
  const requestTime = new Date(request.startedDateTime).getTime();
  
  // Find the closest preceding user action workflow session
  let targetWorkflow = null;
  
  // Loop backwards to find the nearest action before request start time
  for (let i = workflows.length - 1; i >= 0; i--) {
    const w = workflows[i];
    if (w.type === 'unassociated') continue;
    
    const diff = requestTime - w.timestamp;
    if (diff >= 0 && diff <= settings.associationWindow) {
      targetWorkflow = w;
      break;
    }
  }

  // If no action matched, group into Unassociated
  if (!targetWorkflow) {
    targetWorkflow = getUnassociatedCluster(requestTime);
  }

  // Parse GraphQL details if applicable
  const parsedGql = parseGraphQL(request);
  if (parsedGql) {
    request._graphql = parsedGql;
  }

  targetWorkflow.requests.push(request);

  // Re-run heuristics for this workflow
  runHeuristics(targetWorkflow);
  
  // Run logic flaw detection
  targetWorkflow.flaws = detectFlaws(targetWorkflow);
  updateFlawSeverity(targetWorkflow);
  
  // Re-render
  renderWorkflowList();
  if (selectedWorkflowId === targetWorkflow.id) {
    updateDetailsPane();
  }
}

// Parse GraphQL Body
function parseGraphQL(request) {
  const isJSON = request.request.headers.some(h => 
    h.name.toLowerCase() === 'content-type' && h.value.toLowerCase().includes('application/json')
  );
  
  if (!isJSON) return null;
  
  const postData = request.request.postData;
  if (!postData || !postData.text) return null;
  
  try {
    const body = JSON.parse(postData.text);
    
    const parseSingle = (obj) => {
      if (obj && typeof obj === 'object' && 'query' in obj) {
        const queryStr = obj.query;
        let operationName = obj.operationName || '';
        let type = 'query';
        
        if (queryStr) {
          const trimmed = queryStr.trim();
          if (trimmed.startsWith('mutation') || trimmed.includes('mutation ')) {
            type = 'mutation';
          } else if (trimmed.startsWith('subscription') || trimmed.includes('subscription ')) {
            type = 'subscription';
          }
          
          if (!operationName) {
            // Regex to match query/mutation operation name
            const match = trimmed.match(/^(mutation|query|subscription)\s+(\w+)/);
            if (match && match[2]) {
              operationName = match[2];
            }
          }
        }
        
        return {
          query: queryStr,
          operationName: operationName || 'anonymous',
          variables: obj.variables || {},
          type
        };
      }
      return null;
    };
    
    if (Array.isArray(body)) {
      const results = body.map(parseSingle).filter(Boolean);
      return results.length ? { isBatched: true, operations: results } : null;
    } else {
      const res = parseSingle(body);
      return res ? { isBatched: false, operations: [res] } : null;
    }
  } catch (e) {
    return null;
  }
}

// Helper to extract clean URL pathname
function getPathname(urlString) {
  try {
    const url = new URL(urlString);
    return url.pathname;
  } catch(e) {
    return urlString;
  }
}

// Helper to extract domain/host
function getHostname(urlString) {
  try {
    const url = new URL(urlString);
    return url.host;
  } catch(e) {
    return '';
  }
}

// HEURISTICS ENGINE
function runHeuristics(workflow) {
  if (workflow.type === 'unassociated' || workflow.requests.length === 0) {
    workflow.heuristics = [];
    workflow.severity = 'none';
    workflow.score = 0;
    return;
  }

  const findings = [];
  let score = 0;

  const sortedReqs = [...workflow.requests].sort((a, b) => {
    return new Date(a.startedDateTime).getTime() - new Date(b.startedDateTime).getTime();
  });

  // 1) Sequential fan-out: rapid bursts of requests (delta < 200ms between consecutive requests)
  let burstCount = 0;
  for (let i = 1; i < sortedReqs.length; i++) {
    const prevTime = new Date(sortedReqs[i-1].startedDateTime).getTime();
    const currTime = new Date(sortedReqs[i].startedDateTime).getTime();
    if (currTime - prevTime < 200) {
      burstCount++;
    }
  }
  if (burstCount >= 2) {
    const count = burstCount + 1;
    const severity = count > 3 ? 'medium' : 'low';
    const findingScore = severity === 'medium' ? 25 : 10;
    findings.push({
      id: 'fanout',
      name: 'Sequential Fan-out',
      description: `Detected sequential fan-out. ${count} requests launched in rapid succession (within 200ms increments).`,
      severity,
      score: findingScore
    });
    score += findingScore;
  }

  // 2) Atomicity checks anchored on mutating endpoints
  // For each mutating request (POST/PUT/PATCH/DELETE or GraphQL mutation), find the nearest preceding
  // check-like request (GET with keywords or GraphQL query with check keywords) that completes before/near it.

  // NOTE (Concurrency): When multiple multi-step flows run concurrently against the same mutation/guard pattern,
  // we can see overlapping mutations with similar paths and very short inter-mutation gaps.
  // We add a dedicated heuristic to flag these cases as potential racey concurrency anomalies.


  const isMutatingRequest = (req) => {
    return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.request.method) ||
      (req._graphql && req._graphql.operations && req._graphql.operations.some(op => op.type === 'mutation'));
  };

  const isGraphQLCheckKeyword = (req) => {
    if (!req._graphql || !req._graphql.operations) return false;
    return req._graphql.operations.some(op =>
      /check|validate|verify|auth|perm|exist|status|search|lookup/i.test(op.operationName)
    );
  };

  const isCheckLikeRequest = (req) => {
    const isGetOrGqlQuery =
      req.request.method === 'GET' ||
      (req._graphql && req._graphql.operations && req._graphql.operations.some(op => op.type === 'query'));

    const path = getPathname(req.request.url).toLowerCase();
    const isCheckKeyword = /check|validate|verify|auth|perm|exist|status|search|lookup/.test(path) || isGraphQLCheckKeyword(req);

    return isGetOrGqlQuery && isCheckKeyword;
  };

  // Keep the original workflow-level check-then-act detection behavior, but also anchor
  // findings to individual mutating endpoints.
  let checkThenActDetected = false;
  let checkReq = null;
  let actReq = null;

  // Per-mutation anchored findings
  const anchoredCheckActFindings = [];
  const checkThenActToleranceMs = 100;

  for (let j = 0; j < sortedReqs.length; j++) {
    const reqB = sortedReqs[j];
    if (!isMutatingRequest(reqB)) continue;

    // Search backwards for the closest preceding check-like request.
    // We require that the mutation starts after the check request completes (with tolerance).
    let closestCheck = null;

    for (let i = j - 1; i >= 0; i--) {
      const reqA = sortedReqs[i];
      if (reqA.type === 'unassociated') continue;
      if (!isCheckLikeRequest(reqA)) continue;

      const aStart = new Date(reqA.startedDateTime).getTime();
      const aEnd = aStart + (reqA.time || 0);
      const bStart = new Date(reqB.startedDateTime).getTime();

      if (bStart >= aEnd - checkThenActToleranceMs) {
        closestCheck = reqA;
        break; // nearest preceding qualifying check
      }
    }

    if (!closestCheck) continue;

    // Determine severity anchored to this mutating endpoint
    const isPaymentOrCritical = /pay|checkout|buy|purchase|submit|delete/i.test(reqB.request.url) ||
      (reqB._graphql && reqB._graphql.operations && reqB._graphql.operations.some(op => /pay|checkout|buy|purchase|submit|delete/i.test(op.operationName)));

    const severity = isPaymentOrCritical ? 'high' : 'medium';
    const findingScore = severity === 'high' ? 45 : 30;

    const checkLabel = closestCheck._graphql
      ? `GraphQL: ${closestCheck._graphql.operations[0].operationName}`
      : getPathname(closestCheck.request.url);

    const actLabel = reqB._graphql
      ? `GraphQL: ${reqB._graphql.operations[0].operationName}`
      : `${reqB.request.method} ${getPathname(reqB.request.url)}`;

    anchoredCheckActFindings.push({
      id: 'check-act',
      name: 'Check-then-act Pattern (Anchored to Mutating Endpoint)',
      description: `Potential guard check: \`${checkLabel}\` completed, then mutating \`${actLabel}\` executed.`,
      severity,
      score: findingScore
    });

    // Maintain legacy single-finding behavior for overall workflow summary
    if (!checkThenActDetected) {
      checkThenActDetected = true;
      checkReq = closestCheck;
      actReq = reqB;
    }
  }

  // Add per-mutation findings (can be multiple)
  if (anchoredCheckActFindings.length) {
    anchoredCheckActFindings.forEach(f => {
      findings.push(f);
      score += f.score;
    });
  }

  // Keep legacy single finding too, but avoid double counting if we already added anchored findings
  if (checkThenActDetected && anchoredCheckActFindings.length === 0) {
    const isPaymentOrCritical = /pay|checkout|buy|purchase|submit|delete/i.test(actReq.request.url) ||
      (actReq._graphql && actReq._graphql.operations.some(op => /pay|checkout|buy|purchase|submit|delete/i.test(op.operationName)));

    const severity = isPaymentOrCritical ? 'high' : 'medium';
    const findingScore = severity === 'high' ? 45 : 30;

    const checkLabel = checkReq._graphql ? `GraphQL: ${checkReq._graphql.operations[0].operationName}` : getPathname(checkReq.request.url);
    const actLabel = actReq._graphql ? `GraphQL: ${actReq._graphql.operations[0].operationName}` : `${actReq.request.method} ${getPathname(actReq.request.url)}`;

    findings.push({
      id: 'check-act',
      name: 'Check-then-act Pattern',
      description: `Potential guard check: GET query \`${checkLabel}\` completed, then mutating \`${actLabel}\` executed.`,
      severity,
      score: findingScore
    });
    score += findingScore;
  }

  // 2.5) Racey concurrent mutations on similar guard patterns
  // Detect overlapping/near-concurrent mutations that share similar pathname prefixes (or identical paths)
  // and occur with very short start-to-start gaps. This helps flag when concurrent multi-step flows
  // target the same mutation endpoints.
  const mutatingReqsSorted = [...sortedReqs].filter(isMutatingRequest);
  if (mutatingReqsSorted.length >= 2) {
    // bucket by normalized pathname (without query) to avoid counting unrelated endpoints
    const pathKey = (req) => {
      const p = getPathname(req.request.url).toLowerCase();
      // treat first 3 segments as a coarse grouping key
      const segs = p.split('/').filter(Boolean);
      return segs.slice(0, 3).join('/') || p;
    };

    let raceyPairs = 0;
    for (let k = 1; k < mutatingReqsSorted.length; k++) {
      const prev = mutatingReqsSorted[k - 1];
      const curr = mutatingReqsSorted[k];
      const gap = new Date(curr.startedDateTime).getTime() - new Date(prev.startedDateTime).getTime();
      if (gap >= 0 && gap < 120) {
        if (pathKey(prev) === pathKey(curr)) raceyPairs++;
      }
    }

    if (raceyPairs > 0) {
      const severity = raceyPairs >= 3 ? 'high' : 'medium';
      const findingScore = severity === 'high' ? 55 : 35;
      findings.push({
        id: 'racey-concurrent-mutations',
        name: 'Racey Concurrent Mutations (Same Mutation Surface)',
        description: `Detected ${raceyPairs} near-concurrent mutation requests (start-gap < 120ms) targeting the same mutation path group, suggesting racey concurrent multi-step flows.`,
        severity,
        score: findingScore
      });
      score += findingScore;
    }
  }

  // 3) Cross-Domain/Service Orchestration
  const uniqueHosts = [...new Set(workflow.requests.map(r => getHostname(r.request.url)).filter(Boolean))];

  if (uniqueHosts.length > 1) {
    const severity = uniqueHosts.length > 2 ? 'medium' : 'low';
    const findingScore = severity === 'medium' ? 20 : 10;
    findings.push({
      id: 'cross-domain',
      name: 'Cross-Domain Orchestration',
      description: `Request flows spans ${uniqueHosts.length} distinct service domains: ${uniqueHosts.join(', ')}.`,
      severity,
      score: findingScore
    });
    score += findingScore;
  }

  // 4) Mixed status codes (indicating partial failure / error recovery flows)
  const statuses = workflow.requests.map(r => r.response.status).filter(s => s > 0);
  const hasSuccess = statuses.some(s => s >= 200 && s < 300);
  const hasError = statuses.some(s => s >= 400);
  if (hasSuccess && hasError) {
    const has5xx = statuses.some(s => s >= 500);
    const severity = has5xx ? 'high' : 'medium';
    const findingScore = severity === 'high' ? 40 : 25;
    findings.push({
      id: 'mixed-status',
      name: 'Mixed Status (Unstable Flow)',
      description: `Workflow contains both successful (2xx) and failed (${statuses.filter(s=>s>=400).join(', ')}) status codes, indicating partial transaction failure.`,
      severity,
      score: findingScore
    });
    score += findingScore;
  }

  // 5) Staged polling/readiness loops
  // Count identical endpoints queried multiple times
  const pathCounts = {};
  workflow.requests.forEach(r => {
    const path = getPathname(r.request.url);
    pathCounts[path] = (pathCounts[path] || 0) + 1;
  });
  
  let pollingPath = null;
  let pollingCount = 0;
  for (const [path, count] of Object.entries(pathCounts)) {
    if (count >= 3 && /poll|status|job|progress|ready|wait/i.test(path)) {
      pollingPath = path;
      pollingCount = count;
      break;
    }
  }
  if (pollingCount > 0) {
    findings.push({
      id: 'polling',
      name: 'Staged Polling Loop',
      description: `Detected polling sync behavior: ${pollingCount} requests fired sequentially to status check \`${pollingPath}\`.`,
      severity: 'medium',
      score: 25
    });
    score += 25;
  }

  // 6) Counter/threshold parameters evolving
  const counterKeys = ['limit', 'offset', 'page', 'retry', 'attempt', 'count', 'threshold'];
  let foundCounters = new Set();
  workflow.requests.forEach(r => {
    // Check query params
    r.request.queryString.forEach(q => {
      if (counterKeys.includes(q.name.toLowerCase())) {
        foundCounters.add(q.name.toLowerCase());
      }
    });
    // Check POST data keys if JSON
    if (r._graphql) {
      r._graphql.operations.forEach(op => {
        Object.keys(op.variables || {}).forEach(k => {
          if (counterKeys.some(ck => k.toLowerCase().includes(ck))) {
            foundCounters.add(k.toLowerCase());
          }
        });
      });
    }
  });
  if (foundCounters.size > 0) {
    findings.push({
      id: 'counters',
      name: 'Paging / Threshold Parameters',
      description: `Request payload contains pagination or retry keys: ${Array.from(foundCounters).join(', ')}.`,
      severity: 'low',
      score: 10
    });
    score += 10;
  }

  // 7) Multiple GraphQL Mutations
  let mutationCount = 0;
  workflow.requests.forEach(r => {
    if (r._graphql) {
      r._graphql.operations.forEach(op => {
        if (op.type === 'mutation') mutationCount++;
      });
    }
  });
  if (mutationCount > 1) {
    const severity = mutationCount > 2 ? 'high' : 'medium';
    const findingScore = severity === 'high' ? 35 : 20;
    findings.push({
      id: 'graphql-mutations',
      name: 'Multiple GraphQL Mutations',
      description: `Orchestrated mutation flow: detected ${mutationCount} write operations in a single action cluster.`,
      severity,
      score: findingScore
    });
    score += findingScore;
  }

  // 8) Telemetry alongside core business logic
  const analyticsHosts = ['segment.io', 'mixpanel.com', 'amplitude.com', 'google-analytics.com', 'sentry.io', 'datadog', 'hotjar.com', 'doubleclick'];
  let telemetryCount = 0;
  let coreApiCount = 0;

  workflow.requests.forEach(r => {
    const host = getHostname(r.request.url);
    const isAnalytics = analyticsHosts.some(ah => host.includes(ah)) || /collect|telemetry|track|events|analytics/i.test(r.request.url);
    if (isAnalytics) {
      telemetryCount++;
    } else {
      // API call or fetch
      const isApi = r.request.url.includes('/api/') || r._graphql || r.request.headers.some(h => h.name.toLowerCase() === 'accept' && h.value.includes('json'));
      if (isApi) {
        coreApiCount++;
      }
    }
  });

  if (telemetryCount > 0 && coreApiCount > 0) {
    findings.push({
      id: 'telemetry-mix',
      name: 'Mixed Telemetry and Business Logic',
      description: `Parallel telemetry trigger: ${telemetryCount} logging requests sent simultaneously with ${coreApiCount} core APIs.`,
      severity: 'low',
      score: 10
    });
    score += 10;
  }

  // Determine overall severity
  let finalSeverity = 'none';
  if (findings.some(f => f.severity === 'high')) {
    finalSeverity = 'high';
  } else if (findings.some(f => f.severity === 'medium')) {
    finalSeverity = 'medium';
  } else if (findings.some(f => f.severity === 'low')) {
    finalSeverity = 'low';
  }

  // Filter based on severity threshold
  const thresholdMap = { 'low': 1, 'medium': 2, 'high': 3 };
  const minLevel = thresholdMap[settings.severityThreshold] || 2;

  const filteredFindings = findings.filter(f => {
    const lvl = thresholdMap[f.severity] || 1;
    return lvl >= minLevel;
  });

  workflow.heuristics = filteredFindings;
  workflow.severity = filteredFindings.length > 0 ? finalSeverity : 'none';
  workflow.score = score;

  // Clear previous atomicity traversal results (if any)
  delete workflow.atomicity;
}

/**
 * Update flaw severity based on highest severity flaw finding.
 */
function updateFlawSeverity(workflow) {
  if (!workflow.flaws || workflow.flaws.length === 0) {
    workflow.flawSeverity = 'none';
    return;
  }

  const severityOrder = ['none', 'low', 'medium', 'high'];
  let maxIdx = 0;

  workflow.flaws.forEach(f => {
    const idx = severityOrder.indexOf(f.severity);
    if (idx > maxIdx) maxIdx = idx;
  });

  workflow.flawSeverity = severityOrder[maxIdx];
}

// =========================
// HIGH-ONLY ATOMICITY TRAVERSAL (output/produce anchored)
// =========================

function runHighOnlyAtomicityTraversal(flows) {
  if (!Array.isArray(flows) || flows.length === 0) return;

  const highFlows = flows.filter(f => f && f.severity === 'high');
  if (!highFlows.length) return;

  // For each high flow, compute atomicity anchored to the output/produce (last mutating request)
  highFlows.forEach(flow => {
    flow.atomicity = computeOutputAnchoredAtomicity(flow);
  });
}

function computeOutputAnchoredAtomicity(flow) {
  const requests = Array.isArray(flow.requests) ? flow.requests : [];
  if (requests.length <= 1) {
    return {
      isAtomic: true,
      anchoredOutput: null,
      violations: [],
      reasons: []
    };
  }

  const sortedReqs = [...requests].sort((a, b) => {
    return new Date(a.startedDateTime).getTime() - new Date(b.startedDateTime).getTime();
  });

  const isMutatingRequest = (req) => {
    return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.request.method) ||
      (req._graphql && req._graphql.operations && req._graphql.operations.some(op => op.type === 'mutation'));
  };

  const isCheckLikeRequest = (req) => {
    const isGetOrGqlQuery =
      req.request.method === 'GET' ||
      (req._graphql && req._graphql.operations && req._graphql.operations.some(op => op.type === 'query'));

    const path = getPathname(req.request.url).toLowerCase();
    const isPathCheckKeyword = /check|validate|verify|auth|perm|exist|status|search|lookup/.test(path);

    const isGraphQLCheckKeyword = !!(req._graphql && req._graphql.operations && req._graphql.operations.some(op =>
      /check|validate|verify|auth|perm|exist|status|search|lookup/i.test(op.operationName)
    ));

    return isGetOrGqlQuery && (isPathCheckKeyword || isGraphQLCheckKeyword);
  };

  // Output/produce = last mutating request in the cluster
  let outputReq = null;
  for (let i = sortedReqs.length - 1; i >= 0; i--) {
    if (isMutatingRequest(sortedReqs[i])) {
      outputReq = sortedReqs[i];
      break;
    }
  }

  if (!outputReq) {
    // No mutating request => treat as atomic-ish
    return {
      isAtomic: true,
      anchoredOutput: null,
      violations: [],
      reasons: []
    };
  }

  const outputIdx = sortedReqs.indexOf(outputReq);
  const beforeOutput = sortedReqs.slice(0, outputIdx);

  // Evidence buckets
  const violations = [];
  const reasons = [];

  const outputIsPaymentOrCritical = (() => {
    const url = outputReq.request.url || '';
    const gqlMutName = outputReq._graphql?.operations?.[0]?.operationName || '';
    return /pay|checkout|buy|purchase|submit|delete/i.test(url) || /pay|checkout|buy|purchase|submit|delete/i.test(gqlMutName);
  })();

  // 1) Guard check then act around output
  // If a check-like request exists close enough before output, we flag non-atomicity.
  // Uses time tolerance similar to existing logic (100ms) but relative to output.
  let guardReq = null;
  const outputStart = new Date(outputReq.startedDateTime).getTime();
  const toleranceMs = 100;

  for (let i = beforeOutput.length - 1; i >= 0; i--) {
    const cand = beforeOutput[i];
    if (!isCheckLikeRequest(cand)) continue;
    const candStart = new Date(cand.startedDateTime).getTime();
    const candEnd = candStart + ((cand.time || 0));
    if (outputStart >= candEnd - toleranceMs) {
      guardReq = cand;
      break;
    }
  }

  if (guardReq) {
    violations.push({ id: 'output-check-act', severity: outputIsPaymentOrCritical ? 'high' : 'medium' });
    reasons.push('Found guard/check-like request immediately before the output/produce mutating request.');
  }

  // 2) Polling/readiness loops BEFORE output
  const pathCounts = {};
  beforeOutput.forEach(r => {
    const p = getPathname(r.request.url);
    pathCounts[p] = (pathCounts[p] || 0) + 1;
  });

  const pollingPathEntry = Object.entries(pathCounts).find(
    ([p, count]) => count >= 3 && /poll|status|job|progress|ready|wait/i.test(p)
  );
  const pollingPath = pollingPathEntry ? pollingPathEntry[0] : null;



  if (pollingPath) {
    violations.push({ id: 'output-polling', severity: 'medium' });
    reasons.push(`Detected repeated readiness/polling endpoint (${pollingPath}) before the output/produce request.`);
  }

  // 3) Multi-mutation BEFORE/INCLUDING output
  const mutatingReqs = sortedReqs.filter(isMutatingRequest);
  if (mutatingReqs.length > 1) {
    violations.push({ id: 'output-multiple-mutations', severity: mutatingReqs.length > 2 ? 'high' : 'medium' });
    reasons.push(`Detected ${mutatingReqs.length} mutating requests in the same high cluster; atomicity is unlikely if output depends on earlier writes.`);
  }

  // 4) Racey concurrent mutation patterns in the cluster (already approximated by existing heuristic)
  // Here: if there are multiple mutation reqs with very short start gaps targeting same path-group.
  if (mutatingReqs.length >= 2) {
    const pathKey = (req) => {
      const p = getPathname(req.request.url).toLowerCase();
      const segs = p.split('/').filter(Boolean);
      return segs.slice(0, 3).join('/') || p;
    };

    let raceyPairs = 0;
    for (let k = 1; k < mutatingReqs.length; k++) {
      const prev = mutatingReqs[k - 1];
      const curr = mutatingReqs[k];
      const gap = new Date(curr.startedDateTime).getTime() - new Date(prev.startedDateTime).getTime();
      if (gap >= 0 && gap < 120) {
        if (pathKey(prev) === pathKey(curr)) raceyPairs++;
      }
    }

    if (raceyPairs > 0) {
      violations.push({ id: 'output-racey-concurrent-mutations', severity: raceyPairs >= 3 ? 'high' : 'medium' });
      reasons.push(`Detected ${raceyPairs} near-concurrent mutation requests targeting the same mutation surface before/around the output.`);
    }
  }

  const isAtomic = violations.length === 0;

  const anchoredOutput = {
    label: outputReq._graphql
      ? `GQL(${outputReq._graphql.operations?.[0]?.operationName || 'anonymous'})`
      : `${outputReq.request.method} ${getPathname(outputReq.request.url)}`,
    timestamp: outputReq.startedDateTime
  };

  return { isAtomic, anchoredOutput, violations, reasons };
}


// UI RENDERING: WORKFLOW LIST
function renderWorkflowList() {
  const container = document.getElementById('workflow-list');
  container.innerHTML = '';

  const filtered = workflows.filter(w => {
    if (activeFilters.text === '') return true;
    const query = activeFilters.text.toLowerCase();
    return w.detail.toLowerCase().includes(query) || 
           w.url.toLowerCase().includes(query) || 
           w.requests.some(r => r.request.url.toLowerCase().includes(query));
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; padding: 30px 10px; color: var(--text-dark); font-size: 12px;">
        No events captured matching query.
      </div>`;
    return;
  }

  // Sort workflows: Unassociated group at top, rest chronological (newest first)
  const sorted = [...filtered].sort((a, b) => {
    if (a.id === 'unassociated-group') return -1;
    if (b.id === 'unassociated-group') return 1;
    return b.timestamp - a.timestamp;
  });

  sorted.forEach(w => {
    const item = document.createElement('div');
    item.className = `workflow-item ${w.id === selectedWorkflowId ? 'active' : ''}`;
    item.dataset.id = w.id;
    
    const formattedTime = w.id === 'unassociated-group' ? 'Running' : new Date(w.timestamp).toLocaleTimeString();
    
    // Heuristic pill if has severity
    let severityBadge = '';
    if (w.severity !== 'none') {
      severityBadge = `<span class="severity-indicator severity-${w.severity}">${w.severity}</span>`;
    }
    // Flaw severity pill
    let flawBadge = '';
    if (w.flawSeverity && w.flawSeverity !== 'none') {
      flawBadge = `<span class="severity-indicator severity-${w.flawSeverity}" style="background:rgba(239,68,68,0.08);color:#f87171;border:1px solid rgba(239,68,68,0.15);">🛡️ flaw</span>`;
    }

    item.innerHTML = `
      <div class="item-top">
        <span class="item-type-pill type-${w.type}">${w.type}</span>
        <span class="item-time">${formattedTime}</span>
      </div>
      <div class="item-desc" title="${escapeHtml(w.detail)}">${escapeHtml(w.detail)}</div>
      <div class="item-meta">
        <span class="item-req-count">${w.requests.length} request${w.requests.length === 1 ? '' : 's'}</span>
        ${severityBadge} ${flawBadge}
      </div>
    `;

    item.addEventListener('click', () => selectWorkflow(w.id));
    container.appendChild(item);
  });
}

function selectWorkflow(id) {
  selectedWorkflowId = id;
  renderWorkflowList();
  updateDetailsPane();
}

// UI RENDERING: DETAILS PANE
function updateDetailsPane() {
  const detailsPane = document.getElementById('details-pane');
  const detailsContent = detailsPane.querySelector('.details-content');
  const emptyState = detailsPane.querySelector('.empty-state');

  const workflow = workflows.find(w => w.id === selectedWorkflowId);

  if (!workflow) {
    detailsPane.classList.add('empty');
    detailsContent.style.display = 'none';
    emptyState.style.display = 'flex';
    return;
  }

  detailsPane.classList.remove('empty');
  emptyState.style.display = 'none';
  detailsContent.style.display = 'flex';

  // Set Details Header
  const detailBadge = document.getElementById('detail-badge');
  detailBadge.className = `action-badge type-${workflow.type}`;
  detailBadge.textContent = workflow.type;

  document.getElementById('detail-title').textContent = workflow.detail;
  document.getElementById('detail-time').textContent = `Action Time: ${new Date(workflow.timestamp).toLocaleTimeString()}.${String(workflow.timestamp % 1000).padStart(3, '0')}`;
  document.getElementById('detail-url').textContent = `Page URL: ${workflow.url}`;
  document.getElementById('detail-url').title = workflow.url;

  // Update section tab counts
  const heuristicsCount = document.getElementById('heuristics-count');
  const flawsCount = document.getElementById('flaws-count');
  if (heuristicsCount) heuristicsCount.textContent = workflow.heuristics.length;
  if (flawsCount) flawsCount.textContent = workflow.flaws ? workflow.flaws.length : 0;

  // Apply active section tab
  document.querySelectorAll('.section-tab').forEach(tab => {
    const section = tab.dataset.section;
    tab.classList.toggle('active', section === activeSectionTab);
  });

  // Show/hide section content
  const heuristicsSection = document.getElementById('findings-section-heuristics');
  const flawsSection = document.getElementById('findings-section-flaws');
  if (heuristicsSection) heuristicsSection.style.display = activeSectionTab === 'heuristics' ? 'block' : 'none';
  if (flawsSection) flawsSection.style.display = activeSectionTab === 'flaws' ? 'block' : 'none';

  // Set Heuristic Diagnostics Cards
  const findingsSummary = document.getElementById('findings-summary');
  findingsSummary.innerHTML = '';
  
  if (workflow.heuristics.length === 0) {
    findingsSummary.innerHTML = `
      <div style="background-color: rgba(255,255,255,0.02); border: 1px dashed var(--border-color); padding: 16px; border-radius: 8px; font-size: 12px; color: var(--text-muted); text-align: center;">
        No orchestration heuristics flagged. This workflow looks standard.
      </div>
    `;
  } else {
    workflow.heuristics.forEach(f => {
      const card = document.createElement('div');
      card.className = `finding-card`;
      card.innerHTML = `
        <div class="finding-icon-wrapper finding-icon-${f.severity}">
          ${f.severity === 'high' ? '⚠️' : f.severity === 'medium' ? '⚡' : 'ℹ️'}
        </div>
        <div class="finding-details">
          <h4>${escapeHtml(f.name)}</h4>
          <p>${escapeHtml(f.description)}</p>
        </div>
      `;
      findingsSummary.appendChild(card);
    });
  }

  // Render Logic Flaw Findings
  const flawsSummaryGrid = document.getElementById('flaws-summary-grid');
  const flawsSummaryBar = document.getElementById('flaws-summary-bar');
  
  if (flawsSummaryGrid) {
    flawsSummaryGrid.innerHTML = '';

    if (!workflow.flaws || workflow.flaws.length === 0) {
      flawsSummaryGrid.innerHTML = `
        <div style="background-color: rgba(255,255,255,0.02); border: 1px dashed var(--border-color); padding: 16px; border-radius: 8px; font-size: 12px; color: var(--text-muted); text-align: center;">
          No logic flaws detected in this workflow.
        </div>
      `;
      if (flawsSummaryBar) flawsSummaryBar.style.display = 'none';
    } else {
      if (flawsSummaryBar) {
        flawsSummaryBar.style.display = 'flex';
        document.getElementById('flaws-summary-count').textContent = workflow.flaws.length;
      }

      // Sort flaws by severity (high first)
      const severityOrder = { 'high': 0, 'medium': 1, 'low': 2 };
      const sortedFlaws = [...workflow.flaws].sort((a, b) => {
        const aIdx = severityOrder[a.severity] !== undefined ? severityOrder[a.severity] : 3;
        const bIdx = severityOrder[b.severity] !== undefined ? severityOrder[b.severity] : 3;
        return aIdx - bIdx;
      });

      sortedFlaws.forEach(f => {
        const card = document.createElement('div');
        card.className = `flaw-card severity-${f.severity}`;

        // Category icon
        const catIcon = getFlawCategoryIcon(f.category);

        // Format evidence
        let evidenceHtml = '';
        if (f.evidence) {
          try {
            evidenceHtml = escapeHtml(JSON.stringify(f.evidence, null, 2));
          } catch (_) {
            evidenceHtml = escapeHtml(String(f.evidence));
          }
        }

        card.innerHTML = `
          <div class="flaw-card-icon flaw-cat-${f.category || 'idor'}">${catIcon}</div>
          <div class="flaw-card-body">
            <div class="flaw-card-header">
              <span class="flaw-card-name">${escapeHtml(f.name)}</span>
              <span class="flaw-severity-badge flaw-severity-${f.severity}">${f.severity}</span>
              <span class="flaw-card-category">${escapeHtml(f.category || 'unknown')}</span>
            </div>
            <div class="flaw-card-description">${escapeHtml(f.description)}</div>
            ${evidenceHtml ? `<div class="flaw-card-evidence">${evidenceHtml}</div>` : ''}
            ${f.requestIndex !== undefined ? `<div style="margin-top:6px;font-size:10px;color:var(--text-dark);font-family:var(--font-mono);">Request #${f.requestIndex + 1}</div>` : ''}
          </div>
        `;
        flawsSummaryGrid.appendChild(card);
      });
    }
  }

  // Build Timeline Visualizer
  const timelineContainer = document.getElementById('timeline-container');
  timelineContainer.innerHTML = '';

  if (workflow.requests.length === 0) {
    timelineContainer.innerHTML = `
      <div style="text-align: center; color: var(--text-dark); padding: 20px 0; font-size: 12px;">
        No network requests captured for this action window.
      </div>`;
  } else {
    const sortedReqs = [...workflow.requests].sort((a, b) => {
      return new Date(a.startedDateTime).getTime() - new Date(b.startedDateTime).getTime();
    });

    const startAnchor = workflow.timestamp;
    
    // Find absolute maximum span to fit scale (min 1 second window)
    let maxSpan = 1000;
    sortedReqs.forEach(r => {
      const reqStart = new Date(r.startedDateTime).getTime();
      const reqEnd = reqStart + (r.time || 50);
      const span = reqEnd - startAnchor;
      if (span > maxSpan) maxSpan = span;
    });

    // Add extra padding to maxSpan (10%)
    maxSpan = Math.max(1000, maxSpan * 1.1);

    // Update ruler labels
    const rulerSpans = document.querySelectorAll('.timeline-ruler span');
    rulerSpans[0].textContent = '0s';
    rulerSpans[1].textContent = `${(maxSpan * 0.25 / 1000).toFixed(2)}s`;
    rulerSpans[2].textContent = `${(maxSpan * 0.5 / 1000).toFixed(2)}s`;
    rulerSpans[3].textContent = `${(maxSpan * 0.75 / 1000).toFixed(2)}s`;
    rulerSpans[4].textContent = `${(maxSpan / 1000).toFixed(2)}s+`;

    sortedReqs.forEach((r, idx) => {
      const reqStart = new Date(r.startedDateTime).getTime();
      const delay = Math.max(0, reqStart - startAnchor);
      const duration = r.time || 50;

      const leftPercent = Math.min(95, (delay / maxSpan) * 100);
      const widthPercent = Math.max(1.5, Math.min(100 - leftPercent, (duration / maxSpan) * 100));

      const row = document.createElement('div');
      row.className = 'timeline-row';
      
      const labelText = r._graphql ? `GQL: ${r._graphql.operations[0].operationName}` : getPathname(r.request.url);
      
      // Status class
      let statusClass = 'status-2xx';
      const status = r.response.status;
      if (status >= 500) statusClass = 'status-5xx';
      else if (status >= 400) statusClass = 'status-4xx';
      else if (status >= 300) statusClass = 'status-3xx';
      else if (status === 0) statusClass = 'status-failed';

      row.innerHTML = `
        <div class="timeline-label" title="${escapeHtml(r.request.url)}">${escapeHtml(labelText)}</div>
        <div class="timeline-bar-track">
          <div class="timeline-bar ${statusClass}" 
               style="left: ${leftPercent}%; width: ${widthPercent}%;"
               title="${r.request.method} ${status} (${duration.toFixed(0)}ms, +${delay.toFixed(0)}ms delay)">
          </div>
        </div>
      `;

      // Clicking timeline labels or bars opens request inspector drawer
      row.querySelector('.timeline-label').addEventListener('click', () => inspectRequest(r));
      row.querySelector('.timeline-bar').addEventListener('click', () => inspectRequest(r));

      timelineContainer.appendChild(row);
    });
  }

  // Populate Requests Table
  const tbody = document.getElementById('requests-tbody');
  tbody.innerHTML = '';

  if (workflow.requests.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dark);">No requests loaded.</td></tr>`;
  } else {
    const sortedReqs = [...workflow.requests].sort((a, b) => {
      return new Date(a.startedDateTime).getTime() - new Date(b.startedDateTime).getTime();
    });

    sortedReqs.forEach(r => {
      const row = document.createElement('tr');
      row.addEventListener('click', () => inspectRequest(r));

      const status = r.response.status;
      let statusStyle = 'success';
      if (status >= 400) statusStyle = 'danger';
      else if (status >= 300) statusStyle = 'warning';
      else if (status === 0) statusStyle = 'muted';

      const methodClass = `method-${r.request.method.toLowerCase()}`;
      const pathText = r._graphql ? `[GraphQL] ${r._graphql.operations[0].operationName}` : getPathname(r.request.url);
      const delay = Math.max(0, new Date(r.startedDateTime).getTime() - workflow.timestamp);
      
      const sizeText = r.response.bodySize > 0 
        ? `${(r.response.bodySize / 1024).toFixed(1)} KB` 
        : r.response.content && r.response.content.size > 0 
          ? `${(r.response.content.size / 1024).toFixed(1)} KB` 
          : '0 KB';

      row.innerHTML = `
        <td class="method-cell ${methodClass}">${r.request.method}</td>
        <td class="path-cell" title="${escapeHtml(r.request.url)}">${escapeHtml(pathText)}</td>
        <td class="status-cell ${statusStyle}">${status || 'Failed'}</td>
        <td class="delay-cell">+${delay.toFixed(0)}ms</td>
        <td class="duration-cell">${(r.time || 0).toFixed(0)}ms</td>
        <td class="size-cell">${sizeText}</td>
      `;

      tbody.appendChild(row);
    });
  }
}

// INSPECT SINGLE REQUEST (Drawer View)
function inspectRequest(request) {
  const drawer = document.getElementById('request-inspector-drawer');
  drawer.classList.add('open');

  // Fill URL
  document.getElementById('inspect-url').textContent = request.request.url;

  // Fill Headers
  let reqHeadersStr = '';
  request.request.headers.forEach(h => {
    reqHeadersStr += `${h.name}: ${h.value}\n`;
  });
  document.getElementById('inspect-req-headers').textContent = reqHeadersStr || 'No request headers';

  let resHeadersStr = '';
  request.response.headers.forEach(h => {
    resHeadersStr += `${h.name}: ${h.value}\n`;
  });
  document.getElementById('inspect-res-headers').textContent = resHeadersStr || 'No response headers';

  // Fill Payload
  let payloadStr = 'No request payload';
  if (request.request.postData && request.request.postData.text) {
    try {
      const parsed = JSON.parse(request.request.postData.text);
      payloadStr = JSON.stringify(parsed, null, 2);
    } catch(e) {
      payloadStr = request.request.postData.text;
    }
  }
  document.getElementById('inspect-payload').textContent = payloadStr;

  // Fill Response Body (HAR content requires async fetching via getContent in Chrome DevTools)
  const responseCodeBox = document.getElementById('inspect-response');
  responseCodeBox.textContent = 'Loading response content...';
  
  if (request.getContent) {
    request.getContent((content, encoding) => {
      if (!content) {
        responseCodeBox.textContent = 'No response body returned or failed to load.';
        return;
      }
      try {
        const parsed = JSON.parse(content);
        responseCodeBox.textContent = JSON.stringify(parsed, null, 2);
      } catch(e) {
        responseCodeBox.textContent = content.substring(0, 10000) + (content.length > 10000 ? '\n... (truncated)' : '');
      }
    });
  } else {
    // Fallback for mock/offline testing
    if (request.response.content && request.response.content.text) {
      const content = request.response.content.text;
      try {
        const parsed = JSON.parse(content);
        responseCodeBox.textContent = JSON.stringify(parsed, null, 2);
      } catch(e) {
        responseCodeBox.textContent = content;
      }
    } else {
      responseCodeBox.textContent = 'Response body not captured in this context.';
    }
  }

  // GraphQL Tab handling
  const gqlTabBtn = document.getElementById('graphql-tab-btn');
  if (request._graphql) {
    gqlTabBtn.style.display = 'block';
    
    // Fill GraphQL values (taking first operation from batched/single)
    const op = request._graphql.operations[0];
    const typeBadge = document.getElementById('inspect-graphql-type');
    typeBadge.textContent = op.type;
    typeBadge.className = `badge type-${op.type === 'mutation' ? 'submit' : 'click'}`;
    
    document.getElementById('inspect-graphql-name').textContent = op.operationName;
    document.getElementById('inspect-graphql-vars').textContent = JSON.stringify(op.variables, null, 2);
    document.getElementById('inspect-graphql-query').textContent = op.query;
  } else {
    gqlTabBtn.style.display = 'none';
    // If active tab was GraphQL, switch back to headers
    const activeTab = document.querySelector('.tab-btn.active');
    if (activeTab && activeTab.id === 'graphql-tab-btn') {
      switchTab('headers');
    }
  }
}

// Close Inspector Drawer
function closeDrawer() {
  document.getElementById('request-inspector-drawer').classList.remove('open');
}

// Tab Switching logic
function switchTab(tabName) {
  const tabs = document.querySelectorAll('.tab-btn');
  const contents = document.querySelectorAll('.tab-content');

  tabs.forEach(t => {
    if (t.dataset.tab === tabName) t.classList.add('active');
    else t.classList.remove('active');
  });

  contents.forEach(c => {
    if (c.id === `tab-${tabName}`) c.classList.add('active');
    else c.classList.remove('active');
  });
}

// Modal handling
function openModal(id) {
  document.getElementById(id).classList.add('open');
}

function closeModal(id) {
  document.getElementById(id).classList.remove('open');
}

// Clear all history
function clearLogs() {
  workflows = [];
  selectedWorkflowId = null;
  renderWorkflowList();
  updateDetailsPane();
  closeDrawer();
  console.log('[Workflow Detector] History cleared.');
}

// Export captured workflows as JSON
function exportData() {
  if (workflows.length === 0) {
    alert('No workflows recorded yet.');
    return;
  }

  // Clean objects from extension functions for serializing
  const exportable = workflows.map(w => {
    return {
      type: w.type,
      detail: w.detail,
      timestamp: w.timestamp,
      url: w.url,
      severity: w.severity,
      score: w.score,
      heuristics: w.heuristics,
      requestsCount: w.requests.length,
      requests: w.requests.map(r => ({
        url: r.request.url,
        method: r.request.method,
        status: r.response.status,
        time: r.time,
        startedDateTime: r.startedDateTime,
        graphql: r._graphql || null
      }))
    };
  });

  const blob = new Blob([JSON.stringify(exportable, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = `workflow-detector-export-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Setup Event Listeners
function setupUIEventListeners() {
  // Clear button
  document.getElementById('clear-btn').addEventListener('click', clearLogs);

  // Export button
  document.getElementById('export-btn').addEventListener('click', exportData);

  // Settings button
  document.getElementById('settings-btn').addEventListener('click', () => {
    updateSettingsUI();
    openModal('settings-modal');
  });

  // Modal actions
  document.getElementById('close-settings').addEventListener('click', () => closeModal('settings-modal'));
  document.getElementById('save-settings-btn').addEventListener('click', saveSettings);

  // Tab events in inspector drawer
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      switchTab(e.target.dataset.tab);
    });
  });

  // Close inspector drawer
  document.getElementById('close-drawer-btn').addEventListener('click', closeDrawer);

  // Search filter
  document.getElementById('search-input').addEventListener('input', (e) => {
    activeFilters.text = e.target.value;
    renderWorkflowList();
  });

  // Section Tab switching (Heuristics vs Flaws)
  document.querySelectorAll('.section-tab').forEach(tab => {
    tab.addEventListener('click', (e) => {
      const section = e.currentTarget.dataset.section;
      if (section) {
        activeSectionTab = section;
        updateDetailsPane();
      }
    });
  });

  // Import modal + dashboard actions
  setupImportUI();
}

// =========================
// IMPORT / UPLOAD ANALYZER
// =========================

function setupImportUI() {
  const importModal = document.getElementById('import-modal');
  const closeImport = document.getElementById('close-import');
  const browseBtn = document.getElementById('browse-btn');
  const fileInput = document.getElementById('import-file-input');
  const dropZone = document.getElementById('import-drop-zone');
  const importError = document.getElementById('import-error');
  const importBtn = document.getElementById('import-btn');

  if (!importModal || !closeImport || !browseBtn || !fileInput || !dropZone || !importError) {
    console.warn('[Workflow Detector] Import UI elements missing; skipping import setup.');
    return;
  }

  if (importBtn) {
    importBtn.addEventListener('click', () => {
      importError.style.display = 'none';
      fileInput.value = '';
      openModal('import-modal');
    });
  }

  closeImport.addEventListener('click', () => closeModal('import-modal'));

  browseBtn.addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    await analyzeUploadedFile(file);
  });

  // Drag and drop
  const prevent = (ev) => {
    ev.preventDefault();
    ev.stopPropagation();
  };

  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, prevent);
  });

  dropZone.addEventListener('drop', async (ev) => {
    prevent(ev);
    const file = ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0];
    if (!file) return;
    await analyzeUploadedFile(file);
  });

  // Dashboard: return to live mode
  const closeDashboardBtn = document.getElementById('close-dashboard-btn');
  if (closeDashboardBtn) {
    closeDashboardBtn.addEventListener('click', () => {
      isImportedMode = false;
      closeModal('import-modal');
      document.getElementById('dashboard-state').style.display = 'none';
      detailsPaneToEmpty();
    });
  }
}

function detailsPaneToEmpty() {
  // Return to live sidebar/details state without forcing workflow selection.
  const detailsPane = document.getElementById('details-pane');
  const detailsContent = detailsPane.querySelector('.details-content');
  const emptyState = detailsPane.querySelector('.empty-state');

  detailsPane.classList.add('empty');
  detailsContent.style.display = 'none';
  emptyState.style.display = 'flex';

  // Hide dashboard
  const dashboardState = document.getElementById('dashboard-state');
  if (dashboardState) dashboardState.style.display = 'none';
}

async function analyzeUploadedFile(file) {
  const importError = document.getElementById('import-error');
  const fileName = file.name || 'uploaded-file';

  try {
    importError.style.display = 'none';
    importError.textContent = '';

    const text = await file.text();
    const isHar = fileName.toLowerCase().endsWith('.har');

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      throw new Error('Uploaded file is not valid JSON.');
    }

    let flows;
    if (isHar || (parsed && parsed.log && Array.isArray(parsed.log.entries))) {
      flows = parseHarToFlows(parsed);
    } else {
      flows = parseScytheOrEndpointJsonToFlows(parsed);
    }

    // Run atomicity analysis + heuristic validations
    isImportedMode = true;
    importedFilename = fileName;

    // Replace current workflows with imported flows for UI compatibility
    workflows = flows;
    selectedWorkflowId = null;

    // Ensure a fresh atomicity traversal ONLY for HIGH workflows
    runHighOnlyAtomicityTraversal(flows);

    // Compute and render dashboard
    renderAtomicityDashboard(flows);


    // Swap UI into dashboard state
    document.getElementById('dashboard-state').style.display = 'block';
    const subtitle = document.getElementById('dashboard-subtitle');
    if (subtitle) subtitle.textContent = `File: ${fileName}`;

    closeModal('import-modal');

    // Render sidebar list for imported flows too
    renderWorkflowList();
    updateDetailsPane();

  } catch (err) {
    console.error('[Workflow Detector] Import analysis failed:', err);
    importError.textContent = err && err.message ? err.message : String(err);
    importError.style.display = 'block';
  }
}

function parseScytheOrEndpointJsonToFlows(json) {
  // Supports BOTH:
  // - array: [{method,url,...}, ...]
  // - object: { endpoints:[...] }
  // - scythe export: [{ type, detail, timestamp, requests:[...] }, ...]

  const now = Date.now();

  // If it looks like Scythe export
  if (Array.isArray(json) && json.length && json[0] && (json[0].requests || json[0].heuristics)) {
    return json.map((w, idx) => normalizeImportedWorkflow(w, idx, now));
  }

  if (json && json.workflows && Array.isArray(json.workflows)) {
    return json.workflows.map((w, idx) => normalizeImportedWorkflow(w, idx, now));
  }

  const endpoints = Array.isArray(json) ? json : (json && Array.isArray(json.endpoints) ? json.endpoints : null);
  if (!endpoints) {
    // If it is a HAR-like object, fall back to HAR parser
    if (json && json.log && Array.isArray(json.log.entries)) return parseHarToFlows(json);
    throw new Error('Unsupported JSON format for endpoint upload. Expected HAR or an endpoints array/object.');
  }

  // Each endpoint is treated as its own request; we need flows/clusters.
  // Heuristic clustering: group consecutive endpoints into a flow when URLs share a common base path OR time gap is small.
  const requests = endpoints.map((ep, i) => normalizeEndpointToRequest(ep, i));

  const flows = [];
  let current = {
    id: generateId(),
    type: 'imported',
    detail: 'Imported endpoint sequence',
    timestamp: now + iota(0),
    requests: [],
    heuristics: [],
    severity: 'none',
    score: 0
  };

  for (let i = 0; i < requests.length; i++) {
    const r = requests[i];
    const prev = current.requests[current.requests.length - 1];

    if (!prev) {
      current.requests.push(r);
      continue;
    }

    const prevTime = new Date(prev.startedDateTime).getTime();
    const currTime = new Date(r.startedDateTime).getTime();
    const timeGap = Math.abs(currTime - prevTime);

    const prevPath = getPathname(prev.request.url);
    const currPath = getPathname(r.request.url);

    const shouldCluster = timeGap <= settings.associationWindow || prevPath.split('/').slice(0,2).join('/') === currPath.split('/').slice(0,2).join('/');

    if (shouldCluster) {
      current.requests.push(r);
    } else {
      flows.push(finalizeImportedWorkflow(current));
      current = {
        id: generateId(),
        type: 'imported',
        detail: 'Imported endpoint sequence',
        timestamp: now + iota(flows.length + 1),
        requests: [r],
        heuristics: [],
        severity: 'none',
        score: 0
      };
    }
  }

  if (current.requests.length) flows.push(finalizeImportedWorkflow(current));

  return flows;
}

function iota(n) {
  // deterministic tiny offset
  return n * 10;
}

function normalizeImportedWorkflow(w, idx, now) {
  const workflow = {
    id: w.id || `imported-${idx}`,
    type: w.type || 'imported',
    detail: w.detail || 'Imported workflow',
    timestamp: typeof w.timestamp === 'number' ? w.timestamp : (now + idx * 50),
    requests: [],
    heuristics: [],
    severity: w.severity || 'none',
    score: w.score || 0
  };

  // If it already has requests in scythe export shape
  if (Array.isArray(w.requests)) {
    workflow.requests = w.requests.map((r, i) => normalizeRequestShim(r, i));
  }

  return finalizeImportedWorkflow(workflow);
}

function normalizeEndpointToRequest(ep, idx) {
  const url = ep.url || ep.endpoint || ep.path || '';
  const method = (ep.method || ep.httpMethod || 'GET').toUpperCase();

  const graphql = ep.graphql || (ep.type && ep.query ? { type: ep.type, operationName: ep.operationName || 'anonymous', variables: ep.variables || {}, query: ep.query } : null);

  // For our heuristics engine compatibility we create a request shim that looks like DevTools requestFinished object
  const startedDateTime = typeof ep.startedDateTime === 'number'
    ? ep.startedDateTime
    : (typeof ep.time === 'number' ? (Date.now() - (endOffsetFromDuration(ep.time) + idx)) : Date.now() + idx);

  const status = typeof ep.status === 'number' ? ep.status : (typeof ep.responseStatus === 'number' ? ep.responseStatus : 200);

  return {
    request: {
      method,
      url,
      headers: Array.isArray(ep.headers) ? ep.headers : [],
      queryString: Array.isArray(ep.queryString) ? ep.queryString : (Array.isArray(ep.query) ? ep.query : []),
      postData: ep.body ? { text: typeof ep.body === 'string' ? ep.body : JSON.stringify(ep.body) } : (ep.postData || null)
    },
    response: {
      status,
      headers: Array.isArray(ep.responseHeaders) ? ep.responseHeaders : [],
      bodySize: ep.bodySize || 0,
      content: ep.content || null
    },
    time: typeof ep.time === 'number' ? ep.time : 50,
    startedDateTime: new Date(startedDateTime).toISOString(),
    _graphql: graphql
  };
}

function endOffsetFromDuration(ms) {
  return Math.max(0, ms);
}

function normalizeRequestShim(r, i) {
  // Compatible with our export schema from exportData() in this repo.
  return {
    request: {
      url: r.url || '',
      method: (r.method || 'GET').toUpperCase(),
      headers: [],
      queryString: [],
      postData: null
    },
    response: {
      status: r.status || 200,
      headers: [],
      bodySize: 0,
      content: null
    },
    time: typeof r.time === 'number' ? r.time : 50,
    startedDateTime: r.startedDateTime || new Date(Date.now() + i * 10).toISOString(),
    _graphql: r.graphql || null
  };
}

function finalizeImportedWorkflow(w) {
  // Convert any request shims missing startedDateTime/time/status
  if (!Array.isArray(w.requests)) w.requests = [];

  // Ensure request shape minimal compatibility for heuristics
  w.requests.forEach(req => {
    if (!req.startedDateTime) req.startedDateTime = new Date().toISOString();
    if (!req.time) req.time = 50;
    if (!req.response) req.response = { status: 200 };
    if (!req.request) req.request = { method: 'GET', url: '' };
    if (!req.request.method) req.request.method = 'GET';
    if (!req.request.url) req.request.url = '';
    if (!req.request.headers) req.request.headers = [];
    if (!req.request.queryString) req.request.queryString = [];
  });

  // Run heuristics to populate findings
  runHeuristics(w);

  // Run logic flaw detection on imported workflow
  w.flaws = detectFlaws(w);
  updateFlawSeverity(w);

  return w;
}

function parseHarToFlows(har) {
  // HAR has log.entries; we create best-effort flows by time gaps.
  const entries = (har && har.log && Array.isArray(har.log.entries)) ? har.log.entries : [];
  if (!entries.length) throw new Error('HAR file contains no entries.');

  const now = Date.now();
  const flows = [];

  const sorted = [...entries].sort((a, b) => {
    const aT = new Date(a.startedDateTime || now).getTime();
    const bT = new Date(b.startedDateTime || now).getTime();
    return aT - bT;
  });

  let current = {
    id: generateId(),
    type: 'imported-har',
    detail: 'HAR imported flow',
    timestamp: new Date(sorted[0].startedDateTime || now).getTime(),
    requests: [],
    heuristics: [],
    severity: 'none',
    score: 0
  };

  for (let i = 0; i < sorted.length; i++) {
    const e = sorted[i];
    const r = harEntryToRequestShim(e);

    const prev = current.requests[current.requests.length - 1];
    if (!prev) {
      current.requests.push(r);
      continue;
    }

    const prevT = new Date(prev.startedDateTime).getTime();
    const currT = new Date(r.startedDateTime).getTime();
    const gap = Math.abs(currT - prevT);

    if (gap <= settings.associationWindow) {
      current.requests.push(r);
    } else {
      flows.push(finalizeImportedWorkflow(current));
      current = {
        id: generateId(),
        type: 'imported-har',
        detail: 'HAR imported flow',
        timestamp: new Date(e.startedDateTime || now).getTime(),
        requests: [r],
        heuristics: [],
        severity: 'none',
        score: 0
      };
    }
  }

  if (current.requests.length) flows.push(finalizeImportedWorkflow(current));

  return flows;
}

function harEntryToRequestShim(entry) {
  const url = entry.request && entry.request.url ? entry.request.url : '';
  const method = (entry.request && entry.request.method ? entry.request.method : 'GET').toUpperCase();

  const headers = (entry.request && Array.isArray(entry.request.headers)) ? entry.request.headers : [];

  const responseStatus = entry.response && typeof entry.response.status === 'number' ? entry.response.status : 200;
  const bodySize = entry.response && typeof entry.response.bodySize === 'number' ? entry.response.bodySize : 0;

  // HAR has queryString separately sometimes; DevTools heuristics uses request.queryString array.
  const queryString = [];
  if (entry.request && Array.isArray(entry.request.queryString)) {
    entry.request.queryString.forEach(q => {
      if (q && typeof q.name === 'string') queryString.push({ name: q.name, value: q.value });
    });
  }

  // HAR postData
  let postData = null;
  if (entry.request && entry.request.postData && entry.request.postData.text) {
    postData = { text: entry.request.postData.text };
  }

  // Minimal startedDateTime iso
  const startedDateTime = entry.startedDateTime || new Date().toISOString();

  // Duration from HAR entry (ms)
  const time = typeof entry.timings && typeof entry.timings.wait === 'number'
    ? entry.timings.wait
    : (typeof entry.time === 'number' ? entry.time : 50);

  return {
    request: {
      method,
      url,
      headers,
      queryString,
      postData
    },
    response: {
      status: responseStatus,
      headers: (entry.response && Array.isArray(entry.response.headers)) ? entry.response.headers : [],
      bodySize,
      content: null
    },
    time,
    startedDateTime,
    _graphql: null
  };
}

function renderAtomicityDashboard(flows) {
  const metricAtomicity = document.getElementById('metric-atomicity-score');
  const metricTotalFlows = document.getElementById('metric-total-flows');
  const metricNonAtomic = document.getElementById('metric-non-atomic');
  const metricViolations = document.getElementById('metric-violations');
  const patternsList = document.getElementById('dashboard-patterns-list');
  const recTbody = document.getElementById('recommendations-tbody');

  if (!metricAtomicity || !metricTotalFlows || !metricNonAtomic || !metricViolations || !patternsList || !recTbody) {
    console.warn('[Workflow Detector] Atomicity dashboard containers missing; cannot render dashboard.');
    return;
  }

  const totalFlows = flows.length;
  let atomicCount = 0;
  let nonAtomic = 0;
  let violations = 0;

  const highFlows = flows.filter(f => f && f.severity === 'high');
  const atomicitiesHigh = highFlows.map(f => f.atomicity).filter(Boolean);
  const highTotal = highFlows.length;
  let highChecked = 0;
  let highAtomicCount = 0;
  let highNonAtomic = 0;
  let highViolations = 0;


  const patternCounts = {};

  // Count findings by heuristic id
  flows.forEach(f => {
    const atomicInfo = f && f.atomicity;
    const isAtomic = atomicInfo && typeof atomicInfo.isAtomic === 'boolean'
      ? atomicInfo.isAtomic
      : (f.requests.length === 1);

    if (isAtomic) atomicCount++;
    else nonAtomic++;

    const heur = f.heuristics || [];
    if (heur.length > 0) violations++;

    heur.forEach(h => {
      patternCounts[h.id] = (patternCounts[h.id] || 0) + 1;
    });
  });

  // HIGH-only metrics for the “atomicity update” pass
  highFlows.forEach(f => {
    highChecked++;
    const a = f.atomicity;
    if (a && a.isAtomic) highAtomicCount++;
    else highNonAtomic++;

    if (a && a.violations && a.violations.length > 0) highViolations++;
  });

  const atomicityScore = totalFlows > 0 ? Math.round((atomicCount / totalFlows) * 100) : 0;
  const highAtomicityScore = highTotal > 0 ? Math.round((highAtomicCount / highTotal) * 100) : 0;

  metricAtomicity.textContent = `${highAtomicityScore}% (high)`;
  metricTotalFlows.textContent = `${totalFlows}`;
  metricNonAtomic.textContent = `${highNonAtomic}/${highTotal}`;
  metricViolations.textContent = `${highViolations} high violations`;


  // Render pattern prevalence
  const patterns = Object.entries(patternCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  patternsList.innerHTML = '';

  if (!patterns.length) {
    patternsList.innerHTML = `
      <div style="text-align:center;color:var(--text-muted);font-size:12px;padding:12px;">No orchestration patterns detected in uploaded endpoints.</div>
    `;
  } else {
    patterns.forEach(([pid, count]) => {
      const pct = totalFlows ? Math.round((count / totalFlows) * 100) : 0;
      patternsList.innerHTML += `
        <div class="chart-row" style="margin: 10px 0;">
          <div class="chart-label" style="display:flex;justify-content:space-between;font-size:12px;color:var(--text-muted);">
            <span>${escapeHtml(pid)}</span>
            <span>${pct}%</span>
          </div>
          <div class="chart-bar" style="height:10px;background:rgba(255,255,255,0.06);border-radius:999px;overflow:hidden;margin-top:6px;">
            <div style="height:100%;width:${Math.min(100, pct)}%;background:linear-gradient(90deg,var(--color-primary),rgba(59,130,246,0.6));"></div>
          </div>
        </div>
      `;
    });
  }

  // Recommendations: show non-atomic HIGH flows (based on output-anchored atomicity traversal)
  const nonAtomicFlows = highFlows
    .filter(f => {
      const a = f.atomicity;
      if (a && typeof a.isAtomic === 'boolean') return !a.isAtomic;
      return f.requests.length > 1;
    })
    .sort((a, b) => (b.score || 0) - (a.score || 0));

  recTbody.innerHTML = '';

  if (!nonAtomicFlows.length) {
    recTbody.innerHTML = `
      <tr>
        <td colspan="3" style="text-align:center;color:var(--text-muted);font-size:12px;">All flows look atomic (single request).</td>
      </tr>
    `;
    return;
  }

  nonAtomicFlows.slice(0, 10).forEach(f => {
    const endpointsSeq = f.requests.map(r => {
      const label = r._graphql ? `GQL(${r._graphql.operations?.[0]?.operationName || 'anonymous'})` : `${(r.request.method || 'GET')} ${getPathname(r.request.url || '')}`;
      return label;
    }).join('  →  ');

    const patterns = (f.heuristics || []).map(h => h.name).join(', ') || 'No heuristic findings';

    const recommendation = suggestConsolidationRecommendation(f);

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td title="${escapeHtml(endpointsSeq)}">${escapeHtml(truncate(endpointsSeq, 120))}</td>
      <td>${escapeHtml(truncate(patterns, 90))}</td>
      <td>${escapeHtml(recommendation)}</td>
    `;
    recTbody.appendChild(tr);
  });
}

function suggestConsolidationRecommendation(flow) {
  const heur = flow.heuristics || [];
  const hasCheckAct = heur.some(h => h.id === 'check-act');
  const hasPolling = heur.some(h => h.id === 'polling');
  const hasFanout = heur.some(h => h.id === 'fanout');
  const hasGraphMut = heur.some(h => h.id === 'graphql-mutations');

  if (hasCheckAct) {
    return 'Consolidate guard-check + mutation into a single backend endpoint that enforces authorization/validation server-side, returning the final state in one round trip.';
  }
  if (hasPolling) {
    return 'Replace staged polling with an async job pattern that returns a final state/callback, or provide a single endpoint that returns readiness immediately.';
  }
  if (hasGraphMut) {
    return 'Batch GraphQL mutations server-side (single mutation/request) to avoid multi-write orchestration from the client.';
  }
  if (hasFanout) {
    return 'Where possible, collapse fan-out reads/writes into a composed endpoint (server-side aggregation) to reduce request cascades.';
  }
  return 'Consider consolidating the endpoint sequence into a single atomic backend operation to reduce orchestration and failure modes.';
}

function truncate(str, n) {
  if (!str) return '';
  return str.length > n ? str.slice(0, n - 1) + '…' : str;
}



// HTML Escaping Utility
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Get emoji icon for a flaw category.
 */
function getFlawCategoryIcon(category) {
  const icons = {
    'idor': '\uD83D\uDD11',
    'parameter-tampering': '\uD83D\uDCB0',
    'auth-escalation': '\uD83D\uDEC2',
    'mass-assignment': '\uD83D\uDCE6',
    'process-bypass': '\uD83D\uDD04',
    'input-validation': '\uD83D\uDCDD',
    'race-condition': '\uD83C\uDFCE\uFE0F',
    'deserialization': '\uD83D\uDC7E',
    'file-parser-vulns': '\uD83D\uDCC4',
    'auth-bypass-state-manip': '\uD83D\uDD12',
    'prototype-pollution': '\uD83E\uDD16',
    'memory-web-context': '\uD83E\uDDE0'
  };
  return icons[category] || '\u26A0\uFE0F';
}
