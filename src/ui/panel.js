// DevTools Panel JS: Handles sessionization, heuristic evaluation, timeline rendering, and user interaction

// Global State
let workflows = [];
let selectedWorkflowId = null;
let activeFilters = { text: '' };

// Settings State
let settings = {
  associationWindow: 2500, // ms
  severityThreshold: 'medium', // 'low', 'medium', 'high'
  preserveLog: true
};

// Background connection
let backgroundPageConnection = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  setupConnection();
  setupUIEventListeners();
  renderWorkflowList();
  updateDetailsPane();
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
  workflows.forEach(w => runHeuristics(w));
  renderWorkflowList();
  if (selectedWorkflowId) {
    updateDetailsPane();
  }
  
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

  // Listen to user actions from the content script via background.js
  backgroundPageConnection.onMessage.addListener((message) => {
    if (message.type === 'USER_ACTION') {
      handleUserAction(message.action);
    }
  });

  // Listen to network requests from the inspected window (built-in DevTools API)
  chrome.devtools.network.onRequestFinished.addListener((request) => {
    handleNetworkRequest(request);
  });

  // Reset log on navigation if preserveLog is false
  chrome.devtools.network.onNavigated.addListener((url) => {
    console.log('[Workflow Detector] Navigated to:', url);
    if (!settings.preserveLog) {
      clearLogs();
    } else {
      // Add a navigation record to mark the flow
      handleUserAction({
        type: 'navigation',
        detail: `Navigated to ${new URL(url).pathname}`,
        timestamp: Date.now(),
        url: url
      });
    }
  });
}

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
    severity: 'none',
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
      severity: 'none',
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

  // 2) Check-then-act sequence
  // Find a GET (read/check) followed by a mutating request (POST, PUT, DELETE or GraphQL mutation)
  // where the mutation starts AFTER the GET is fully completed.
  let checkThenActDetected = false;
  let checkReq = null;
  let actReq = null;

  for (let i = 0; i < sortedReqs.length; i++) {
    const reqA = sortedReqs[i];
    const isGet = reqA.request.method === 'GET' || (reqA._graphql && reqA._graphql.operations.some(op => op.type === 'query'));
    
    // Check keywords in path
    const pathA = getPathname(reqA.request.url).toLowerCase();
    const isCheckKeyword = /check|validate|verify|auth|perm|exist|status|search|lookup/.test(pathA) ||
                           (reqA._graphql && reqA._graphql.operations.some(op => /check|validate|verify|auth|perm|exist|status|search|lookup/i.test(op.operationName)));
    
    if (isGet && isCheckKeyword) {
      const aStart = new Date(reqA.startedDateTime).getTime();
      const aEnd = aStart + (reqA.time || 0);

      // Look for a subsequent mutating action that started after A completed
      for (let j = i + 1; j < sortedReqs.length; j++) {
        const reqB = sortedReqs[j];
        const isMutating = ['POST', 'PUT', 'DELETE'].includes(reqB.request.method) || (reqB._graphql && reqB._graphql.operations.some(op => op.type === 'mutation'));
        
        // Skip if same query (not a mutation)
        if (reqB.request.method === 'GET') continue;

        const bStart = new Date(reqB.startedDateTime).getTime();
        
        if (isMutating && bStart >= aEnd) {
          checkThenActDetected = true;
          checkReq = reqA;
          actReq = reqB;
          break;
        }
      }
    }
    if (checkThenActDetected) break;
  }

  if (checkThenActDetected) {
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

    item.innerHTML = `
      <div class="item-top">
        <span class="item-type-pill type-${w.type}">${w.type}</span>
        <span class="item-time">${formattedTime}</span>
      </div>
      <div class="item-desc" title="${escapeHtml(w.detail)}">${escapeHtml(w.detail)}</div>
      <div class="item-meta">
        <span class="item-req-count">${w.requests.length} request${w.requests.length === 1 ? '' : 's'}</span>
        ${severityBadge}
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

  // Open Test Bench
  const testBenchHandler = () => {
    const testBenchUrl = chrome.runtime.getURL('src/ui/test_bench.html');
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.create({ url: testBenchUrl });
    } else {
      window.open(testBenchUrl);
    }
  };
  
  document.getElementById('open-test-bench').addEventListener('click', testBenchHandler);
  document.getElementById('trigger-sample-btn').addEventListener('click', testBenchHandler);
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
