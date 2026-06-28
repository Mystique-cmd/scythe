// Test Bench JS: Simulates various user interaction and network request patterns

document.addEventListener('DOMContentLoaded', () => {
  setupConsole();
  setupClickListeners();
});

function setupConsole() {
  const clearBtn = document.getElementById('clear-console');
  clearBtn.addEventListener('click', () => {
    const log = document.getElementById('console-log');
    log.innerHTML = `<div class="log-line"><span class="log-timestamp">[System]</span> Console cleared. Ready.</div>`;
  });
}

function logToConsole(message, type = 'info') {
  const consoleLog = document.getElementById('console-log');
  const line = document.createElement('div');
  line.className = 'log-line';
  
  const timestamp = new Date().toLocaleTimeString() + '.' + String(Date.now() % 1000).padStart(3, '0');
  
  line.innerHTML = `<span class="log-timestamp">[${timestamp}]</span> <span class="log-${type}">${message}</span>`;
  consoleLog.appendChild(line);
  consoleLog.scrollTop = consoleLog.scrollHeight;
}

// Helper: safe fetch that reports to console and runs fallback if offline
async function safeFetch(url, options = {}, label = '') {
  const method = options.method || 'GET';
  logToConsole(`Launching request: ${method} ${label || url}...`, 'info');
  
  try {
    const response = await fetch(url, options);
    if (response.ok) {
      logToConsole(`Success: ${method} ${label || url} returned Status ${response.status}`, 'success');
      return response;
    } else {
      logToConsole(`Error response: ${method} ${label || url} returned Status ${response.status}`, 'error');
      return response;
    }
  } catch (error) {
    logToConsole(`Network failure: ${method} ${label || url} failed (${error.message})`, 'error');
    // Fallback to local files if httpbin fails/offline
    if (url.startsWith('https://httpbin.org/')) {
      logToConsole(`Attempting local fallback for ${label || url}...`, 'warning');
      const fallbackUrl = getLocalFallbackUrl(url);
      try {
        const fbRes = await fetch(fallbackUrl, {
          ...options,
          method: 'GET' // Chrome only allows GET to extension files
        });
        logToConsole(`Fallback success: GET ${fallbackUrl} returned Status ${fbRes.status}`, 'success');
        return fbRes;
      } catch (fbErr) {
        logToConsole(`Fallback failed: ${fbErr.message}`, 'error');
      }
    }
    throw error;
  }
}

// Fallback mapper for offline mode
function getLocalFallbackUrl(url) {
  if (url.includes('/status/500')) {
    return 'mock_responses/non_existent_file_triggering_404.json';
  }
  if (url.includes('/post')) {
    return 'mock_responses/check_permissions.json?fallback=post_action';
  }
  return 'mock_responses/config.json';
}

function setupClickListeners() {
  // Scenario 1: Parallel Burst (Sequential Fan-out)
  document.getElementById('btn-fanout').addEventListener('click', async () => {
    logToConsole('--- SCENARIO: Parallel Burst (Fan-out) ---', 'info');
    
    // Fire 3 fetches in parallel
    const p1 = safeFetch('mock_responses/users.json', {}, 'users.json');
    const p2 = safeFetch('mock_responses/items.json', {}, 'items.json');
    const p3 = safeFetch('mock_responses/config.json', {}, 'config.json');
    
    await Promise.all([p1, p2, p3]);
    logToConsole('Scenario 1 finished.', 'success');
  });

  // Scenario 2: Check-Then-Act
  document.getElementById('btn-checkact').addEventListener('click', async () => {
    logToConsole('--- SCENARIO: Check-Then-Act ---', 'info');
    
    // Step A: GET verification
    const verifyRes = await safeFetch('mock_responses/check_permissions.json?action=validate_permissions', {}, 'check_permissions.json');
    
    if (verifyRes) {
      logToConsole('Permissions check complete. Simulating 300ms processing delay...', 'info');
      await new Promise(resolve => setTimeout(resolve, 300));
      
      // Step B: Mutating POST
      await safeFetch('https://httpbin.org/post', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'checkout_buy', user: 'user_dev_881' })
      }, 'POST /api/checkout/buy');
    }
    
    logToConsole('Scenario 2 finished.', 'success');
  });

  // Scenario 3: Multi-Domain Sync
  document.getElementById('btn-crossdomain').addEventListener('click', async () => {
    logToConsole('--- SCENARIO: Multi-Domain Sync ---', 'info');
    
    // Fire to local extension, external API, and telemetry host
    await safeFetch('mock_responses/config.json', {}, 'config.json (local)');
    
    try {
      await safeFetch('https://httpbin.org/get?domain=partner-identity', {}, 'httpbin.org (remote)');
    } catch(e) {}

    await safeFetch('mock_responses/analytics.json?event=sync', {}, 'analytics.json (telemetry)');
    
    logToConsole('Scenario 3 finished.', 'success');
  });

  // Scenario 4: GraphQL Checkout (Multiple Mutations)
  document.getElementById('btn-graphql').addEventListener('click', async () => {
    logToConsole('--- SCENARIO: GraphQL Checkout ---', 'info');
    
    // Mutation 1: createCart
    await safeFetch('https://httpbin.org/post?op=createCart', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: 'mutation createCart($id: ID!) { createCart(id: $id) { id total } }',
        variables: { id: '99281' },
        operationName: 'createCart'
      })
    }, 'GraphQL: createCart');

    logToConsole('Cart created. Firing second mutation...', 'info');
    await new Promise(resolve => setTimeout(resolve, 150));

    // Mutation 2: submitPayment
    await safeFetch('https://httpbin.org/post?op=submitPayment', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: 'mutation submitPayment($cartId: ID!, $amount: Float!) { submitPayment(cartId: $cartId, amount: $amount) { success transactionId } }',
        variables: { cartId: '99281', amount: 249.99 },
        operationName: 'submitPayment'
      })
    }, 'GraphQL: submitPayment');
    
    logToConsole('Scenario 4 finished.', 'success');
  });

  // Scenario 5: Faulty Transaction (Mixed Status)
  document.getElementById('btn-mixed').addEventListener('click', async () => {
    logToConsole('--- SCENARIO: Faulty Transaction ---', 'info');
    
    // Call 1: Success (200 OK)
    await safeFetch('mock_responses/users.json', {}, 'users.json');
    
    // Call 2: Failure (500 Error / 404 Fallback)
    try {
      await safeFetch('https://httpbin.org/status/500', {}, 'status/500 (remote error)');
    } catch(e) {}
    
    logToConsole('Scenario 5 finished.', 'success');
  });

  // Scenario 6: Staged Polling Loop
  document.getElementById('btn-polling').addEventListener('click', async () => {
    logToConsole('--- SCENARIO: Staged Polling Loop ---', 'info');
    
    // Start job
    await safeFetch('https://httpbin.org/post?action=export_pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ job: 'export_pdf' })
    }, 'POST /api/jobs/export');

    // Poll 1: Pending
    await new Promise(resolve => setTimeout(resolve, 300));
    await safeFetch('mock_responses/job_status_pending.json?attempt=1', {}, 'job_status_pending.json?attempt=1');

    // Poll 2: Pending
    await new Promise(resolve => setTimeout(resolve, 300));
    await safeFetch('mock_responses/job_status_pending.json?attempt=2', {}, 'job_status_pending.json?attempt=2');

    // Poll 3: Completed
    await new Promise(resolve => setTimeout(resolve, 300));
    await safeFetch('mock_responses/job_status_complete.json?attempt=3', {}, 'job_status_complete.json?attempt=3');
    
    logToConsole('Scenario 6 finished.', 'success');
  });
}
