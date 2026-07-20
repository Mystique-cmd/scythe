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

// Helper: fixture-only fetch that reports to console.
// NOTE: The test bench is intentionally offline/deterministic for real extension behavior.
async function safeFetch(url, options = {}, label = '') {
  const method = options.method || 'GET';

  // Hard guard: never allow cross-origin / external network calls from the bench.
  if (/^https?:\/\//i.test(url) || url.startsWith('chrome://') || url.startsWith('file://')) {
    logToConsole(`Blocked external request from test bench: ${method} ${label || url}`, 'error');
    return Promise.reject(new Error('External requests are disabled in the Test Bench.'));
  }

  logToConsole(`Launching request: ${method} ${label || url}...`, 'info');

  const response = await fetch(url, options);
  if (response.ok) {
    logToConsole(`Success: ${method} ${label || url} returned Status ${response.status}`, 'success');
  } else {
    logToConsole(`Error response: ${method} ${label || url} returned Status ${response.status}`, 'error');
  }

  return response;
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

  // Scenario 1.5: Concurrent Check-Then-Act (mutation concurrency simulation)
  document.getElementById('btn-concurrent-checkact').addEventListener('click', async () => {
    logToConsole('--- SCENARIO: Concurrent Check-Then-Act (Racey Mutation Concurrency) ---', 'info');

    const concurrency = 3; // keep deterministic and reasonably fast

    const oneGuardedFlow = async (flowIndex) => {
      // Step A: GET verification (fixture)
      await safeFetch(
        `mock_responses/check_permissions.json?action=validate_permissions&flow=${flowIndex}`,
        {},
        `flow-${flowIndex} GET check_permissions`
      );

      // jitter inside the flow to encourage interleaving across concurrent flows
      await new Promise(resolve => setTimeout(resolve, 100 + flowIndex * 35));

      // Step B: Mutating POST (fixture-based simulated endpoint)
      await safeFetch(
        `mock_responses/check_permissions.json?fallback=post_action&flow=${flowIndex}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'checkout_buy', user: `user_dev_881_flow_${flowIndex}` })
        },
        `flow-${flowIndex} POST checkout_buy (fixture)`
      );
    };

    // Run multiple guarded flows concurrently
    const all = [];
    for (let i = 0; i < concurrency; i++) {
      all.push(oneGuardedFlow(i));
    }

    await Promise.all(all);
    logToConsole('Scenario 1.5 finished.', 'success');
  });

  // Scenario 2: Check-Then-Act
  document.getElementById('btn-checkact').addEventListener('click', async () => {
    logToConsole('--- SCENARIO: Check-Then-Act ---', 'info');
    
    // Step A: GET verification (fixture)
    const verifyRes = await safeFetch('mock_responses/check_permissions.json?action=validate_permissions', {}, 'check_permissions.json');
    
    if (verifyRes) {
      logToConsole('Permissions check complete. Simulating 300ms processing delay...', 'info');
      await new Promise(resolve => setTimeout(resolve, 300));
      
      // Step B: Mutating POST (fixture-based simulated endpoint)
      await safeFetch('mock_responses/check_permissions.json?fallback=post_action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'checkout_buy', user: 'user_dev_881' })
      }, 'POST /api/checkout/buy (fixture)');
    }
    
    logToConsole('Scenario 2 finished.', 'success');
  });


  // Scenario 3: Multi-Domain Sync (fixture-only)
  document.getElementById('btn-crossdomain').addEventListener('click', async () => {
    logToConsole('--- SCENARIO: Multi-Domain Sync (fixture-only) ---', 'info');

    // Fire to multiple fixture endpoints
    await safeFetch('mock_responses/config.json', {}, 'config.json');
    await new Promise(resolve => setTimeout(resolve, 80));
    await safeFetch('mock_responses/users.json', {}, 'users.json');
    await new Promise(resolve => setTimeout(resolve, 80));
    await safeFetch('mock_responses/analytics.json?event=sync', {}, 'analytics.json');

    logToConsole('Scenario 3 finished.', 'success');
  });


  // Scenario 4: GraphQL Checkout (fixture-only)
  document.getElementById('btn-graphql').addEventListener('click', async () => {
    logToConsole('--- SCENARIO: GraphQL Checkout (fixture-only) ---', 'info');

    // The real extension detects GraphQL by parsing request bodies captured by DevTools.
    // The test bench does not generate actual GraphQL network calls (offline mode),
    // but we still hit multiple JSON fixtures representing payloads.
    await safeFetch('mock_responses/items.json', {}, 'GraphQL fixture: createCart (represented)');

    logToConsole('Cart created. Firing second mutation...', 'info');
    await new Promise(resolve => setTimeout(resolve, 120));

    await safeFetch('mock_responses/check_permissions.json', {}, 'GraphQL fixture: submitPayment (represented)');

    logToConsole('Scenario 4 finished.', 'success');
  });


  // Scenario 5: Faulty Transaction (Mixed Status) - fixture-only
  document.getElementById('btn-mixed').addEventListener('click', async () => {
    logToConsole('--- SCENARIO: Faulty Transaction (fixture-only) ---', 'info');

    // Call 1: Success (fixture)
    await safeFetch('mock_responses/users.json', {}, 'users.json');

    // Call 2: Failure (simulate error by requesting a non-existing fixture)
    // This will still be captured as a failing network request by DevTools.
    try {
      await safeFetch('mock_responses/__missing_fixture__.json', {}, 'missing fixture (expected 404)');
    } catch (e) {
      // expected
    }

    logToConsole('Scenario 5 finished.', 'success');
  });


  // Scenario 6: Staged Polling Loop - fixture-only
  document.getElementById('btn-polling').addEventListener('click', async () => {
    logToConsole('--- SCENARIO: Staged Polling Loop (fixture-only) ---', 'info');

    // Start job (fixture)
    await safeFetch('mock_responses/job_status_pending.json?start=1', {}, 'start job (fixture)');

    // Poll 1: Pending
    await new Promise(resolve => setTimeout(resolve, 250));
    await safeFetch('mock_responses/job_status_pending.json?attempt=1', {}, 'job_status_pending.json?attempt=1');

    // Poll 2: Pending
    await new Promise(resolve => setTimeout(resolve, 250));
    await safeFetch('mock_responses/job_status_pending.json?attempt=2', {}, 'job_status_pending.json?attempt=2');

    // Poll 3: Completed
    await new Promise(resolve => setTimeout(resolve, 250));
    await safeFetch('mock_responses/job_status_complete.json?attempt=3', {}, 'job_status_complete.json?attempt=3');

    logToConsole('Scenario 6 finished.', 'success');
  });

  // =============================
  // LOGIC FLAW SCENARIOS
  // =============================

  // Flaw 1: IDOR - Sequential Object IDs
  document.getElementById('btn-flaw-idor').addEventListener('click', async () => {
    logToConsole('--- FLAW SCENARIO: IDOR Sequential IDs ---', 'info');

    // Simulate requests to /api/users/1001, /api/users/1002, /api/users/1003
    // These fetch the same fixture but the path structure triggers IDOR detection
    await safeFetch('mock_responses/users.json', {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    }, 'GET /api/users/1001');
    await new Promise(resolve => setTimeout(resolve, 80));

    await safeFetch('mock_responses/users.json', {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    }, 'GET /api/users/1002');
    await new Promise(resolve => setTimeout(resolve, 80));

    await safeFetch('mock_responses/users.json', {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    }, 'GET /api/users/1003');

    // Also simulate a mutation with missing auth header to match IDOR-no-auth pattern
    await safeFetch('mock_responses/check_permissions.json', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: 1001, action: 'update_profile' })
    }, 'POST /api/admin/users/1001 (no auth)');

    logToConsole('IDOR flaw scenario finished.', 'success');
  });

  // Flaw 2: Parameter Tampering - Price Manipulation
  document.getElementById('btn-flaw-param-tamper').addEventListener('click', async () => {
    logToConsole('--- FLAW SCENARIO: Parameter Tampering (Price) ---', 'info');

    // Checkout with negative price and zero quantity
    await safeFetch('mock_responses/check_permissions.json?fallback=checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        productId: 42,
        price: -50.00,
        quantity: 0,
        discount: -100,
        total: -150.00
      })
    }, 'POST /api/checkout (negative price + zero qty)');

    logToConsole('Parameter tamper flaw scenario finished.', 'success');
  });

  // Flaw 3: Auth Privilege Escalation
  document.getElementById('btn-flaw-auth').addEventListener('click', async () => {
    logToConsole('--- FLAW SCENARIO: Privilege Escalation ---', 'info');

    // Registration with client-supplied admin role
    await safeFetch('mock_responses/users.json', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'attacker',
        email: 'attacker@example.com',
        password: 'password123',
        role: 'admin',
        isAdmin: true,
        isPremium: true,
        permissions: ['read', 'write', 'admin']
      })
    }, 'POST /api/register (client-supplied role=admin)');

    logToConsole('Privilege escalation flaw scenario finished.', 'success');
  });

  // Flaw 4: Mass Assignment
  document.getElementById('btn-flaw-mass-assign').addEventListener('click', async () => {
    logToConsole('--- FLAW SCENARIO: Mass Assignment ---', 'info');

    // Profile update with protected internal fields
    await safeFetch('mock_responses/users.json', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'John Doe',
        email: 'john@example.com',
        isVerified: true,
        isAdmin: true,
        balance: 999999,
        credit_limit: 1000000,
        role: 'admin',
        account_balance: 500000,
        internalNotes: 'Approved for special access',
        approved: true
      })
    }, 'PUT /api/users/profile (mass assignment)');

    logToConsole('Mass assignment flaw scenario finished.', 'success');
  });

  // Flaw 5: Business Process Bypass
  document.getElementById('btn-flaw-process-bypass').addEventListener('click', async () => {
    logToConsole('--- FLAW SCENARIO: Process Bypass (Payment Without Cart) ---', 'info');

    // Direct payment without any cart or checkout steps
    await safeFetch('mock_responses/check_permissions.json?fallback=payment', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        amount: 199.99,
        currency: 'USD',
        card: '4111111111111111',
        billing: { address: '123 Victim Ln' },
        paymentMethod: 'credit_card'
      })
    }, 'POST /api/payment (no cart/checkout step)');

    logToConsole('Process bypass flaw scenario finished.', 'success');
  });

  // Flaw 6: Injection Patterns
  document.getElementById('btn-flaw-injection').addEventListener('click', async () => {
    logToConsole('--- FLAW SCENARIO: Injection Patterns ---', 'info');

    // Login with SQL injection in email and NoSQL operator in password
    await safeFetch('mock_responses/users.json', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: "' OR '1'='1' --",
        password: '{\"$ne\": \"\"}',
        username: "1=1--"
      })
    }, 'POST /api/login (SQL + NoSQL injection)');

    logToConsole('Injection flaw scenario finished.', 'success');
  });

  // Flaw 7: Race Condition TOCTOU
  document.getElementById('btn-flaw-race').addEventListener('click', async () => {
    logToConsole('--- FLAW SCENARIO: Race Condition (TOCTOU) ---', 'info');

    // Step A: Check balance (GET verification)
    await safeFetch('mock_responses/check_permissions.json?check=balance', {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    }, 'GET /api/check-balance');

    // Large delay creating a wide TOCTOU window (600ms)
    logToConsole('TOCTOU window: 600ms gap between check and mutation...', 'warning');
    await new Promise(resolve => setTimeout(resolve, 600));

    // Step B: Withdraw mutation (POST)
    await safeFetch('mock_responses/check_permissions.json?fallback=withdraw', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountId: 5001,
        amount: 10000,
        currency: 'USD'
      })
    }, 'POST /api/withdraw (600ms after balance check)');

    logToConsole('Race condition flaw scenario finished.', 'success');
  });

}
