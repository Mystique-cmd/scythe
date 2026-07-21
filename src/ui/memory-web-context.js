/**
 * Memory-Related Issues in Web Context Detection Engine
 *
 * Analyzes workflows and individual requests for memory-related vulnerabilities
 * in web applications and browser contexts:
 *   - DOM Clobbering via HTML Responses (id/name collisions with dangerous properties)
 *   - Cache Poisoning / Web Cache Deception (cache header manipulation, cache key abuse)
 *   - Client-Side Storage Manipulation (localStorage/sessionStorage payload injection)
 *   - Memory Exhaustion via Deeply Nested Objects (deep JSON, large arrays, zip bombs)
 *   - Service Worker Cache Pollution (precache abuse, stale cache serving)
 *   - Detached DOM / Large Payload Generation (massive HTML, repeated DOM creation)
 *   - Cross-Window / Tab Memory Leak (window.open leaks, postMessage accumulation)
 *   - WebSocket Connection Abuse (unclosed connections, message flooding)
 *   - IndexedDB / Storage API Abuse (excessive DB creation, storage event abuse)
 *   - Event Listener / Timer Leak Indicators (orphaned intervals, listener accumulation)
 */

// =========================
// PUBLIC INTERFACE
// =========================

/**
 * Run all memory/web context detectors against a workflow.
 * Returns an array of flaw findings compatible with the existing flaws engine.
 */
export function detectMemoryWebContext(workflow) {
  if (!workflow || !Array.isArray(workflow.requests) || workflow.requests.length === 0) {
    return [];
  }

  const sortedReqs = [...workflow.requests].sort((a, b) => {
    return new Date(a.startedDateTime).getTime() - new Date(b.startedDateTime).getTime();
  });

  const findings = [];

  // Run each detector
  detectDOMClobbering(sortedReqs, findings);
  detectCachePoisoning(sortedReqs, findings);
  detectClientSideStorageManipulation(sortedReqs, findings);
  detectMemoryExhaustNestedObjects(sortedReqs, findings);
  detectServiceWorkerCachePollution(sortedReqs, findings);
  detectDetachedDOMLargePayload(sortedReqs, findings);
  detectCrossWindowMemoryLeak(sortedReqs, findings);
  detectWebSocketConnectionAbuse(sortedReqs, findings);
  detectIndexedDBStorageAbuse(sortedReqs, findings);
  detectEventListenerTimerLeak(sortedReqs, findings);

  return findings;
}

// =========================
// UTILITY HELPERS
// =========================

function getPathname(url) {
  try { return new URL(url).pathname; } catch (_) { return url || ''; }
}

function getHostname(url) {
  try { return new URL(url).host; } catch (_) { return ''; }
}

function isMutatingRequest(req) {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.request && req.request.method) ||
    (req._graphql && req._graphql.operations && req._graphql.operations.some(op => op.type === 'mutation'));
}

function getRequestBodyText(req) {
  if (req.request && req.request.postData && req.request.postData.text) {
    return req.request.postData.text;
  }
  return null;
}

function tryParseJSON(str) {
  if (!str) return null;
  try { return JSON.parse(str); } catch (_) { return null; }
}

function getAllParams(req) {
  const params = {};

  // Query string
  if (req.request && Array.isArray(req.request.queryString)) {
    req.request.queryString.forEach(q => {
      if (q.name) params[q.name] = q.value;
    });
  }

  // URL search params from full URL
  try {
    const url = new URL(req.request.url);
    url.searchParams.forEach((val, key) => {
      params[key] = val;
    });
  } catch (_) {}

  // POST body
  const bodyText = getRequestBodyText(req);
  if (bodyText) {
    const parsed = tryParseJSON(bodyText);
    if (parsed && typeof parsed === 'object') {
      Object.keys(parsed).forEach(k => {
        params[k] = parsed[k];
      });
    }
  }

  // GraphQL variables
  if (req._graphql && req._graphql.operations) {
    req._graphql.operations.forEach(op => {
      if (op.variables && typeof op.variables === 'object') {
        Object.keys(op.variables).forEach(vk => {
          params[vk] = op.variables[vk];
        });
      }
    });
  }

  return params;
}

function getHeaderValue(req, headerName) {
  if (!req.request || !Array.isArray(req.request.headers)) return null;
  const h = req.request.headers.find(hdr => (hdr.name || '').toLowerCase() === headerName.toLowerCase());
  return h ? h.value : null;
}

function getAllHeaderValues(req) {
  if (!req.request || !Array.isArray(req.request.headers)) return [];
  return req.request.headers.map(h => ({ name: h.name, value: h.value }));
}

/**
 * Deep scan an object for a given key.
 * Returns array of paths where the key is found.
 */
function deepFindKey(obj, targetKey, path = '', maxDepth = 8) {
  const results = [];
  if (!obj || typeof obj !== 'object' || maxDepth <= 0) return results;

  Object.keys(obj).forEach(k => {
    const currentPath = path ? `${path}.${k}` : k;

    if (k === targetKey) {
      results.push({ path: currentPath, value: obj[k] });
    }

    if (obj[k] && typeof obj[k] === 'object') {
      results.push(...deepFindKey(obj[k], targetKey, currentPath, maxDepth - 1));
    }
  });

  return results;
}

// =========================
// CONSTANTS
// =========================

// Dangerous DOM properties that can be clobbered by HTML id/name attributes
const DANGEROUS_DOM_PROPERTIES = [
  'innerHTML', 'outerHTML', 'textContent', 'innerText',
  'cookie', 'location', 'href', 'src',
  'origin', 'protocol', 'host', 'hostname', 'pathname', 'search', 'hash',
  'constructor', '__proto__', 'prototype',
  'onerror', 'onload', 'onclick', 'onmouseover', 'onsubmit',
  'value', 'checked', 'disabled', 'selected', 'selectedIndex',
  'name', 'id', 'className', 'classList', 'style',
  'form', 'action', 'method', 'target',
  'defaultView', 'parent', 'top', 'self', 'window', 'frames',
  'document', 'head', 'body', 'title', 'forms', 'images', 'links',
  'nextSibling', 'previousSibling', 'parentNode', 'childNodes',
  'firstChild', 'lastChild', 'children', 'offsetParent',
  'offsetTop', 'offsetLeft', 'offsetWidth', 'offsetHeight',
  'scrollTop', 'scrollLeft', 'scrollWidth', 'scrollHeight',
  'dataset', 'attributes', 'styleSheets',
  'contentType', 'characterSet', 'charset', 'baseURI',
  'all', 'embeds', 'plugins', 'scripts', 'stylesheets'
];

// Clobberable HTML element tags and their name patterns
const DOM_CLOBBER_HTML_PATTERNS = [
  // <a> tag with name attribute
  { pattern: /<a\s[^>]*name=["'](?:innerHTML|cookie|location|constructor|__proto__)["']/i, severity: 'high', tag: '<a name=...>' },
  // <form> with name/id matching dangerous properties
  { pattern: /<form\s[^>]*(?:id|name)=["'](?:innerHTML|cookie|location|constructor|__proto__)["']/i, severity: 'high', tag: '<form id/name=...>' },
  // <img> with name attribute
  { pattern: /<img\s[^>]*name=["'](?:innerHTML|cookie|location|constructor|__proto__)["']/i, severity: 'high', tag: '<img name=...>' },
  // <embed> with name attribute
  { pattern: /<embed\s[^>]*name=["'](?:innerHTML|cookie|location|constructor|__proto__)["']/i, severity: 'high', tag: '<embed name=...>' },
  // <object> with name attribute
  { pattern: /<object\s[^>]*name=["'](?:innerHTML|cookie|location|constructor|__proto__)["']/i, severity: 'high', tag: '<object name=...>' },
  // Any element with id matching dangerous properties
  { pattern: /id=["'](?:innerHTML|cookie|location|constructor|__proto__|value|name)["']/i, severity: 'high', tag: 'id= dangerous property' },
  // <script> with dangerous id
  { pattern: /<script\s[^>]*id=["'](?:innerHTML|cookie|location|constructor|__proto__)["']/i, severity: 'high', tag: '<script id=...>' },
  // <iframe> with name matching dangerous
  { pattern: /<iframe\s[^>]*name=["'](?:innerHTML|cookie|location|constructor|__proto__)["']/i, severity: 'high', tag: '<iframe name=...>' }
];

// Cache directive patterns indicating potential poisoning / deception
const CACHE_POISONING_HEADER_PATTERNS = {
  dangerous: [
    { pattern: /public/i, description: 'Cache set to public — may cache authenticated responses' },
    { pattern: /no-store/i, description: 'no-store present but contradictory public directive may cause cache confusion' }
  ],
  deceptive: [
    { pattern: /max-age=\s*(\d+)/i, extract: true, maxAgeThreshold: 86400, description: 'Excessive max-age (>24h) increases cache poisoning window' },
    { pattern: /s-maxage=\s*(\d+)/i, extract: true, maxAgeThreshold: 3600, description: 'CDN/proxy cache TTL is very long (>1h) — stale content could be served' },
    { pattern: /stale-while-revalidate=\s*(\d+)/i, extract: true, maxAgeThreshold: 86400, description: 'stale-while-revalidate is excessively long' }
  ]
};

// Cache key manipulation parameter names
const CACHE_KEY_PARAMS = [
  'cb', 'cache_buster', 'cacheBuster', 'cache-buster',
  't', 'timestamp', 'ts', '_', 'nocache', 'no-cache',
  'refresh', 'reload', 'v', 'ver', 'version',
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'
];

// Known cache poisoning / web cache deception endpoints
const CACHE_DECEPTION_ENDPOINTS = [
  /\.css$/i, /\.js$/i, /\.png$/i, /\.jpg$/i, /\.gif$/i, /\.svg$/i,
  /\.ico$/i, /\.woff2?$/i, /\.eot$/i, /\.ttf$/i, /\.pdf$/i,
  /\/static\//i, /\/assets\//i, /\/public\//i, /\/dist\//i,
  /\/cdn\//i, /\/cache\//i
];

// Storage API-related parameter names
const STORAGE_MANIPULATION_PARAMS = [
  'localStorage', 'local_storage', 'localstorage',
  'sessionStorage', 'session_storage', 'sessionstorage',
  'setItem', 'set_item', 'getItem', 'get_item',
  'removeItem', 'remove_item', 'clear',
  'storage', 'store', 'cache', 'persist',
  'key', 'keys', 'value', 'values', 'data', 'payload',
  'prefix', 'namespace', 'scope', 'quota'
];

// Suspect storage payload patterns
const STORAGE_PAYLOAD_PATTERNS = [
  /localStorage\.setItem\s*\(/i,
  /sessionStorage\.setItem\s*\(/i,
  /window\.localStorage/i,
  /window\.sessionStorage/i,
  /storage\.setItem/i,
  /__storage__/i,
  /store\.set/i,
  /persist\.save/i,
  /cache\.put/i
];

// XSS/gadget injection via storage
const STORAGE_INJECTION_PATTERNS = [
  /<script/i, /<img/i, /<svg/i, /<iframe/i,
  /onerror=/i, /onload=/i, /onclick=/i,
  /javascript:/i, /data:text\/html/i,
  /eval\(/i, /Function\(/i, /setTimeout\(/i, /setInterval\(/i,
  /document\.write/i, /innerHTML/i, /outerHTML/i,
  /__proto__/i, /constructor\.prototype/i
];

// Service worker related endpoint patterns
const SW_ENDPOINT_PATTERNS = [
  /service.?worker/i, /sw\.js/i, /worker\.js/i,
  /precache/i, /cache.?worker/i,
  /push.?worker/i, /sync.?worker/i,
  /\/sw/i, /\/workers\//i
];

// Large payload / memory exhaustion thresholds
const MEMORY_EXHAUSTION_THRESHOLDS = {
  jsonNestingDepth: 12,        // Max safe JSON nesting depth
  jsonArrayLength: 5000,       // Max array elements before flagging
  responseBodySizeMB: 10,      // Max response body size in MB
  stringFieldLength: 100000,   // Max single string field length
  objectPropertyCount: 500,    // Max object property count
  repeatedElements: 100,       // Max repeated elements in array
  compressionRatio: 100        // Uncompressed/compressed ratio threshold
};

// Cross-window communication parameter patterns
const CROSS_WINDOW_PARAMS = [
  'windowName', 'window_name', 'target', 'popup', 'childWindow',
  'opener', 'postMessage', 'post_message',
  'messageChannel', 'message_channel',
  'broadcastChannel', 'broadcast_channel',
  'sharedWorker', 'shared_worker',
  'onmessage', 'addEventListener', 'message',
  'origin', 'source', 'ports'
];

// WebSocket related patterns
const WEBSOCKET_PATTERNS = [
  /ws:\/\//i, /wss:\/\//i,
  /websocket/i, /socket\.io/i, /sockjs/i,
  /upgrade:\s*websocket/i,
  /Sec-WebSocket-/i,
  /\/ws\//i, /\/wss\//i, /\/socket\//i, /\/sock\//i,
  /long.?poll/i, /polling/i, /stream/i
];

// IndexedDB related patterns
const INDEXED_DB_PARAMS = [
  'indexedDB', 'indexed_db', 'indexeddb',
  'idb', 'dbName', 'db_name', 'databaseName',
  'objectStore', 'object_store', 'storeName',
  'createObjectStore', 'create_object_store',
  'put', 'add', 'delete', 'clear', 'getAll',
  'transaction', 'openCursor', 'open_index',
  'version', 'onupgradeneeded', 'oncomplete',
  'database', 'databases', 'collection'
];

// Event listener / timer leak patterns
const EVENT_LISTENER_PATTERNS = [
  /addEventListener\s*\(/i,
  /removeEventListener/i,
  /setInterval\s*\(/i,
  /setTimeout\s*\(/i,
  /clearInterval/i,
  /clearTimeout/i,
  /attachEvent/i,
  /detachEvent/i,
  /on\w+\s*=\s*function/i,
  /\.on(?:click|load|error|submit|change|focus|blur|scroll|resize|keyup|keydown|mousedown|mouseup|mousemove)\s*=/i
];

// Orphaned listener patterns (added but never removed)
const ORPHANED_LISTENER_INDICATORS = [
  /window\.addEventListener/i,
  /document\.addEventListener/i,
  /body\.addEventListener/i,
  /window\.on\w+/i,
  /document\.on\w+/i
];

// =========================
// DETECTOR 1: DOM CLOBBERING VIA HTML RESPONSES
// =========================
/**
 * Detect DOM Clobbering via HTML Responses:
 * - HTML elements with id/name colliding with dangerous DOM properties (innerHTML, cookie, location)
 * - <a name="cookie">, <form id="innerHTML">, <img name="constructor"> patterns
 * - Nested clobbering via descendant forms and anchors
 * - SVG/MathML elements with clobbering attributes
 */
function detectDOMClobbering(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    // Only check HTML responses
    const headers = getAllHeaderValues(req);
    const contentType = headers.find(h => h.name.toLowerCase() === 'content-type');
    const contentTypeVal = contentType ? (contentType.value || '') : '';
    const isHtml = /text\/html|application\/xhtml\+xml/i.test(contentTypeVal);

    // Check if response content is available
    let responseBody = null;
    if (req.response && req.response.content && req.response.content.text) {
      responseBody = req.response.content.text;
    }

    if (!responseBody && !isHtml) {
      // Also check request body for clobbering payloads
      responseBody = getRequestBodyText(req);
    }

    if (!responseBody) return;

    const path = getPathname(req.request && req.request.url);
    const clobberFindings = [];

    // 1. Check for DOM clobbering HTML patterns
    DOM_CLOBBER_HTML_PATTERNS.forEach(patternEntry => {
      const matches = responseBody.match(new RegExp(patternEntry.pattern.source, 'gi'));
      if (matches) {
        matches.forEach(match => {
          // Extract the dangerous property name
          const propMatch = match.match(/name=["']([^"']+)["']|id=["']([^"']+)["']/i);
          const propName = (propMatch && (propMatch[1] || propMatch[2])) || 'unknown';
          clobberFindings.push({
            type: 'dom-clobber-html',
            tag: patternEntry.tag,
            property: propName,
            snippet: match.substring(0, 100),
            severity: patternEntry.severity
          });
        });
      }
    });

    // 2. Check for form ancestors with name set to dangerous properties
    // Forms with id="innerHTML" + descendant input results in window.innerHTML being the form
    const formClobberMatches = responseBody.match(/<form\s[^>]*(?:id|name)=["'](\w+)["'][^>]*>[\s\S]*?<\/form>/gi);
    if (formClobberMatches) {
      formClobberMatches.forEach(formHtml => {
        const idMatch = formHtml.match(/(?:id|name)=["'](\w+)["']/i);
        if (idMatch) {
          const formId = idMatch[1];
          if (DANGEROUS_DOM_PROPERTIES.some(dp => dp.toLowerCase() === formId.toLowerCase())) {
            // Check if form has named descendant elements (inputs, buttons, etc.)
            const namedChildren = formHtml.match(/<input\s[^>]*name=["']\w+["']|<button\s[^>]*name=["']\w+["']|<textarea\s[^>]*name=["']\w+["']/gi);
            if (namedChildren) {
              clobberFindings.push({
                type: 'dom-clobber-form-ancestor',
                tag: '<form>',
                property: formId,
                childCount: namedChildren.length,
                severity: 'high',
                snippet: formHtml.substring(0, 150)
              });
            }
          }
        }
      });
    }

    // 3. Check for <a> tags with name attribute clobbering
    const anchorClobberMatches = responseBody.match(/<a\s[^>]*name=["'](\w+)["'][^>]*>/gi);
    if (anchorClobberMatches) {
      anchorClobberMatches.forEach(match => {
        const nameMatch = match.match(/name=["'](\w+)["']/i);
        if (nameMatch) {
          const name = nameMatch[1];
          if (DANGEROUS_DOM_PROPERTIES.some(dp => dp.toLowerCase() === name.toLowerCase())) {
            clobberFindings.push({
              type: 'dom-clobber-anchor',
              tag: '<a name=...>',
              property: name,
              severity: 'high',
              snippet: match.substring(0, 80)
            });
          }
        }
      });
    }

    // 4. Check for nested clobbering with document.all-like patterns
    // Multiple elements with same id (document.all[id] returns HTMLCollection)
    const idCounts = {};
    const idMatches = responseBody.matchAll(/id=["'](\w+)["']/gi);
    for (const match of idMatches) {
      const idVal = match[1].toLowerCase();
      if (DANGEROUS_DOM_PROPERTIES.some(dp => dp.toLowerCase() === idVal)) {
        idCounts[idVal] = (idCounts[idVal] || 0) + 1;
      }
    }

    Object.keys(idCounts).forEach(idVal => {
      if (idCounts[idVal] >= 2) {
        clobberFindings.push({
          type: 'dom-clobber-multiple-ids',
          property: idVal,
          count: idCounts[idVal],
          severity: 'medium',
          snippet: `Element id="${idVal}" appears ${idCounts[idVal]} times`
        });
      }
    });

    // 5. Check for clobbering via SVG/MathML elements
    const svgClobber = responseBody.match(/<svg[^>]*>[\s\S]*?<[a-z]+[^>]*id=["'](\w+)["']/gi);
    if (svgClobber) {
      svgClobber.forEach(match => {
        const idMatch = match.match(/id=["'](\w+)["']/i);
        if (idMatch && DANGEROUS_DOM_PROPERTIES.some(dp => dp.toLowerCase() === idMatch[1].toLowerCase())) {
          clobberFindings.push({
            type: 'dom-clobber-svg',
            tag: '<svg>',
            property: idMatch[1],
            severity: 'high',
            snippet: match.substring(0, 120)
          });
        }
      });
    }

    if (clobberFindings.length === 0) return;

    const findId = 'memory-dom-clobbering';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const highSeverity = clobberFindings.some(f => f.severity === 'high');
    const properties = [...new Set(clobberFindings.map(f => f.property))];

    findings.push({
      id: findId,
      category: 'memory-web-context',
      name: 'DOM Clobbering via HTML Responses',
      description: `Detected ${clobberFindings.length} DOM clobbering vector(s) targeting properties: ${properties.join(', ')}. DOM clobbering occurs when HTML elements with \`id\` or \`name\` attributes shadow built-in DOM properties (e.g., \`<a name="cookie">\` clobbers \`document.cookie\`). This can bypass XSS filters, hijack form actions, and manipulate script behavior by overwriting globally accessible properties with attacker-controlled DOM nodes.`,
      severity: highSeverity ? 'high' : 'medium',
      requestIndex: idx,
      evidence: {
        vectors: clobberFindings.slice(0, 8).map(f => ({ type: f.type, property: f.property, tag: f.tag, snippet: f.snippet ? f.snippet.substring(0, 80) : '' })),
        totalMatches: clobberFindings.length,
        url: path,
        method: req.request && req.request.method,
        contentType: contentTypeVal
      },
      score: highSeverity ? 80 : 45
    });
  });
}

// =========================
// DETECTOR 2: CACHE POISONING / WEB CACHE DECEPTION
// =========================
/**
 * Detect Cache Poisoning / Web Cache Deception:
 * - Aggressive cache headers on dynamic/authenticated content
 * - Conflicting cache directives (public + no-store)
 * - Cache key manipulation via parameters
 * - Static-file extensions on dynamic content
 * - Excessive cache TTLs
 * - CDN-specific header abuse
 */
function detectCachePoisoning(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const headers = getAllHeaderValues(req);
    const path = getPathname(req.request && req.request.url);
    const fullUrl = req.request && req.request.url ? req.request.url : '';

    // Check for authentication indicators in the request
    const authHeader = headers.find(h => h.name.toLowerCase() === 'authorization');
    const cookieHeader = headers.find(h => h.name.toLowerCase() === 'cookie');
    const hasAuth = !!(authHeader || (cookieHeader && (cookieHeader.value || '').includes('session')));

    const cacheIssues = [];

    // 1. Check Cache-Control header for dangerous directives
    const cacheControl = headers.find(h => h.name.toLowerCase() === 'cache-control');
    if (cacheControl) {
      const ccVal = cacheControl.value || '';

      // Public cache on authenticated content
      if (hasAuth && /public/i.test(ccVal)) {
        cacheIssues.push({
          type: 'cache-auth-public',
          severity: 'high',
          description: 'Cache-Control header includes \`public\` on an authenticated request. This may cause CDNs and proxies to cache private user data and serve it to other users.'
        });
      }

      // Contradictory directives (public + private + no-store)
      const hasPublic = /public/i.test(ccVal);
      const hasPrivate = /private/i.test(ccVal);
      const hasNoStore = /no-store/i.test(ccVal);
      if ((hasPublic && hasPrivate) || (hasPublic && hasNoStore) || (hasPrivate && hasNoStore)) {
        cacheIssues.push({
          type: 'cache-contradictory-directives',
          severity: 'medium',
          description: `Cache-Control contains contradictory directives: \`${ccVal}\`. Conflicting cache directives cause unpredictable caching behavior across different intermediaries.`
        });
      }

      // Excessive max-age
      const maxAgeMatch = ccVal.match(/max-age=(\d+)/i);
      if (maxAgeMatch) {
        const maxAge = parseInt(maxAgeMatch[1], 10);
        if (maxAge > 86400) { // > 24 hours
          cacheIssues.push({
            type: 'cache-excessive-max-age',
            severity: 'medium',
            description: `Cache-Control \`max-age=${maxAge}\` (${(maxAge / 3600).toFixed(1)} hours) is excessively long. This increases the window for cache poisoning attacks and serves stale content.`
          });
        }
      }

      // Missing no-cache on dynamic/API endpoints
      const isApiEndpoint = /\/api\/|\/graphql|\.json/i.test(path);
      if (isApiEndpoint && !/no-cache|no-store|must-revalidate/i.test(ccVal)) {
        cacheIssues.push({
          type: 'cache-api-no-cache',
          severity: 'medium',
          description: `API/dynamic endpoint (\`${path}\`) lacks \`no-cache\` or \`must-revalidate\` in Cache-Control. Dynamic content should never be cached without explicit revalidation.`
        });
      }
    }

    // 2. Check for Pragma header
    const pragma = headers.find(h => h.name.toLowerCase() === 'pragma');
    if (pragma && /public/i.test(pragma.value || '')) {
      cacheIssues.push({
        type: 'cache-pragma-public',
        severity: 'medium',
        description: 'Pragma header is set to \`public\'. This legacy header may override modern Cache-Control directives in some intermediaries.'
      });
    }

    // 3. Check for Vary header manipulation (cache key poisoning)
    const vary = headers.find(h => h.name.toLowerCase() === 'vary');
    if (vary && vary.value) {
      const varyVal = vary.value;
      // Vary: * is dangerous — caches everything uniquely
      if (varyVal.includes('*')) {
        cacheIssues.push({
          type: 'cache-vary-wildcard',
          severity: 'high',
          description: 'Vary header is set to \`*\`. This tells caches that every request is unique, which can exhaust cache storage and degrade performance, or in some implementations, be ignored entirely leading to cache confusion.'
        });
      }
      // Vary with user-specific headers
      if (/cookie|authorization|token/i.test(varyVal) && !hasAuth) {
        cacheIssues.push({
          type: 'cache-vary-auth-header',
          severity: 'medium',
          description: `Vary header includes authentication-related headers (\`${varyVal}\`) but request lacks credentials. This could cause authenticated responses to be cached and served to anonymous users.`
        });
      }
    }

    // 4. Check for cache key manipulation via unique parameters
    const params = getAllParams(req);
    const cacheKeyParams = Object.keys(params).filter(k =>
      CACHE_KEY_PARAMS.some(ckp => k.toLowerCase() === ckp.toLowerCase())
    );
    if (cacheKeyParams.length > 3) {
      cacheIssues.push({
        type: 'cache-excessive-key-params',
        severity: 'medium',
        description: `Request contains ${cacheKeyParams.length} cache-busting parameters (${cacheKeyParams.join(', ')}). Excessive cache key parameters can lead to cache poisoning by allowing attackers to generate unique cache keys that poison different cache entries.`
      });
    }

    // 5. Check for static-file extension on authenticated response
    if (hasAuth) {
      const isStaticExtension = CACHE_DECEPTION_ENDPOINTS.some(p => p.test(path));
      if (isStaticExtension) {
        cacheIssues.push({
          type: 'cache-deception-auth-static',
          severity: 'high',
          description: `Authenticated response uses a static-file extension (\`${path}\`). In Web Cache Deception attacks, attackers trick users into requesting dynamic content with a static extension (e.g., \`/account/settings.css\`) that gets cached and then retrieved by the attacker to read sensitive data.`
        });
      }
    }

    // 6. Check for CDN-specific cache headers
    const cdnHeaders = headers.filter(h =>
      /x-cache|cf-cache|x-served-by|x-cache-status|x-amz-cache|x-akamai/i.test(h.name)
    );
    if (cdnHeaders.length > 0) {
      cdnHeaders.forEach(h => {
        const val = (h.value || '').toLowerCase();
        if (val.includes('hit') || val.includes('served')) {
          // Cached response was served — could be stale/poisoned
          if (hasAuth && /miss|dynamic/i.test(val)) {
            // Auth'd content being cached is dangerous
          }
        }
      });
    }

    // 7. Check for Age header (stale cache indicator)
    const ageHeader = headers.find(h => h.name.toLowerCase() === 'age');
    if (ageHeader) {
      const ageSecs = parseInt(ageHeader.value, 10);
      if (!isNaN(ageSecs) && ageSecs > 3600) {
        cacheIssues.push({
          type: 'cache-stale-age',
          severity: 'low',
          description: `Response has \`Age: ${ageSecs}s\` (${(ageSecs / 3600).toFixed(1)} hours old). This response was served from cache and is potentially stale.`
        });
      }
    }

    if (cacheIssues.length === 0) return;

    const findId = 'memory-cache-poisoning';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const hasHigh = cacheIssues.some(i => i.severity === 'high');
    const overallSeverity = hasHigh ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'memory-web-context',
      name: 'Cache Poisoning / Web Cache Deception',
      description: `Detected ${cacheIssues.length} cache-related issue(s): ${cacheIssues.map(i => i.description).join(' ')}. Cache poisoning vulnerabilities allow attackers to serve malicious cached content to users, while Web Cache Deception tricks servers into caching sensitive authenticated responses by appending static-file extensions to dynamic URLs.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        issues: cacheIssues.map(i => ({ type: i.type, severity: i.severity })),
        url: path,
        method: req.request && req.request.method,
        hasAuthentication: hasAuth,
        cacheControl: cacheControl ? cacheControl.value : null,
        varyHeader: vary ? vary.value : null
      },
      score: overallSeverity === 'high' ? 80 : 40
    });
  });
}

// =========================
// DETECTOR 3: CLIENT-SIDE STORAGE MANIPULATION
// =========================
/**
 * Detect Client-Side Storage Manipulation:
 * - Payloads targeting localStorage/sessionStorage.setItem
 * - Injection of malicious scripts into storage
 * - Storage quota abuse patterns
 * - Storage event manipulation
 * - Cookie-based storage injection
 */
function detectClientSideStorageManipulation(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const bodyText = getRequestBodyText(req);
    const allTextValues = [];
    const path = getPathname(req.request && req.request.url);

    // Collect all text values
    Object.keys(params).forEach(k => allTextValues.push(String(params[k])));
    if (bodyText) allTextValues.push(bodyText);
    allTextValues.push(req.request && req.request.url ? req.request.url : '');
    allTextValues.push(path);

    const storageIssues = [];

    // 1. Check for storage API invocation patterns in params/body
    allTextValues.forEach(txt => {
      for (const pattern of STORAGE_PAYLOAD_PATTERNS) {
        if (pattern.test(txt)) {
          const match = txt.match(pattern);
          storageIssues.push({
            type: 'storage-api-invocation',
            pattern: match ? match[0] : pattern.source.substring(0, 40),
            snippet: txt.substring(0, 120),
            severity: 'high',
            description: 'Request body/params contain code that invokes client-side storage APIs (localStorage/sessionStorage.setItem). This could be an attempt to manipulate stored data, inject malicious scripts, or exfiltrate data via storage side-channels.'
          });
          break;
        }
      }
    });

    // 2. Check for storage-related parameter names with suspicious values
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      const isStorageParam = STORAGE_MANIPULATION_PARAMS.some(sp =>
        lowerKey === sp.toLowerCase() || lowerKey.includes(sp.toLowerCase())
      );
      if (!isStorageParam) return;

      const val = String(params[key]);

      // Check if value contains injection payloads
      for (const injPattern of STORAGE_INJECTION_PATTERNS) {
        if (injPattern.test(val)) {
          storageIssues.push({
            type: 'storage-injection-payload',
            param: key,
            valueSample: val.substring(0, 80),
            injectionType: injPattern.source.substring(0, 20),
            severity: 'high',
            description: `Storage-related parameter \`${key}\` contains injection payload: \`${val.substring(0, 60)}\`. Malicious scripts stored in localStorage/sessionStorage can later be executed by the application, leading to stored XSS.`
          });
          break;
        }
      }

      // Check for excessively large values (quota abuse)
      if (val.length > 10000) {
        storageIssues.push({
          type: 'storage-quota-abuse',
          param: key,
          valueSize: val.length,
          severity: 'medium',
          description: `Storage parameter \`${key}\` has an excessively large value (${val.length} bytes). This could be an attempt to exhaust the browser's storage quota (typically ~5-10MB per origin) and cause denial of service.`
        });
      }

      // Check for prototype pollution + storage combination
      if (containsProtoPattern(val)) {
        storageIssues.push({
          type: 'storage-proto-pollution',
          param: key,
          valueSample: val.substring(0, 60),
          severity: 'high',
          description: `Storage parameter \`${key}\` contains prototype pollution pattern (\`__proto__\` or \`constructor.prototype\`). Combined with storage manipulation, this can enable persistent prototype pollution across page loads.`
        });
      }
    });

    // 3. Check for storage quota exhaustion indicators
    const bodySize = (req.response && req.response.bodySize) || 0;
    if (bodySize > 5 * 1024 * 1024) { // 5MB — close to typical localStorage quota
      storageIssues.push({
        type: 'storage-quota-exhaustion-body',
        severity: 'low',
        description: `Response body is ${(bodySize / 1048576).toFixed(1)} MB, approaching the typical localStorage quota limit (~5-10MB). Large responses that get stored can exhaust browser storage.`
      });
    }

    // 4. Check for storage event manipulation (storage events fire on other tabs)
    if (bodyText) {
      const storageEventPatterns = [
        /window\.addEventListener\s*\(\s*['"]storage['"]/i,
        /window\.onstorage\s*=/i,
        /addEventListener\s*\(\s*['"]storage['"]/i
      ];
      storageEventPatterns.forEach(pattern => {
        if (pattern.test(bodyText)) {
          storageIssues.push({
            type: 'storage-event-listener',
            severity: 'medium',
            description: 'Request body contains a storage event listener (\`window.addEventListener("storage", ...)\`). Storage event listeners can be exploited for cross-tab communication side-channels or to trigger malicious callbacks when storage is modified.'
          });
        }
      });
    }

    // 5. Check for window.name abuse (cross-tab storage)
    const windowNamePattern = /window\.name\s*=|self\.name\s*=|top\.name\s*=/i;
    if (windowNamePattern.test(bodyText || '')) {
      storageIssues.push({
        type: 'window-name-storage',
        severity: 'medium',
        description: 'Request body manipulates \`window.name\`. \`window.name\` persists across page navigations and can be used as a cross-origin storage mechanism, enabling data leakage across different origins.'
      });
    }

    if (storageIssues.length === 0) return;

    const findId = 'memory-storage-manipulation';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const hasHigh = storageIssues.some(i => i.severity === 'high');

    findings.push({
      id: findId,
      category: 'memory-web-context',
      name: 'Client-Side Storage Manipulation',
      description: `Detected ${storageIssues.length} client-side storage manipulation indicator(s): ${storageIssues.map(i => i.description).join(' ')}. Client-side storage APIs (localStorage, sessionStorage) can be abused to inject malicious scripts, exhaust storage quotas, create cross-tab communication channels, or persistently store prototype pollution payloads.`,
      severity: hasHigh ? 'high' : 'medium',
      requestIndex: idx,
      evidence: {
        issues: storageIssues.map(i => ({ type: i.type, ...(i.param ? { param: i.param } : {}), ...(i.valueSample ? { valueSample: i.valueSample.substring(0, 50) } : {}), ...(i.valueSize ? { valueSize: i.valueSize } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: hasHigh ? 80 : 40
    });
  });
}

function containsProtoPattern(val) {
  if (!val || typeof val !== 'string') return false;
  return /__proto__|constructor\.prototype|prototype\.\w+/.test(val);
}

// =========================
// DETECTOR 4: MEMORY EXHAUSTION VIA DEEPLY NESTED OBJECTS
// =========================
/**
 * Detect Memory Exhaustion via Deeply Nested Objects:
 * - JSON responses with excessive nesting depth (>12 levels)
 * - Large arrays in JSON responses (>5000 elements)
 * - Extremely large string fields (>100KB)
 * - Objects with excessive property counts (>500)
 * - Compression bomb indicators (zip bomb, gzip bomb)
 * - Massively repeated structural patterns
 */
function detectMemoryExhaustNestedObjects(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const path = getPathname(req.request && req.request.url);

    // Check response body
    let responseBody = null;
    if (req.response && req.response.content && req.response.content.text) {
      responseBody = req.response.content.text;
    }

    // Also check request body
    const requestBody = getRequestBodyText(req);

    const exhaustionIssues = [];

    // Analyze a text blob for memory exhaustion patterns
    const analyzeText = (text, source) => {
      if (!text || text.length < 10000) return; // Skip small payloads

      // Try to parse as JSON
      const parsed = tryParseJSON(text);

      if (parsed && typeof parsed === 'object') {
        // 1. Check nesting depth
        const measureDepth = (obj, currentDepth = 0) => {
          if (!obj || typeof obj !== 'object' || currentDepth > 30) return currentDepth;
          let maxDepth = currentDepth;
          Object.keys(obj).forEach(k => {
            if (obj[k] && typeof obj[k] === 'object') {
              const d = measureDepth(obj[k], currentDepth + 1);
              maxDepth = Math.max(maxDepth, d);
            }
          });
          return maxDepth;
        };

        const depth = measureDepth(parsed);
        if (depth >= MEMORY_EXHAUSTION_THRESHOLDS.jsonNestingDepth) {
          exhaustionIssues.push({
            type: 'excessive-nesting',
            source,
            depth,
            severity: depth >= 20 ? 'high' : 'medium',
            description: `JSON payload has excessive nesting depth (${depth} levels). Deeply nested objects consume significant memory during parsing and can cause stack overflow or OOM errors in JSON.parse() implementations.`
          });
        }

        // 2. Check for large top-level arrays
        if (Array.isArray(parsed) && parsed.length > MEMORY_EXHAUSTION_THRESHOLDS.jsonArrayLength) {
          exhaustionIssues.push({
            type: 'excessive-array',
            source,
            arrayLength: parsed.length,
            severity: parsed.length > 50000 ? 'high' : 'medium',
            description: `JSON payload contains a top-level array with ${parsed.length} elements. Large arrays consume significant memory and CPU during parsing, especially when each element is a complex object.`
          });
        }

        // 3. Check for objects with excessive property count
        const countProperties = (obj, maxScan = 3) => {
          if (!obj || typeof obj !== 'object' || maxScan <= 0) return 0;
          let count = Object.keys(obj).length;
          Object.keys(obj).forEach(k => {
            if (obj[k] && typeof obj[k] === 'object' && !Array.isArray(obj[k])) {
              count += countProperties(obj[k], maxScan - 1);
            }
          });
          return count;
        };

        const propCount = countProperties(parsed);
        if (propCount > MEMORY_EXHAUSTION_THRESHOLDS.objectPropertyCount) {
          exhaustionIssues.push({
            type: 'excessive-properties',
            source,
            propertyCount: propCount,
            severity: 'medium',
            description: `JSON payload contains ${propCount} total properties across all nested objects. Large object graphs consume memory proportional to property count.`
          });
        }

        // 4. Check for very large string fields
        if (typeof parsed === 'object') {
          const scanLargeStrings = (obj, path = '') => {
            if (!obj || typeof obj !== 'object') return;
            Object.keys(obj).forEach(k => {
              const currentPath = path ? `${path}.${k}` : k;
              if (typeof obj[k] === 'string' && obj[k].length > MEMORY_EXHAUSTION_THRESHOLDS.stringFieldLength) {
                exhaustionIssues.push({
                  type: 'excessive-string-field',
                  source,
                  field: currentPath,
                  stringLength: obj[k].length,
                  severity: obj[k].length > 500000 ? 'high' : 'medium',
                  description: `String field \`${currentPath}\` is extremely large (${(obj[k].length / 1024).toFixed(1)} KB). Large string fields consume memory during parsing and can be used for heap spray attacks.`
                });
              }
              scanLargeStrings(obj[k], currentPath);
            });
          };
          scanLargeStrings(parsed);
        }

        // 5. Check for repeated identical structures (pads memory)
        if (Array.isArray(parsed) && parsed.length > 100) {
          const firstStr = JSON.stringify(parsed[0]);
          let repeatCount = 0;
          for (let i = 1; i < Math.min(parsed.length, 20); i++) {
            if (JSON.stringify(parsed[i]) === firstStr) repeatCount++;
          }
          if (repeatCount > 10) {
            exhaustionIssues.push({
              type: 'repeated-structure',
              source,
              repeatCount: repeatCount,
              arrayLength: parsed.length,
              severity: 'medium',
              description: `Array contains ${repeatCount}+ identical object structures out of first 20 elements (total array length: ${parsed.length}). Repeated structures with many elements can be used for memory padding in heap spray attacks.`
            });
          }
        }
      }

      // 6. Check for compression bomb / zip bomb patterns
      // Look for high compression ratio: small raw text that decompresses to huge data
      const textLength = text.length;
      const contentSize = (req.response && req.response.bodySize) || 0;
      if (contentSize > 0 && textLength > 0) {
        const ratio = textLength / contentSize;
        if (ratio > MEMORY_EXHAUSTION_THRESHOLDS.compressionRatio) {
          exhaustionIssues.push({
            type: 'compression-bomb',
            source,
            compressedSize: contentSize,
            decompressedSize: textLength,
            ratio: Math.round(ratio),
            severity: 'high',
            description: `Response has an extreme compression ratio (${Math.round(ratio)}:1, compressed: ${(contentSize / 1024).toFixed(1)}KB, decompressed: ${(textLength / 1048576).toFixed(1)}MB). This is characteristic of a decompression bomb (zip bomb / gzip bomb) designed to exhaust server or client memory.`
          });
        }
      }

      // 7. Check for deeply nested bracket/key patterns (JSON bomb)
      const openBraces = (text.match(/\{/g) || []).length;
      const closeBraces = (text.match(/\}/g) || []).length;
      const totalDepthChanges = Math.max(openBraces, closeBraces);

      // A high ratio of braces to content length suggests deep nesting without much data
      if (totalDepthChanges > 500 && textLength < 100000) {
        exhaustionIssues.push({
          type: 'json-bomb',
          source,
          braceCount: totalDepthChanges,
          textLength,
          severity: 'high',
          description: `JSON payload has a high density of opening/closing braces (${totalDepthChanges} braces in ${textLength} chars). This is a characteristic of a "JSON bomb" designed to cause stack overflow during parsing.`
        });
      }
    };

    if (responseBody) analyzeText(responseBody, 'response');
    if (requestBody) analyzeText(requestBody, 'request');

    if (exhaustionIssues.length === 0) return;

    const findId = 'memory-exhaustion-nested';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const hasHigh = exhaustionIssues.some(i => i.severity === 'high');

    findings.push({
      id: findId,
      category: 'memory-web-context',
      name: 'Memory Exhaustion via Deeply Nested Objects',
      description: `Detected ${exhaustionIssues.length} memory exhaustion indicator(s): ${exhaustionIssues.map(i => i.description).join(' ')}. Memory exhaustion attacks use deeply nested JSON, compression bombs, huge arrays, or excessively large string fields to cause OOM errors, stack overflows, or degrade browser/application performance.`,
      severity: hasHigh ? 'high' : 'medium',
      requestIndex: idx,
      evidence: {
        issues: exhaustionIssues.map(i => ({ type: i.type, source: i.source, severity: i.severity, ...(i.depth ? { depth: i.depth } : {}), ...(i.arrayLength ? { arrayLength: i.arrayLength } : {}), ...(i.stringLength ? { stringLengthKB: (i.stringLength / 1024).toFixed(1) } : {}), ...(i.ratio ? { compressionRatio: i.ratio } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: hasHigh ? 85 : 45
    });
  });
}

// =========================
// DETECTOR 5: SERVICE WORKER CACHE POLLUTION
// =========================
/**
 * Detect Service Worker Cache Pollution:
 * - Service worker script registration endpoints
 * - Precaching of attacker-controlled resources
 * - Cache API abuse patterns
 * - Uncontrolled cache population
 * - Stale cache serving
 */
function detectServiceWorkerCachePollution(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);
    const headers = getAllHeaderValues(req);
    const bodyText = getRequestBodyText(req);

    const swIssues = [];

    // 1. Check for service worker registration endpoints
    const isSWEndpoint = SW_ENDPOINT_PATTERNS.some(p => p.test(path) || p.test(url));
    if (isSWEndpoint) {
      // Check if the service worker script could be modified via caching
      const swResponseHeaders = (req.response && req.response.headers) ? req.response.headers : [];
      const swCacheControl = swResponseHeaders.find(h => (h.name || '').toLowerCase() === 'cache-control');
      if (swCacheControl && /max-age=\s*(\d+)/i.test(swCacheControl.value || '')) {
        const maxAge = parseInt(swCacheControl.value.match(/max-age=(\d+)/i)[1], 10);
        if (maxAge > 3600) {
          swIssues.push({
            type: 'sw-long-cache',
            severity: 'high',
            description: `Service worker script (\`${path}\`) has a long cache lifetime (\`max-age=${maxAge}\`). Cached service worker scripts can serve stale, potentially malicious code to users. Attackers who poison the SW cache can persistently control all pages under the SW scope.`
          });
        }
      }

      // Check for importScripts with dynamic/unsafe URLs
      if (bodyText) {
        const importMatches = bodyText.match(/importScripts\s*\(\s*['"][^'"]+['"]/gi);
        if (importMatches) {
          importMatches.forEach(imp => {
            const urlMatch = imp.match(/['"]https?:\/\/[^'"]+['"]/i);
            if (urlMatch) {
              const importUrl = urlMatch[0].replace(/['"]/g, '');
              // Check if importing from a different domain (cross-origin SW dependency)
              const swOrigin = new URL(url).origin;
              const importOrigin = new URL(importUrl).origin;
              if (swOrigin !== importOrigin) {
                swIssues.push({
                  type: 'sw-cross-origin-import',
                  severity: 'high',
                  description: `Service worker imports a script from a different origin: \`${importUrl}\`. Cross-origin imports are a security risk — if the external origin is compromised, the attacker gains full control over the service worker and all pages it controls.`
                });
              }
            }
          });
        }
      }
    }

    // 2. Check for Cache API invocation patterns
    if (bodyText) {
      const cacheApiPatterns = [
        /caches\.open\s*\(/i,
        /cache\.put\s*\(/i,
        /cache\.addAll?\s*\(/i,
        /cache\.match\s*\(/i,
        /self\.caches/i,
        /event\.respondWith\s*\(/i,
        /event\.waitUntil\s*\(/i
      ];

      cacheApiPatterns.forEach(pattern => {
        if (pattern.test(bodyText)) {
          swIssues.push({
            type: 'sw-cache-api-usage',
            severity: 'medium',
            description: `Service worker code uses Cache API (\`${pattern.source.substring(0, 30)}\`). Unvalidated cache operations can lead to cache poisoning if the SW caches attacker-controlled responses.`
          });
        }
      });

      // Check for precaching of user-supplied URLs
      const precacheMatches = bodyText.match(/precache\.\w+\s*\(/i);
      if (precacheMatches) {
        swIssues.push({
          type: 'sw-precache-usage',
          severity: 'medium',
          description: 'Service worker uses Workbox precache (\`precache.*()\`). If precache manifest URLs are user-influenced, attackers can inject malicious resources into the precache that are served for the SW lifetime.'
        });
      }
    }

    // 3. Check for SW-related headers in response
    const swScope = headers.find(h => (h.name || '').toLowerCase() === 'service-worker-allowed');
    if (swScope) {
      swIssues.push({
        type: 'sw-scope-header',
        severity: 'medium',
        description: `Response includes \`Service-Worker-Allowed\` header with value: \`${swScope.value}\`. This header extends the SW scope beyond the script path. An overly broad scope allows the SW to intercept requests for a wider range of URLs.`
      });
    }

    // 4. Check for stale cache serving via SW patterns
    if (bodyText) {
      // Network first vs cache first patterns
      const hasNetworkFirst = /networkFirst|network_first|network\.only|NetworkOnly/i.test(bodyText);
      const hasCacheFirst = /cacheFirst|cache_first|cache\.only|CacheOnly|staleWhileRevalidate|stale.*while.*revalidate/i.test(bodyText);

      if (hasCacheFirst && !hasNetworkFirst) {
        swIssues.push({
          type: 'sw-stale-cache',
          severity: 'medium',
          description: 'Service worker uses a cache-first strategy without a network-first fallback. Cache-first strategies can serve stale or poisoned content for extended periods until the cache is invalidated.'
        });
      }
    }

    if (swIssues.length === 0) return;

    const findId = 'memory-sw-cache-pollution';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const hasHigh = swIssues.some(i => i.severity === 'high');

    findings.push({
      id: findId,
      category: 'memory-web-context',
      name: 'Service Worker Cache Pollution',
      description: `Detected ${swIssues.length} service worker cache issue(s): ${swIssues.map(i => i.description).join(' ')}. Service worker cache pollution allows attackers to inject malicious responses into the SW cache, which are then served to all users under the SW scope. Since SWs have long lifetimes, poisoned caches persist across page loads.`,
      severity: hasHigh ? 'high' : 'medium',
      requestIndex: idx,
      evidence: {
        issues: swIssues.map(i => ({ type: i.type, severity: i.severity, ...(i.description ? { detail: i.description.substring(0, 100) } : {}) })),
        url: path,
        method: req.request && req.request.method,
        isServiceWorkerEndpoint: isSWEndpoint
      },
      score: hasHigh ? 85 : 45
    });
  });
}

// =========================
// DETECTOR 6: DETACHED DOM / LARGE PAYLOAD GENERATION
// =========================
/**
 * Detect Detached DOM / Large Payload Generation:
 * - Massive HTML responses (>10MB)
 * - Repeated DOM creation patterns in responses
 * - innerHTML/outerHTML injection with large payloads
 * - DocumentFragment creation patterns
 * - Cloned node patterns (potential for detached DOM trees)
 * - Excessive whitespace/padding in responses
 */
function detectDetachedDOMLargePayload(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const path = getPathname(req.request && req.request.url);
    const headers = getAllHeaderValues(req);
    const contentType = headers.find(h => h.name.toLowerCase() === 'content-type');
    const contentTypeVal = contentType ? (contentType.value || '') : '';

    let responseBody = null;
    if (req.response && req.response.content && req.response.content.text) {
      responseBody = req.response.content.text;
    }

    if (!responseBody) return;

    const domIssues = [];
    const textSize = responseBody.length;

    // 1. Check for excessively large response body
    if (textSize > MEMORY_EXHAUSTION_THRESHOLDS.responseBodySizeMB * 1024 * 1024) {
      domIssues.push({
        type: 'massive-html-response',
        size: textSize,
        sizeMB: (textSize / 1048576).toFixed(1),
        severity: textSize > 50 * 1024 * 1024 ? 'high' : 'medium',
        description: `Response body is ${(textSize / 1048576).toFixed(1)} MB. Massive HTML responses consume significant browser memory for DOM parsing and rendering. They can cause browser hangs, OOM crashes, or be used for heap spray attacks.`
      });
    }

    // 2. Check for repeated DOM creation patterns (innerHTML in script tags)
    const scriptBlocks = responseBody.match(/<script[^>]*>[\s\S]*?<\/script>/gi) || [];
    scriptBlocks.forEach(script => {
      const innerHTMLPatterns = [
        /\.innerHTML\s*=/gi,
        /\.outerHTML\s*=/gi,
        /\.insertAdjacentHTML\s*\(/gi,
        /document\.createElement\s*\(/gi,
        /\.cloneNode\s*\(/gi,
        /\.appendChild\s*\(/gi,
        /\.removeChild\s*\(/gi,
        /\.replaceChild\s*\(/gi,
        /document\.createDocumentFragment\s*\(/gi
      ];

      innerHTMLPatterns.forEach(pattern => {
        const matches = script.match(pattern);
        if (matches && matches.length > 10) {
          domIssues.push({
            type: 'excessive-dom-operations',
            pattern: pattern.source.substring(0, 30),
            count: matches.length,
            scriptSnippet: script.substring(0, 80),
            severity: matches.length > 50 ? 'high' : 'medium',
            description: `Script block contains ${matches.length} uses of \`${pattern.source.substring(0, 30)}\`. Excessive DOM manipulations, especially with \`innerHTML\`, create detached DOM trees that garbage collection cannot reclaim, leading to memory leaks.`
          });
        }
      });
    });

    // 3. Check for cloned node patterns that cause detached DOM
    const cloneMatches = responseBody.match(/\.cloneNode\s*\(\s*true\s*\)/gi);
    if (cloneMatches && cloneMatches.length > 5) {
      domIssues.push({
        type: 'excessive-clone-operations',
        count: cloneMatches.length,
        severity: 'medium',
        description: `Response contains ${cloneMatches.length} \`cloneNode(true)\` calls. Deep cloning DOM nodes creates detached subtrees that are not visible but consume memory until explicitly removed.`
      });
    }

    // 4. Check for large base64-encoded content (inline images, etc.)
    const base64Images = responseBody.match(/data:image\/[^;]+;base64,[A-Za-z0-9+/=]{1000,}/gi);
    if (base64Images) {
      const totalBase64Size = base64Images.reduce((sum, img) => sum + img.length, 0);
      if (totalBase64Size > 5 * 1024 * 1024) { // >5MB of inline base64
        domIssues.push({
          type: 'excessive-base64-inline',
          totalSize: totalBase64Size,
          imageCount: base64Images.length,
          severity: 'medium',
          description: `Response contains ${base64Images.length} inline base64-encoded images totaling ${(totalBase64Size / 1048576).toFixed(1)} MB. Large inline base64 content significantly increases DOM memory usage since each image is decoded into a bitmap in memory.`
        });
      }
    }

    // 5. Check for extensive whitespace/padding (memory padding)
    const whitespaceRatio = (responseBody.match(/\s/g) || []).length / textSize;
    if (whitespaceRatio > 0.5 && textSize > 500000) {
      domIssues.push({
        type: 'excessive-whitespace-padding',
        whitespaceRatio: Math.round(whitespaceRatio * 100),
        totalSize: textSize,
        severity: 'medium',
        description: `Response body is ${(textSize / 1048576).toFixed(1)} MB with ${Math.round(whitespaceRatio * 100)}% whitespace. Padding responses with whitespace can be used to inflate memory usage or bypass security filters.`
      });
    }

    // 6. Check for excessive table/list structures (DOM bloat)
    const tableRows = (responseBody.match(/<tr[>\s]/gi) || []).length;
    const listItems = (responseBody.match(/<li[>\s]/gi) || []).length;
    const divs = (responseBody.match(/<div[>\s]/gi) || []).length;

    if (tableRows > 5000) {
      domIssues.push({
        type: 'dom-bloat-table',
        element: '<tr>',
        count: tableRows,
        severity: 'high',
        description: `Response contains ${tableRows} table rows. Very large tables (5000+ rows) cause significant DOM memory usage and poor rendering performance. Repeated rows with user-controlled content can be used for heap spray.`
      });
    }

    if (listItems > 10000) {
      domIssues.push({
        type: 'dom-bloat-list',
        element: '<li>',
        count: listItems,
        severity: 'high',
        description: `Response contains ${listItems} list items. Very large lists consume significant DOM memory and can cause browser hangs.`
      });
    }

    if (divs > 10000) {
      domIssues.push({
        type: 'dom-bloat-divs',
        element: '<div>',
        count: divs,
        severity: 'medium',
        description: `Response contains ${divs} <div> elements. Excessive DOM nodes (>10,000) consume memory and degrade performance.`
      });
    }

    if (domIssues.length === 0) return;

    const findId = 'memory-detached-dom-large-payload';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const hasHigh = domIssues.some(i => i.severity === 'high');

    findings.push({
      id: findId,
      category: 'memory-web-context',
      name: 'Detached DOM / Large Payload Generation',
      description: `Detected ${domIssues.length} DOM/payload size issue(s): ${domIssues.map(i => i.description).join(' ')}. Detached DOM nodes occur when elements are removed from the document but JavaScript references keep them alive, preventing garbage collection. Large payloads compound this by creating massive DOM trees that consume significant memory.`,
      severity: hasHigh ? 'high' : 'medium',
      requestIndex: idx,
      evidence: {
        issues: domIssues.map(i => ({ type: i.type, severity: i.severity, ...(i.sizeMB ? { sizeMB: i.sizeMB } : {}), ...(i.count ? { count: i.count } : {}), ...(i.totalSize ? { totalSizeKB: (i.totalSize / 1024).toFixed(0) } : {}) })),
        url: path,
        method: req.request && req.request.method,
        contentType: contentTypeVal,
        responseSizeKB: Math.round(textSize / 1024)
      },
      score: hasHigh ? 80 : 40
    });
  });
}

// =========================
// DETECTOR 7: CROSS-WINDOW / TAB MEMORY LEAK
// =========================
/**
 * Detect Cross-Window / Tab Memory Leak indicators:
 * - window.open patterns without cleanup
 * - postMessage listener accumulation
 * - BroadcastChannel abuse
 * - SharedWorker connection leaks
 * - Window references preventing garbage collection
 */
function detectCrossWindowMemoryLeak(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const bodyText = getRequestBodyText(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);

    if (!bodyText) return;

    const leakIssues = [];

    // 1. Check for window.open patterns without .close()
    const openMatches = bodyText.match(/window\.open\s*\(/gi);
    const closeMatches = bodyText.match(/\.close\s*\(\)/gi);
    if (openMatches && openMatches.length > 0) {
      const openCount = openMatches.length;
      const closeCount = closeMatches ? closeMatches.length : 0;

      // If significantly more opens than closes, windows may leak
      if (openCount > closeCount + 2) {
        leakIssues.push({
          type: 'window-open-without-close',
          openCount,
          closeCount,
          unclosed: openCount - closeCount,
          severity: openCount - closeCount > 5 ? 'high' : 'medium',
          description: `Response contains ${openCount} \`window.open()\` calls but only ${closeCount} \`.close()\` calls. ${openCount - closeCount} unclosed window(s) will leak memory as each window maintains a reference preventing garbage collection.`
        });
      }
    }

    // 2. Check for postMessage listener accumulation
    const addMessageListener = (bodyText.match(/addEventListener\s*\(\s*['"]message['"]/gi) || []).length;
    const removeMessageListener = (bodyText.match(/removeEventListener\s*\(\s*['"]message['"]/gi) || []).length;
    const onmessagePatterns = (bodyText.match(/\.onmessage\s*=/gi) || []).length;

    const totalMessageAttachments = addMessageListener + onmessagePatterns;
    if (totalMessageAttachments > removeMessageListener + 2) {
      leakIssues.push({
        type: 'postmessage-leak',
        attached: totalMessageAttachments,
        removed: removeMessageListener,
        unremoved: totalMessageAttachments - removeMessageListener,
        severity: totalMessageAttachments - removeMessageListener > 10 ? 'high' : 'medium',
        description: `Detected ${totalMessageAttachments} \`message\` event listener(s) attached but only ${removeMessageListener} removed. Orphaned message event listeners accumulate in memory, especially when created inside loops or repeated function calls.`
      });
    }

    // 3. Check for BroadcastChannel abuse
    const broadcastChannelOpen = (bodyText.match(/new\s+BroadcastChannel\s*\(/gi) || []).length;
    const broadcastChannelClose = (bodyText.match(/BroadcastChannel.*\.close\s*\(\)/gi) || []).length;
    if (broadcastChannelOpen > broadcastChannelClose + 2) {
      leakIssues.push({
        type: 'broadcastchannel-leak',
        open: broadcastChannelOpen,
        closed: broadcastChannelClose,
        severity: 'medium',
        description: `Detected ${broadcastChannelOpen} BroadcastChannel instance(s) created but only ${broadcastChannelClose} closed. Unclosed BroadcastChannels maintain message queues and prevent garbage collection.`
      });
    }

    // 4. Check for SharedWorker connection leaks
    const sharedWorkerPatterns = (bodyText.match(/new\s+SharedWorker\s*\(/gi) || []).length;
    const sharedWorkerPortClose = (bodyText.match(/port\.close\s*\(\)|close\s*\(\)/gi) || []).length;
    if (sharedWorkerPatterns > 0 && sharedWorkerPortClose === 0) {
      leakIssues.push({
        type: 'sharedworker-port-leak',
        workers: sharedWorkerPatterns,
        portsClosed: sharedWorkerPortClose,
        severity: 'medium',
        description: `Detected ${sharedWorkerPatterns} SharedWorker instance(s) with no \`port.close()\` calls. SharedWorker ports maintain connections that prevent worker termination and memory deallocation.`
      });
    }

    // 5. Check for window references that prevent GC (global variable window assignments)
    const windowRefPatterns = bodyText.match(/(?:var|let|const)\s+\w+\s*=\s*(?:window|self|top|parent)\b/gi);
    if (windowRefPatterns && windowRefPatterns.length > 3) {
      leakIssues.push({
        type: 'window-reference-leak',
        count: windowRefPatterns.length,
        severity: 'low',
        description: `Detected ${windowRefPatterns.length} assignments of \`window\`/global objects to variables. Global references to window objects prevent the referenced windows from being garbage collected.`
      });
    }

    // 6. Check for postMessage to cross-origin windows without origin validation
    const postMessageCalls = bodyText.match(/\.postMessage\s*\(/gi);
    if (postMessageCalls && postMessageCalls.length > 0) {
      const originCheckPattern = /origin\s*===?\s*['"][^'"]+['"]|event\.origin/i;
      const hasOriginCheck = originCheckPattern.test(bodyText);
      if (!hasOriginCheck) {
        leakIssues.push({
          type: 'postmessage-no-origin-check',
          count: postMessageCalls.length,
          severity: 'high',
          description: `Detected ${postMessageCalls.length} \`postMessage()\` call(s) without origin validation. Cross-origin messaging without checking \`event.origin\` allows any window to send messages, which can lead to memory leaks via accumulation of messages from unexpected sources.`
        });
      }
    }

    if (leakIssues.length === 0) return;

    const findId = 'memory-cross-window-leak';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const hasHigh = leakIssues.some(i => i.severity === 'high');

    findings.push({
      id: findId,
      category: 'memory-web-context',
      name: 'Cross-Window / Tab Memory Leak',
      description: `Detected ${leakIssues.length} cross-window memory leak indicator(s): ${leakIssues.map(i => i.description).join(' ')}. Cross-window references (via \`window.open\` without cleanup, \`postMessage\` listeners, BroadcastChannel, SharedWorker) can prevent garbage collection of entire window objects, leading to significant memory leaks that grow over time.`,
      severity: hasHigh ? 'high' : 'medium',
      requestIndex: idx,
      evidence: {
        issues: leakIssues.map(i => ({ type: i.type, severity: i.severity, ...(i.openCount ? { openCount: i.openCount, closeCount: i.closeCount, unclosed: i.unclosed } : {}), ...(i.attached ? { attached: i.attached, removed: i.removed } : {}), ...(i.count ? { count: i.count } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: hasHigh ? 80 : 40
    });
  });
}

// =========================
// DETECTOR 8: WEBSOCKET CONNECTION ABUSE
// =========================
/**
 * Detect WebSocket Connection Abuse:
 * - Repeated WebSocket upgrade requests
 * - Unclosed WebSocket connections
 * - Large/malicious WebSocket message patterns
 * - WebSocket memory exhaustion via message flooding
 * - Multiple WebSocket connections to same endpoint
 */
function detectWebSocketConnectionAbuse(sortedReqs, findings) {
  const requestFindings = new Map();
  const wsConnections = [];

  sortedReqs.forEach((req, idx) => {
    const headers = getAllHeaderValues(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);
    const bodyText = getRequestBodyText(req);

    const wsIssues = [];

    // 1. Detect WebSocket upgrade requests
    const upgradeHeader = headers.find(h => h.name.toLowerCase() === 'upgrade');
    const connectionHeader = headers.find(h => h.name.toLowerCase() === 'connection');
    const wsKeyHeader = headers.find(h => h.name.toLowerCase() === 'sec-websocket-key');

    const isWebSocketUpgrade = !!(upgradeHeader && /websocket/i.test(upgradeHeader.value || '') &&
      connectionHeader && /upgrade/i.test(connectionHeader.value || '') &&
      wsKeyHeader);

    if (isWebSocketUpgrade) {
      wsConnections.push({
        idx,
        url,
        path,
        timestamp: new Date(req.startedDateTime).getTime(),
        headers
      });

      wsIssues.push({
        type: 'websocket-upgrade-detected',
        severity: 'low',
        description: `WebSocket upgrade request detected to \`${path}\`. WebSocket connections maintain persistent memory for connection state, buffers, and message queues.`
      });
    }

    // 2. Check for WebSocket API usage in request bodies
    if (bodyText) {
      // Multiple WebSocket connections created
      const wsConnectionPatterns = [
        /new\s+WebSocket\s*\(/gi,
        /new\s+WebSocket\s*\(\s*['"]ws/gi,
        /io\s*\(\s*['"]/gi, // Socket.io
        /io\.connect\s*\(/gi
      ];

      wsConnectionPatterns.forEach(pattern => {
        const matches = bodyText.match(pattern);
        if (matches && matches.length > 3) {
          wsIssues.push({
            type: 'websocket-multiple-connections',
            pattern: pattern.source.substring(0, 20),
            count: matches.length,
            severity: matches.length > 10 ? 'high' : 'medium',
            description: `Detected ${matches.length} WebSocket/Socket.io connection creation(s). Creating many WebSocket connections can exhaust browser connection limits and memory. Browsers typically limit concurrent WebSocket connections to 6 per domain.`
          });
        }
      });

      // WebSocket message flooding
      const sendPatterns = [
        /\.send\s*\(/gi,
        /socket\.emit\s*\(/gi,
        /io\.emit\s*\(/gi
      ];

      sendPatterns.forEach(pattern => {
        const matches = bodyText.match(pattern);
        if (matches && matches.length > 20) {
          wsIssues.push({
            type: 'websocket-message-flooding',
            count: matches.length,
            severity: matches.length > 100 ? 'high' : 'medium',
            description: `Detected ${matches.length} message send operations (\`${pattern.source.substring(0, 10)}\`). High-frequency WebSocket messages can cause buffer bloat and memory exhaustion on both client and server.`
          });
        }
      });

      // Large message payloads
      const largePayloadPattern = /\.send\s*\(\s*['"][^'"]{10000,}['"]/gi;
      if (largePayloadPattern.test(bodyText)) {
        wsIssues.push({
          type: 'websocket-large-payload',
          severity: 'high',
          description: 'WebSocket message contains an extremely large payload (>10KB). Large WebSocket messages consume memory in send/receive buffers and can be used for heap spray attacks.'
        });
      }

      // Unclosed WebSocket connections
      const wsClosePattern = /\.close\s*\(/gi;
      const wsCreatePattern = /new\s+WebSocket\s*\(/gi;
      const wsCreateCount = (bodyText.match(wsCreatePattern) || []).length;
      const wsCloseCount = (bodyText.match(wsClosePattern) || []).length;

      if (wsCreateCount > wsCloseCount + 2 && wsCreateCount > 0) {
        wsIssues.push({
          type: 'websocket-not-closed',
          created: wsCreateCount,
          closed: wsCloseCount,
          unclosed: wsCreateCount - wsCloseCount,
          severity: 'high',
          description: `Detected ${wsCreateCount} WebSocket creation(s) but only ${wsCloseCount} \`.close()\` calls. ${wsCreateCount - wsCloseCount} unclosed WebSocket connection(s) will leak memory and keep the event loop active.`
        });
      }
    }

    // 3. Check for WebSocket in URL path
    const isWSPath = WEBSOCKET_PATTERNS.some(p => p.test(path) || p.test(url));
    if (isWSPath && !isWebSocketUpgrade) {
      // The request path looks like a WebSocket endpoint but wasn't captured as upgrade
      // This might indicate the WS connection is open
    }

    if (wsIssues.length === 0) return;

    const findId = 'memory-websocket-abuse';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const hasHigh = wsIssues.some(i => i.severity === 'high');

    findings.push({
      id: findId,
      category: 'memory-web-context',
      name: 'WebSocket Connection Abuse',
      description: `Detected ${wsIssues.length} WebSocket abuse indicator(s): ${wsIssues.map(i => i.description).join(' ')}. WebSocket connection abuse can cause memory leaks through unclosed connections, message buffer accumulation, and excessive connection creation. Each open WebSocket consumes memory for connection state, send/receive buffers, and associated JavaScript objects.`,
      severity: hasHigh ? 'high' : 'medium',
      requestIndex: idx,
      evidence: {
        issues: wsIssues.map(i => ({ type: i.type, severity: i.severity, ...(i.count ? { count: i.count } : {}), ...(i.created ? { created: i.created, closed: i.closed } : {}) })),
        url: path,
        method: req.request && req.request.method,
        isUpgrade: isWebSocketUpgrade
      },
      score: hasHigh ? 80 : 40
    });
  });

  // Cross-request analysis: detect multiple WS connections to same endpoint
  if (wsConnections.length >= 2) {
    const wsEndpoints = {};
    wsConnections.forEach(conn => {
      const key = conn.url;
      if (!wsEndpoints[key]) wsEndpoints[key] = [];
      wsEndpoints[key].push(conn);
    });

    Object.keys(wsEndpoints).forEach(endpoint => {
      const conns = wsEndpoints[endpoint];
      if (conns.length >= 3) {
        // Multiple WS connections to same endpoint - potential abuse
        const sortedConns = conns.sort((a, b) => a.timestamp - b.timestamp);
        const gaps = [];
        for (let i = 1; i < sortedConns.length; i++) {
          gaps.push(sortedConns[i].timestamp - sortedConns[i - 1].timestamp);
        }
        const avgGap = gaps.reduce((s, g) => s + g, 0) / gaps.length;

        // Rapid reconnection could indicate connection flooding
        if (avgGap < 1000) {
          const lastConn = sortedConns[sortedConns.length - 1];
          const findId = 'memory-websocket-flood';

          if (!requestFindings.has(lastConn.idx)) requestFindings.set(lastConn.idx, new Set());
          if (requestFindings.get(lastConn.idx).has(findId)) return;

          findings.push({
            id: findId,
            category: 'memory-web-context',
            name: 'WebSocket Connection Flooding',
            description: `Detected ${conns.length} WebSocket connections to \`${getPathname(endpoint)}\` with average reconnection gap of ${Math.round(avgGap)}ms. Rapid WebSocket reconnection floods can exhaust connection limits, memory, and CPU on both client and server.`,
            severity: 'high',
            requestIndex: lastConn.idx,
            evidence: {
              endpoint: getPathname(endpoint),
              connectionCount: conns.length,
              averageGapMs: Math.round(avgGap),
              timestamps: sortedConns.map(c => new Date(c.timestamp).toISOString())
            },
            score: 85
          });
        }
      }
    });
  }
}

// =========================
// DETECTOR 9: INDEXEDDB / STORAGE API ABUSE
// =========================
/**
 * Detect IndexedDB / Storage API Abuse:
 * - Excessive database creation
 * - Database creation without cleanup/deletion
 * - Storage event abuse
 * - Quota exhaustion patterns
 * - Unbounded object store growth
 */
function detectIndexedDBStorageAbuse(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const bodyText = getRequestBodyText(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);

    if (!bodyText) return;

    const idbIssues = [];

    // 1. Check for IndexedDB database creation patterns
    const idbOpenPatterns = bodyText.match(/indexedDB\.open\s*\(|window\.indexedDB\.open\s*\(/gi);
    const idbOpenCount = idbOpenPatterns ? idbOpenPatterns.length : 0;

    const idbDeletePatterns = bodyText.match(/indexedDB\.deleteDatabase\s*\(|\.close\s*\(\)/gi);
    const idbDeleteCount = idbDeletePatterns ? idbDeletePatterns.length : 0;

    if (idbOpenCount > 0) {
      if (idbOpenCount > idbDeleteCount + 3) {
        idbIssues.push({
          type: 'idb-excessive-databases',
          openCount: idbOpenCount,
          deleteCount: idbDeleteCount,
          severity: idbOpenCount > 10 ? 'high' : 'medium',
          description: `Detected ${idbOpenCount} IndexedDB database open/creation call(s) but only ${idbDeleteCount} database deletion/close calls. Unclosed IndexedDB databases maintain connections and consume memory/disk quota.`
        });
      }
    }

    // 2. Check for object store creation patterns
    const storeCreatePatterns = bodyText.match(/createObjectStore\s*\(/gi);
    const storeCreateCount = storeCreatePatterns ? storeCreatePatterns.length : 0;

    if (storeCreateCount > 5) {
      idbIssues.push({
        type: 'idb-excessive-stores',
        storeCount: storeCreateCount,
        severity: storeCreateCount > 20 ? 'high' : 'medium',
        description: `Detected ${storeCreateCount} object store creation(s). Excessive IndexedDB object stores consume database file space and can cause browser storage quota warnings.`
      });
    }

    // 3. Check for large data storage operations (put/add)
    const putPatterns = bodyText.match(/\.put\s*\(\s*(?:[^,)]{5000,})/gi);
    const addPatterns = bodyText.match(/\.add\s*\(\s*(?:[^,)]{5000,})/gi);
    if ((putPatterns && putPatterns.length > 0) || (addPatterns && addPatterns.length > 0)) {
      idbIssues.push({
        type: 'idb-large-objects',
        largePutCount: (putPatterns || []).length + (addPatterns || []).length,
        severity: 'medium',
        description: 'Detected IndexedDB \`.put()\` or \`.add()\` calls with very large objects (>5KB). Storing large objects in IndexedDB can quickly exhaust the browser storage quota and impact performance.'
      });
    }

    // 4. Check for getAllKeys / getAll without limit (potential unbounded growth)
    const unboundedReadPatterns = bodyText.match(/\.getAll\s*\(\s*\)/g);
    if (unboundedReadPatterns && unboundedReadPatterns.length > 0) {
      idbIssues.push({
        type: 'idb-unbounded-read',
        pattern: '.getAll()',
        count: unboundedReadPatterns.length,
        severity: 'medium',
        description: `Detected ${unboundedReadPatterns.length} \`.getAll()\` call(s) without a query or limit. Loading all records from a large object store into memory can cause OOM errors.`
      });
    }

    // 5. Check for storage event abuse (storage events fire on other tabs)
    if (bodyText.includes('window.addEventListener(\'storage\'')) {
      const storageEventListenerCount = (bodyText.match(/['"]storage['"]\s*,/gi) || []).length;
      if (storageEventListenerCount > 2) {
        idbIssues.push({
          type: 'idb-storage-event-abuse',
          listenerCount: storageEventListenerCount,
          severity: 'medium',
          description: `Detected ${storageEventListenerCount} storage event listeners. Storage events are broadcast to all tabs of the same origin, and excessive listeners can cause memory/CPU overhead.`
        });
      }
    }

    // 6. Check for transaction creation without explicit commit/abort
    const transactionPatterns = bodyText.match(/\.transaction\s*\(/gi);
    const transactionCompletePatterns = bodyText.match(/\.oncomplete|\.onerror|transaction\.abort\s*\(/gi);
    const transactionCount = transactionPatterns ? transactionPatterns.length : 0;
    const transactionResultCount = transactionCompletePatterns ? transactionCompletePatterns.length : 0;

    if (transactionCount > 0 && transactionResultCount < transactionCount) {
      idbIssues.push({
        type: 'idb-orphaned-transactions',
        transactionCount,
        completionCount: transactionResultCount,
        severity: 'medium',
        description: `Detected ${transactionCount} IndexedDB transaction(s) with only ${transactionResultCount} completion/abort handler(s). Orphaned transactions keep the database connection active and prevent memory cleanup.`
      });
    }

    // 7. Check for navigator.storage.estimate or persistent storage request
    if (/navigator\.storage\.(estimate|persist|persisted)\s*\(/i.test(bodyText)) {
      idbIssues.push({
        type: 'idb-storage-api-usage',
        severity: 'low',
        description: 'Request uses \`navigator.storage\` API. While legitimate, this API can be used to probe storage limits and potentially trigger quota management UI.'
      });
    }

    if (idbIssues.length === 0) return;

    const findId = 'memory-indexeddb-abuse';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const hasHigh = idbIssues.some(i => i.severity === 'high');

    findings.push({
      id: findId,
      category: 'memory-web-context',
      name: 'IndexedDB / Storage API Abuse',
      description: `Detected ${idbIssues.length} IndexedDB/storage abuse indicator(s): ${idbIssues.map(i => i.description).join(' ')}. IndexedDB abuse can exhaust browser storage quota, leak memory through unclosed databases, and cause performance degradation through unbounded queries and orphaned transactions.`,
      severity: hasHigh ? 'high' : 'medium',
      requestIndex: idx,
      evidence: {
        issues: idbIssues.map(i => ({ type: i.type, severity: i.severity, ...(i.openCount ? { openCount: i.openCount, deleteCount: i.deleteCount } : {}), ...(i.storeCount ? { storeCount: i.storeCount } : {}), ...(i.transactionCount ? { transactionCount: i.transactionCount } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: hasHigh ? 80 : 40
    });
  });
}

// =========================
// DETECTOR 10: EVENT LISTENER / TIMER LEAK INDICATORS
// =========================
/**
 * Detect Event Listener / Timer Leak Indicators:
 * - Repeated setInterval without clearInterval
 * - Repeated setTimeout loops without cleanup
 * - Event listener accumulation (added but never removed)
 * - Anonymous functions in listeners preventing removal
 * - Orphaned observer patterns (MutationObserver, ResizeObserver)
 * - Animation frame leaks (requestAnimationFrame without cancel)
 */
function detectEventListenerTimerLeak(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const bodyText = getRequestBodyText(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);

    if (!bodyText) return;

    const timerIssues = [];

    // 1. Check setInterval without clearInterval
    const setIntervalMatches = bodyText.match(/setInterval\s*\(/gi);
    const clearIntervalMatches = bodyText.match(/clearInterval\s*\(/gi);
    const setIntervalCount = setIntervalMatches ? setIntervalMatches.length : 0;
    const clearIntervalCount = clearIntervalMatches ? clearIntervalMatches.length : 0;

    if (setIntervalCount > 0 && setIntervalCount > clearIntervalCount + 2) {
      timerIssues.push({
        type: 'interval-without-clear',
        setCount: setIntervalCount,
        clearCount: clearIntervalCount,
        orphaned: setIntervalCount - clearIntervalCount,
        severity: setIntervalCount - clearIntervalCount > 5 ? 'high' : 'medium',
        description: `Detected ${setIntervalCount} \`setInterval()\` calls but only ${clearIntervalCount} \`clearInterval()\` calls. Orphaned intervals continue firing indefinitely, accumulating callback invocations and preventing garbage collection of captured variables.`
      });
    }

    // 2. Check for setTimeout loops (repeated setTimeout without cleanup)
    const setTimeoutMatches = bodyText.match(/setTimeout\s*\(/gi);
    const clearTimeoutMatches = bodyText.match(/clearTimeout\s*\(/gi);
    const setTimeoutCount = setTimeoutMatches ? setTimeoutMatches.length : 0;
    const clearTimeoutCount = clearTimeoutMatches ? clearTimeoutMatches.length : 0;

    if (setTimeoutCount > clearTimeoutCount + 5) {
      timerIssues.push({
        type: 'timeout-without-clear',
        setCount: setTimeoutCount,
        clearCount: clearTimeoutCount,
        orphaned: setTimeoutCount - clearTimeoutCount,
        severity: 'medium',
        description: `Detected ${setTimeoutCount} \`setTimeout()\` calls but only ${clearTimeoutCount} \`clearTimeout()\` calls. Orphaned timeouts keep the event loop active and prevent garbage collection.`
      });
    }

    // 3. Check for addEventListener without removeEventListener
    const addListenerCount = (bodyText.match(/addEventListener\s*\(/gi) || []).length;
    const removeListenerCount = (bodyText.match(/removeEventListener\s*\(/gi) || []).length;
    const onEventPatterns = (bodyText.match(/\.on\w+\s*=\s*function|\.on\w+\s*=\s*\(\)\s*=>/gi) || []).length;

    const totalListenerAttachments = addListenerCount + onEventPatterns;
    if (totalListenerAttachments > removeListenerCount + 5) {
      timerIssues.push({
        type: 'listener-without-remove',
        attached: totalListenerAttachments,
        removed: removeListenerCount,
        orphaned: totalListenerAttachments - removeListenerCount,
        severity: totalListenerAttachments - removeListenerCount > 20 ? 'high' : 'medium',
        description: `Detected ${totalListenerAttachments} event listener attachment(s) (\`addEventListener\` or \`.on...=\`) but only ${removeListenerCount} \`removeEventListener\` calls. Orphaned event listeners keep references to their callback functions and captured variables, preventing garbage collection.`
      });
    }

    // 4. Check for anonymous functions in addEventListener (cannot be removed)
    const anonListenerPatterns = bodyText.match(/addEventListener\s*\(\s*['"][^'"]+['"]\s*,\s*function\s*\(/gi);
    if (anonListenerPatterns && anonListenerPatterns.length > 3) {
      timerIssues.push({
        type: 'anonymous-listener-functions',
        count: anonListenerPatterns.length,
        severity: 'medium',
        description: `Detected ${anonListenerPatterns.length} anonymous functions in \`addEventListener()\`. Anonymous event listeners cannot be removed with \`removeEventListener()\`, causing permanent memory leaks if the DOM element is not destroyed.`
      });
    }

    // 5. Check for MutationObserver without disconnect
    const observerCreatePatterns = bodyText.match(/new\s+(?:MutationObserver|ResizeObserver|IntersectionObserver|PerformanceObserver)\s*\(/gi);
    const observerDisconnectPatterns = bodyText.match(/\.disconnect\s*\(\)/gi);
    const observerCreateCount = observerCreatePatterns ? observerCreatePatterns.length : 0;
    const observerDisconnectCount = observerDisconnectPatterns ? observerDisconnectPatterns.length : 0;

    if (observerCreateCount > observerDisconnectCount + 2) {
      timerIssues.push({
        type: 'observer-without-disconnect',
        observerCount: observerCreateCount,
        disconnectCount: observerDisconnectCount,
        orphaned: observerCreateCount - observerDisconnectCount,
        severity: observerCreateCount > 5 ? 'high' : 'medium',
        description: `Detected ${observerCreateCount} Observer creation(s) (\`MutationObserver\`, \`ResizeObserver\`, etc.) but only ${observerDisconnectCount} \`.disconnect()\` calls. Observers that are not disconnected continue to monitor DOM changes and consume memory/CPU.`
      });
    }

    // 6. Check for requestAnimationFrame without cancelAnimationFrame
    const rafPatterns = bodyText.match(/requestAnimationFrame\s*\(/gi);
    const cafPatterns = bodyText.match(/cancelAnimationFrame\s*\(/gi);
    const rafCount = rafPatterns ? rafPatterns.length : 0;
    const cafCount = cafPatterns ? cafPatterns.length : 0;

    if (rafCount > cafCount + 3) {
      timerIssues.push({
        type: 'animation-frame-without-cancel',
        rafCount,
        cafCount,
        orphaned: rafCount - cafCount,
        severity: 'medium',
        description: `Detected ${rafCount} \`requestAnimationFrame()\` calls but only ${cafCount} \`cancelAnimationFrame()\`. Uncancelled animation frames continue to fire, consuming CPU and preventing GC of captured objects.`
      });
    }

    // 7. Check for orphaned listener patterns on window/document
    const windowListeners = (bodyText.match(/window\.addEventListener|document\.addEventListener|body\.addEventListener/gi) || []).length;
    if (windowListeners > 5) {
      timerIssues.push({
        type: 'excessive-global-listeners',
        listenerCount: windowListeners,
        severity: 'low',
        description: `Detected ${windowListeners} event listeners attached to \`window\`, \`document\`, or \`body\`. Global event listeners accumulate over time and are only removed when the page is navigated away from, causing memory leaks in single-page applications.`
      });
    }

    // 8. Check for jQuery-like delegate/on patterns (common leak source)
    const jQueryOnPatterns = bodyText.match(/\$\([^)]+\)\.on\s*\(|jQuery\([^)]+\)\.on\s*\(|\.delegate\s*\(|\.live\s*\(/gi);
    if (jQueryOnPatterns && jQueryOnPatterns.length > 10) {
      timerIssues.push({
        type: 'jquery-excessive-delegates',
        count: jQueryOnPatterns.length,
        severity: 'medium',
        description: `Detected ${jQueryOnPatterns.length} jQuery event delegation pattern(s) (\`.on()\`, \`.delegate()\`). Excessive event delegations, especially on large containers, consume memory and degrade event dispatch performance.`
      });
    }

    if (timerIssues.length === 0) return;

    const findId = 'memory-event-timer-leak';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const hasHigh = timerIssues.some(i => i.severity === 'high');

    findings.push({
      id: findId,
      category: 'memory-web-context',
      name: 'Event Listener / Timer Leak Indicators',
      description: `Detected ${timerIssues.length} event/timer leak indicator(s): ${timerIssues.map(i => i.description).join(' ')}. Event listener and timer leaks are one of the most common causes of memory bloat in web applications. Orphaned listeners, intervals, timeouts, observers, and animation frames keep references to their callback scopes, preventing garbage collection and accumulating over time.`,
      severity: hasHigh ? 'high' : 'medium',
      requestIndex: idx,
      evidence: {
        issues: timerIssues.map(i => ({ type: i.type, severity: i.severity, ...(i.setCount ? { setCount: i.setCount, clearCount: i.clearCount, orphaned: i.orphaned } : {}), ...(i.attached ? { attached: i.attached, removed: i.removed, orphaned: i.orphaned } : {}), ...(i.observerCount ? { observerCount: i.observerCount, disconnectCount: i.disconnectCount } : {}), ...(i.count ? { count: i.count } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: hasHigh ? 80 : 40
    });
  });
}

