/**
 * Prototype Pollution Detection Engine
 *
 * Analyzes workflows and individual requests for prototype pollution
 * vulnerabilities in JavaScript/Node.js applications:
 *   - __proto__ Key Injection (direct keys in JSON/params)
 *   - constructor.prototype Manipulation (nested prototype paths)
 *   - Merge/Assign Function Abuse (merge targets with malicious keys)
 *   - URL-Encoded / Nested Param Pollution (encoded proto in query strings)
 *   - JSON Path / Deep Set Expressions (JSONPath-like expressions)
 *   - Array-Based Prototype Pollution (pollution via array methods)
 *   - HTTP Header-Based Pollution (headers merged into objects)
 *   - Cross-Request Merge Chain Detection (sequenced merge operations)
 *   - Cookie/Body-Based Prototype Pollution (cookie/body proto keys)
 *   - Sensitive Property Override Detection (overriding Object.prototype)
 *   - Nested Merge Loop Detection (deeply nested proto at multiple levels)
 *   - Response-Based Prototype Pollution (reflected proto in responses)
 */

// =========================
// PUBLIC INTERFACE
// =========================

/**
 * Run all prototype pollution detectors against a workflow.
 * Returns an array of flaw findings compatible with the existing flaws engine.
 */
export function detectPrototypePollution(workflow) {
  if (!workflow || !Array.isArray(workflow.requests) || workflow.requests.length === 0) {
    return [];
  }

  const sortedReqs = [...workflow.requests].sort((a, b) => {
    return new Date(a.startedDateTime).getTime() - new Date(b.startedDateTime).getTime();
  });

  const findings = [];

  // Run each detector
  detectProtoKeyInjection(sortedReqs, findings);
  detectConstructorPrototypeManipulation(sortedReqs, findings);
  detectMergeAssignAbuse(sortedReqs, findings);
  detectURLEncodedNestedParamPollution(sortedReqs, findings);
  detectJSONPathDeepSetExpressions(sortedReqs, findings);
  detectArrayBasedProtoPollution(sortedReqs, findings);
  detectHTTPHeaderBasedPollution(sortedReqs, findings);
  detectCrossRequestMergeChain(sortedReqs, findings);
  detectCookieBodyBasedPollution(sortedReqs, findings);
  detectSensitivePropertyOverride(sortedReqs, findings);
  detectNestedMergeLoop(sortedReqs, findings);
  detectResponseBasedProtoPollution(sortedReqs, findings);

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
 * Deep scan an object for a given key (e.g., '__proto__' or 'constructor').
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

/**
 * Deep traverse an object to find chains like constructor.prototype.something
 * Returns array of { path, value } matches.
 */
function deepFindPrototypeChain(obj, path = '', maxDepth = 6) {
  const results = [];
  if (!obj || typeof obj !== 'object' || maxDepth <= 0) return results;

  Object.keys(obj).forEach(k => {
    const currentPath = path ? `${path}.${k}` : k;

    // Check if this key is 'constructor' and its value has 'prototype'
    if (k === 'constructor' && obj[k] && typeof obj[k] === 'object') {
      const protoVal = obj[k].prototype;
      if (protoVal !== undefined) {
        results.push({
          path: currentPath,
          depth: currentPath.split('.').filter(Boolean).length,
          hasPrototype: true,
          prototypeKeys: typeof protoVal === 'object' && protoVal !== null ? Object.keys(protoVal) : []
        });
      }
      // Recurse into constructor value
      results.push(...deepFindPrototypeChain(obj[k], currentPath, maxDepth - 1));
    }

    // Recurse into non-null objects
    if (obj[k] && typeof obj[k] === 'object' && !Array.isArray(obj[k])) {
      results.push(...deepFindPrototypeChain(obj[k], currentPath, maxDepth - 1));
    }
  });

  return results;
}

/**
 * Deep find merge/assign function names in object structure.
 */
function deepFindMergeTargets(obj, path = '', maxDepth = 6) {
  const results = [];
  const MERGE_KEYS = ['merge', 'assign', 'extend', 'copy', 'clone', 'set', 'update', 'patch', 'options', 'config', 'settings'];
  if (!obj || typeof obj !== 'object' || maxDepth <= 0) return results;

  Object.keys(obj).forEach(k => {
    const currentPath = path ? `${path}.${k}` : k;

    if (MERGE_KEYS.some(mk => k.toLowerCase().includes(mk))) {
      results.push({ path: currentPath, key: k, value: obj[k] });
    }

    if (obj[k] && typeof obj[k] === 'object') {
      results.push(...deepFindMergeTargets(obj[k], currentPath, maxDepth - 1));
    }
  });

  return results;
}

/**
 * Check if a string value contains prototype pollution patterns.
 */
function containsProtoPollutionPattern(val) {
  if (!val || typeof val !== 'string') return false;
  return /__proto__|constructor\.prototype|prototype\.\w+/.test(val);
}

/**
 * Determine severity based on context and findings.
 */
function severityFromFindings(issues, highTypes) {
  if (!issues || issues.length === 0) return 'low';
  const hasHigh = issues.some(i => highTypes.includes(i.type));
  return hasHigh ? 'high' : 'medium';
}

// =========================
// CONSTANTS
// =========================

// Known merge/assign/utility function names commonly vulnerable
const MERGE_UTILITY_NAMES = [
  'merge', 'deepMerge', 'deep_merge', 'mergeDeep', 'mergeRecursive',
  'assign', 'extend', 'deepExtend', 'deep_extend',
  'copy', 'deepCopy', 'deep_copy', 'clone', 'deepClone',
  'set', 'setIn', 'setPath', 'setNested',
  'update', 'patch', 'applyPatch',
  'flatten', 'unflatten', 'expand', 'objectSpread',
  'options', 'defaults', 'config', 'settings',
  'hydrate', 'deserialize', 'restore',
  'normalize', 'sanitize', 'process',
  'transform', 'mapKeys', 'mapValues',
  'parse', 'stringify', 'traverse',
  'union', 'combine', 'mix', 'mixin'
];

// Sensitive Object.prototype properties that should never be overridden
const SENSITIVE_PROTOTYPE_PROPERTIES = [
  'toString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf',
  'propertyIsEnumerable', 'toLocaleString',
  'constructor', '__proto__', '__defineGetter__',
  '__defineSetter__', '__lookupGetter__', '__lookupSetter__'
];

// Known endpoints that perform merge/assign operations
const MERGE_ENDPOINT_PATTERNS = [
  /merge|assign|extend|copy|clone|patch|sync|import/i,
  /config|configure|settings|options|preference/i,
  /profile|update|save|store|persist/i,
  /api\/v\d+\/.*merge/i,
  /graphql/i
];

// URL param names that are suspicious for prototype pollution
const SUSPICIOUS_URL_PATTERNS = [
  /__proto__/i,
  /__proto%5F%5F/i,
  /__proto\_\_/i,
  /constructor%5Bprototype%5D/i,
  /constructor\[prototype\]/i,
  /options\[__proto__\]/i,
  /config\[__proto__\]/i,
  /settings\[__proto__\]/i
];

// =========================
// DETECTOR 1: __proto__ KEY INJECTION
// =========================
/**
 * Detect direct __proto__ key injection in:
 * - JSON request body (top-level and nested)
 * - Query string parameters
 * - GraphQL variables
 * - URL-encoded body parameters
 */
function detectProtoKeyInjection(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const bodyText = getRequestBodyText(req);
    const params = getAllParams(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);

    const issues = [];

    // 1. Check JSON body for __proto__ keys
    if (bodyText) {
      const body = tryParseJSON(bodyText);

      // Direct string match in raw body (catches all occurrences)
      if (bodyText.includes('__proto__') || bodyText.includes('"__proto__"') || bodyText.includes("'__proto__'")) {
        // Find all occurrences with context
        const protoMatches = bodyText.match(/"__proto__"\s*:/g);
        const protoMatchesCount = protoMatches ? protoMatches.length : 0;

        if (body && typeof body === 'object') {
          // Deep scan for __proto__ at any nesting level
          const found = deepFindKey(body, '__proto__');
          if (found.length > 0) {
            issues.push({
              type: 'proto-key-json-deep',
              count: found.length,
              paths: found.map(f => f.path).slice(0, 5),
              severity: 'high',
              description: `Found \`__proto__\` key at ${found.length} location(s) in JSON body (paths: ${found.map(f => f.path).slice(0, 5).join(', ')}). Direct \`__proto__\` keys in JSON allow attackers to pollute Object.prototype during object merge or assignment operations.`
            });
          }
        } else {
          // Raw text matched but couldn't parse — still flag it
          issues.push({
            type: 'proto-key-raw-body',
            count: protoMatchesCount,
            severity: 'high',
            description: `Found \`__proto__\` key pattern ${protoMatchesCount} time(s) in request body. Raw \`__proto__\` keys can pollute Object.prototype during JSON.parse + merge operations.`
          });
        }
      }

      // Check for constructor.prototype in body
      if (bodyText.includes('constructor.prototype') || bodyText.includes('"constructor"') && bodyText.includes('"prototype"')) {
        if (body && typeof body === 'object') {
          const chainResults = deepFindPrototypeChain(body);
          if (chainResults.length > 0) {
            issues.push({
              type: 'proto-key-constructor-deep',
              count: chainResults.length,
              paths: chainResults.map(c => c.path).slice(0, 5),
              severity: 'high',
              description: `Found \`constructor.prototype\` chain at ${chainResults.length} location(s) in JSON body. This bypasses shallow \`__proto__\` filters while achieving the same prototype pollution effect.`
            });
          }
        }
      }
    }

    // 2. Check query string params for __proto__ or constructor[prototype]
    if (req.request && Array.isArray(req.request.queryString)) {
      req.request.queryString.forEach(q => {
        const name = q.name || '';
        const val = q.value || '';

        if (/__proto__/i.test(name)) {
          issues.push({
            type: 'proto-key-query-param',
            param: name,
            value: val.substring(0, 80),
            severity: 'high',
            description: `Query parameter \`${name}\` contains \`__proto__\`. URL query parameters with \`__proto__\` keys can pollute Object.prototype when parsed by vulnerable query string parsers (e.g., qs, express, body-parser).`
          });
        }

        if (/constructor\[(prototype|__proto__)\]/i.test(name) || /constructor\.prototype/i.test(name)) {
          issues.push({
            type: 'proto-key-constructor-query',
            param: name,
            value: val.substring(0, 80),
            severity: 'high',
            description: `Query parameter \`${name}\` uses \`constructor.prototype\` notation. This bypasses \`__proto__\` filters while still achieving prototype pollution.`
          });
        }
      });
    }

    // 3. Check GraphQL variables for __proto__
    if (req._graphql && req._graphql.operations) {
      req._graphql.operations.forEach((op, opIdx) => {
        const vars = op.variables || {};
        const found = deepFindKey(vars, '__proto__');
        if (found.length > 0) {
          issues.push({
            type: 'proto-key-graphql',
            count: found.length,
            paths: found.map(f => f.path).slice(0, 5),
            operation: op.operationName || 'anonymous',
            severity: 'high',
            description: `Found \`__proto__\` key at ${found.length} location(s) in GraphQL variables for operation \`${op.operationName || 'anonymous'}\`. GraphQL variable injection with \`__proto__\` can pollute Object.prototype.`
          });
        }
      });
    }

    // 4. Check for __proto__ in URL path itself
    if (/__proto__/i.test(path)) {
      issues.push({
        type: 'proto-key-url-path',
        severity: 'high',
        description: `URL path contains \`__proto__\`: \`${path}\`. While less common, some frameworks process URL segments into objects, enabling path-based prototype pollution.`
      });
    }

    if (issues.length === 0) return;

    const findId = 'prototype-injection';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const overallSeverity = issues.some(i => i.severity === 'high') ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'prototype-pollution',
      name: `__proto__ Key Injection (${issues.length} vector${issues.length > 1 ? 's' : ''})`,
      description: `Detected ${issues.length} prototype pollution vector(s) via \`__proto__\` key injection: ${issues.map(i => i.description).join(' ')}. Direct \`__proto__\` injection is the most common prototype pollution vector, allowing attackers to modify Object.prototype and introduce properties that affect all objects in the application.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        vectors: issues.map(i => ({ type: i.type, ...(i.param ? { param: i.param } : {}), ...(i.paths ? { paths: i.paths.slice(0, 3) } : {}), ...(i.count ? { count: i.count } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: overallSeverity === 'high' ? 85 : 50
    });
  });
}

// =========================
// DETECTOR 2: constructor.prototype MANIPULATION
// =========================
/**
 * Detect constructor.prototype manipulation:
 * - Nested constructor.prototype keys in JSON body
 * - constructor.prototype in query params
 * - Deep traversal bypassing shallow __proto__ filters
 * - Multiple nesting levels of constructor.prototype
 */
function detectConstructorPrototypeManipulation(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const bodyText = getRequestBodyText(req);
    const params = getAllParams(req);
    const path = getPathname(req.request && req.request.url);

    const issues = [];

    // 1. Deep scan JSON body for constructor.prototype chains
    if (bodyText) {
      const body = tryParseJSON(bodyText);
      if (body && typeof body === 'object') {
        const chains = deepFindPrototypeChain(body);

        // Group by nesting depth
        const deepChains = chains.filter(c => c.depth >= 2);
        const shallowChains = chains.filter(c => c.depth < 2);

        if (deepChains.length > 0) {
          issues.push({
            type: 'constructor-prototype-deep',
            count: deepChains.length,
            paths: deepChains.map(c => c.path).slice(0, 5),
            maxDepth: Math.max(...deepChains.map(c => c.depth)),
            severity: 'high',
            description: `Found ${deepChains.length} deep \`constructor.prototype\` chain(s) (max depth: ${Math.max(...deepChains.map(c => c.depth))}) in JSON body. Deeply nested \`constructor.prototype\` chains are used to bypass filters that only check the first level of nesting.`
          });
        }

        // Check for alternative constructor patterns
        const constructorRefs = deepFindKey(body, 'constructor');
        const ctorWithProto = constructorRefs.filter(cr => cr.value && typeof cr.value === 'object' && (cr.value.prototype !== undefined || cr.value.__proto__ !== undefined));

        if (ctorWithProto.length > 0) {
          issues.push({
            type: 'constructor-with-prototype',
            count: ctorWithProto.length,
            paths: ctorWithProto.map(c => c.path).slice(0, 5),
            severity: 'high',
            description: `Found \`constructor\` key at ${ctorWithProto.length} location(s) with \`prototype\` or \`__proto__\` sub-property. This is a known prototype pollution pattern.`
          });
        }

        // Check for nested __proto__ inside constructor
        const nestedProtoInCtor = constructorRefs.filter(cr => cr.value && typeof cr.value === 'object' && cr.value.__proto__ !== undefined);
        if (nestedProtoInCtor.length > 0) {
          issues.push({
            type: 'proto-inside-constructor',
            count: nestedProtoInCtor.length,
            paths: nestedProtoInCtor.map(c => c.path).slice(0, 5),
            severity: 'high',
            description: `Found \`__proto__\` inside \`constructor\` at ${nestedProtoInCtor.length} location(s). This is a known bypass technique for filters that block \`__proto__\` only at the top level.`
          });
        }
      }
    }

    // 2. Check params for constructor.prototype patterns
    Object.keys(params).forEach(key => {
      if (/constructor\b.*\bprototype\b/i.test(key) || key === 'constructor.prototype' || key.includes('[constructor][prototype]')) {
        issues.push({
          type: 'constructor-prototype-param',
          param: key,
          value: String(params[key]).substring(0, 80),
          severity: 'high',
          description: `Parameter \`${key}\` uses \`constructor.prototype\` notation. This is a known bypass technique where filters blocking \`__proto__\` but not \`constructor.prototype\` are circumvented.`
        });
      }

      // Check for encoded constructor[prototype]
      if (/constructor%5Bprototype%5D|constructor\[prototype\]/i.test(key)) {
        issues.push({
          type: 'constructor-prototype-encoded',
          param: key,
          value: String(params[key]).substring(0, 80),
          severity: 'high',
          description: `Parameter \`${key}\` uses URL-encoded \`constructor.prototype\` notation. This bypasses filters that check raw parameter names.`
        });
      }
    });

    if (issues.length === 0) return;

    const findId = 'prototype-constructor-manipulation';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    findings.push({
      id: findId,
      category: 'prototype-pollution',
      name: 'constructor.prototype Manipulation',
      description: `Detected ${issues.length} \`constructor.prototype\` manipulation vector(s): ${issues.map(i => i.description).join(' ')}. The \`constructor.prototype\` chain is an alternative to direct \`__proto__\` injection, often used to bypass security filters.`,
      severity: 'high',
      requestIndex: idx,
      evidence: {
        vectors: issues.map(i => ({ type: i.type, ...(i.param ? { param: i.param } : {}), ...(i.paths ? { paths: i.paths.slice(0, 3) } : {}), ...(i.count ? { count: i.count } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: 85
    });
  });
}

// =========================
// DETECTOR 3: MERGE/ASSIGN FUNCTION ABUSE
// =========================
/**
 * Detect merge/assign function abuse:
 * - Parameters targeting merge/assign functions
 * - Endpoints named after merge utilities
 * - Deep merge operations with attacker-controlled data
 * - Options/config merging with prototype keys
 */
function detectMergeAssignAbuse(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const bodyText = getRequestBodyText(req);
    const params = getAllParams(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);

    const issues = [];

    // 1. Check if the endpoint itself suggests a merge operation
    const isMergeEndpoint = MERGE_ENDPOINT_PATTERNS.some(p => p.test(path));
    const isMutating = isMutatingRequest(req);

    if (isMergeEndpoint && isMutating) {
      // Check for potential polluting payloads
      const body = bodyText ? tryParseJSON(bodyText) : null;

      if (body && typeof body === 'object') {
        // Check for merge-like parameter names in the body
        const mergeTargets = deepFindMergeTargets(body);
        if (mergeTargets.length > 0) {
          // Check if any of the merge targets contain __proto__ or constructor.prototype
          const pollutedTargets = mergeTargets.filter(mt => {
            if (typeof mt.value === 'object' && mt.value !== null) {
              const hasProto = deepFindKey(mt.value, '__proto__').length > 0;
              const hasCtorProto = deepFindPrototypeChain(mt.value).length > 0;
              return hasProto || hasCtorProto;
            }
            return containsProtoPollutionPattern(String(mt.value));
          });

          if (pollutedTargets.length > 0) {
            issues.push({
              type: 'merge-param-pollution',
              count: pollutedTargets.length,
              targets: pollutedTargets.map(pt => pt.path),
              severity: 'high',
              description: `Found ${pollutedTargets.length} merge target(s) containing prototype pollution keys in endpoint \`${path}\`. Endpoints that perform object merging with attacker-controlled data are prime targets for prototype pollution. Affected target(s): ${pollutedTargets.map(pt => pt.path).join(', ')}.`
            });
          }
        }

        // Check if the body contains keys like 'options', 'config', 'settings' with proto keys
        ['options', 'config', 'settings', 'defaults', 'params'].forEach(mergeKey => {
          if (body[mergeKey] && typeof body[mergeKey] === 'object') {
            const hasProto = deepFindKey(body[mergeKey], '__proto__').length > 0;
            const hasConstructorChain = deepFindPrototypeChain(body[mergeKey]).length > 0;
            if (hasProto || hasConstructorChain) {
              issues.push({
                type: 'merge-config-pollution',
                configKey: mergeKey,
                severity: 'high',
                description: `Configuration object \`${mergeKey}\` in request body contains prototype pollution keys. Since configuration/options objects are frequently merged with defaults, this can achieve prototype pollution.`
              });
            }
          }
        });
      }

      // Even without body, flag the merge endpoint
      if (!bodyText || issues.length === 0) {
        // Check if there are any __proto__ parameters in URL
        const hasProtoParam = Object.keys(params).some(k => /__proto__|constructor\.prototype/i.test(k));
        if (hasProtoParam) {
          issues.push({
            type: 'merge-endpoint-proto-param',
            severity: 'high',
            description: `Merge endpoint \`${path}\` receives request with \`__proto__\` or \`constructor.prototype\` parameters. This is a high-risk indicator for prototype pollution attacks.`
          });
        }
      }
    }

    // 2. Check for parameters with merge utility names that have suspicious values
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      const isMergeName = MERGE_UTILITY_NAMES.some(mn => {
        return lowerKey === mn.toLowerCase() || lowerKey.includes(mn.toLowerCase());
      });

      if (!isMergeName) return;

      const val = String(params[key]);

      // If the value looks like an object (JSON string) or contains proto patterns
      if (val.startsWith('{') || val.startsWith('[')) {
        const parsed = tryParseJSON(val);
        if (parsed && typeof parsed === 'object') {
          const hasProto = deepFindKey(parsed, '__proto__').length > 0;
          const hasConstructorChain = deepFindPrototypeChain(parsed).length > 0;
          if (hasProto || hasConstructorChain) {
            issues.push({
              type: 'merge-utility-param',
              param: key,
              severity: 'high',
              description: `Parameter \`${key}\` (named after a merge utility) has a JSON value containing prototype pollution keys. Parameters with merge-related names passed to vulnerable libraries are a known prototype pollution vector.`
            });
          }
        }
      }

      // Check string value for proto patterns
      if (containsProtoPollutionPattern(val)) {
        issues.push({
          type: 'merge-utility-proto-value',
          param: key,
          severity: 'high',
          description: `Parameter \`${key}\` (named after a merge utility) contains a string value with \`__proto__\` or \`constructor.prototype\` patterns.`
        });
      }
    });

    if (issues.length === 0) return;

    const findId = 'prototype-merge-abuse';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    findings.push({
      id: findId,
      category: 'prototype-pollution',
      name: 'Merge/Assign Function Abuse',
      description: `Detected ${issues.length} merge/assign function abuse indicator(s): ${issues.map(i => i.description).join(' ')}. Object merge and assign operations are the most common execution context for prototype pollution — vulnerable libraries like lodash.merge, jQuery.extend, and Object.assign will propagate \`__proto__\` properties if not explicitly filtered.`,
      severity: 'high',
      requestIndex: idx,
      evidence: {
        vectors: issues.map(i => ({ type: i.type, ...(i.param ? { param: i.param } : {}), ...(i.targets ? { targets: i.targets.slice(0, 3) } : {}), ...(i.configKey ? { configKey: i.configKey } : {}) })),
        url: path,
        method: req.request && req.request.method,
        isMergeEndpoint
      },
      score: 85
    });
  });
}

// =========================
// DETECTOR 4: URL-ENCODED / NESTED PARAM POLLUTION
// =========================
/**
 * Detect URL-encoded and nested parameter-based prototype pollution:
 * - __proto__[key]=value in URL params
 * - constructor[prototype][key]=value
 * - JSON-like nested parameter parsing
 * - Array notation pollution (__proto__[0]=value)
 * - Mixed encoding bypass attempts
 */
function detectURLEncodedNestedParamPollution(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const path = getPathname(req.request && req.request.url);

    const issues = [];

    // 1. Check parameter names for bracket notation proto pollution
    Object.keys(params).forEach(key => {
      // __proto__[anything] pattern
      if (/^__proto__\[/i.test(key) || /^__proto__\./i.test(key)) {
        issues.push({
          type: 'bracket-proto-param',
          param: key,
          value: String(params[key]).substring(0, 60),
          severity: 'high',
          description: `Parameter \`${key}\` uses bracket notation with \`__proto__\`. Bracket notation like \`__proto__[pollutedKey]=value\` is a classic prototype pollution vector in query string parsers and Express.js applications.`
        });
      }

      // constructor[prototype][anything] pattern
      if (/^constructor\[prototype\]/i.test(key) || /^constructor\.prototype\./i.test(key)) {
        issues.push({
          type: 'bracket-constructor-prototype',
          param: key,
          value: String(params[key]).substring(0, 60),
          severity: 'high',
          description: `Parameter \`${key}\` uses bracket/dot notation with \`constructor.prototype\`. This bypasses \`__proto__\` filters while achieving the same prototype pollution effect via the constructor chain.`
        });
      }

      // options[__proto__][key] = value pattern (nested merge)
      if (/options?\[__proto__\]/i.test(key) || /config\[__proto__\]/i.test(key) || /settings\[__proto__\]/i.test(key)) {
        issues.push({
          type: 'nested-merge-proto',
          param: key,
          value: String(params[key]).substring(0, 60),
          severity: 'high',
          description: `Parameter \`${key}\` uses nested bracket notation with \`__proto__\` inside a configuration object. This exploits vulnerable merge functions that recursively process nested objects.`
        });
      }

      // Prototype array notation: __proto__[0] or prototype[__proto__]
      if (/prototype\[__proto__\]/i.test(key) || /\w+\[__proto__\]/i.test(key)) {
        issues.push({
          type: 'array-proto-notation',
          param: key,
          value: String(params[key]).substring(0, 60),
          severity: 'high',
          description: `Parameter \`${key}\` uses array/dictionary notation that could pollute prototypes when processed by vulnerable parsers.`
        });
      }

      // URL-encoded variants
      if (/%5F%5Fproto%5F%5F/i.test(key) || /%5Fproto%5F/i.test(key)) {
        issues.push({
          type: 'url-encoded-proto',
          param: key,
          value: String(params[key]).substring(0, 60),
          severity: 'high',
          description: `Parameter \`${key}\` uses URL-encoded \`__proto__\` (\`%5F%5Fproto%5F%5F\`). URL encoding can bypass WAF filters and input validation that checks for the literal \`__proto__\` string.`
        });
      }
    });

    // 2. Check for deep nesting that could indicate recursive merge exploitation
    const nestedKeys = Object.keys(params).filter(k => k.includes('[') && k.includes(']'));
    if (nestedKeys.length >= 3) {
      // Multiple nested keys might be an attempt to exploit deep merge
      const hasProtoRelated = nestedKeys.some(k => /proto|constructor|prototype/i.test(k));
      if (hasProtoRelated) {
        issues.push({
          type: 'deep-nested-params',
          count: nestedKeys.length,
          keys: nestedKeys.slice(0, 8),
          severity: 'medium',
          description: `Found ${nestedKeys.length} nested bracket-notation parameters (${nestedKeys.slice(0, 8).join(', ')}). Deeply nested parameters combined with vulnerable merge utilities can enable prototype pollution.`
        });
      }
    }

    if (issues.length === 0) return;

    const findId = 'prototype-url-encoded-param';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const overallSeverity = issues.some(i => i.severity === 'high') ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'prototype-pollution',
      name: 'URL-Encoded / Nested Parameter Pollution',
      description: `Detected ${issues.length} URL-encoded or nested parameter-based prototype pollution vector(s): ${issues.map(i => i.description).join(' ')}. Query string parsers that support nested/bracket notation are a common entry point for prototype pollution attacks.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        vectors: issues.map(i => ({ type: i.type, param: i.param, ...(i.value ? { valueSample: i.value.substring(0, 40) } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: overallSeverity === 'high' ? 80 : 45
    });
  });
}

// =========================
// DETECTOR 5: JSON PATH / DEEP SET EXPRESSIONS
// =========================
/**
 * Detect JSONPath-like expressions and deep set operations:
 * - $.constructor.prototype / $.__proto__ patterns
 * - lodash _.set / _.setWith expressions
 * - JSONPath notation in parameters
 * - Deep property access expressions
 */
function detectJSONPathDeepSetExpressions(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const bodyText = getRequestBodyText(req);
    const params = getAllParams(req);
    const path = getPathname(req.request && req.request.url);

    const issues = [];

    // JSONPath-like expressions
    const jsonPathPatterns = [
      /\$\.__proto__/i,
      /\$\.constructor\.prototype/i,
      /\$\[['"]__proto__['"]\]/i,
      /\$\[['"]constructor['"]\]\[['"]prototype['"]\]/i,
      /\.__proto__\.\w+/i,
      /\.constructor\.prototype\.\w+/i
    ];

    // 1. Check all text values for JSONPath patterns
    const allTextValues = [];
    Object.keys(params).forEach(k => allTextValues.push(k));
    Object.values(params).forEach(v => allTextValues.push(String(v)));
    if (bodyText) allTextValues.push(bodyText);

    allTextValues.forEach(txt => {
      jsonPathPatterns.forEach(pattern => {
        if (pattern.test(txt)) {
          const match = txt.match(pattern);
          if (match && !issues.some(i => i.pattern && i.pattern.includes(match[0]))) {
            issues.push({
              type: 'jsonpath-expression',
              pattern: match[0].substring(0, 50),
              severity: 'high',
              description: `JSONPath-like expression detected: \`${match[0].substring(0, 50)}\`. JSONPath expressions targeting \`__proto__\` or \`constructor.prototype\` can be used to traverse and pollute object prototypes.`
            });
          }
        }
      });
    });

    // 2. Check for deep set operation parameters
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (/^(path|key|prop|property|attribute|field|setPath|set_path|jsonpath)$/i.test(lowerKey)) {
        const val = String(params[key]);
        if (containsProtoPollutionPattern(val)) {
          issues.push({
            type: 'deep-set-path-param',
            param: key,
            value: val.substring(0, 80),
            severity: 'high',
            description: `Deep set path parameter \`${key}\` contains \`__proto__\` or \`constructor.prototype\` in its value (\`${val.substring(0, 60)}\`). Libraries like lodash.set or immer that accept user-controlled paths can be exploited for prototype pollution.`
          });
        }
      }

      // Check for value parameters that look like path expressions
      if (/^(val|value|data|obj|target)$/i.test(lowerKey)) {
        const val = String(params[key]);
        if (containsProtoPollutionPattern(val)) {
          issues.push({
            type: 'deep-set-value-path',
            param: key,
            value: val.substring(0, 80),
            severity: 'medium',
            description: `Parameter \`${key}\` contains a path-like value referencing \`__proto__\` or \`constructor.prototype\`. This may indicate a deep set operation with attacker-controlled value path.`
          });
        }
      }
    });

    // 3. Check body for dotted paths that target prototype
    if (bodyText) {
      // Check for simple path string values that could be used with _.set
      const body = tryParseJSON(bodyText);
      if (body && typeof body === 'object' && !Array.isArray(body)) {
        // Look for parameters named 'path' or 'key' with __proto__ values
        ['path', 'paths', 'key', 'keys', 'property', 'properties'].forEach(pathKey => {
          if (body[pathKey] && typeof body[pathKey] === 'string') {
            if (containsProtoPollutionPattern(body[pathKey])) {
              if (!issues.some(i => i.type === 'deep-set-path-body')) {
                issues.push({
                  type: 'deep-set-path-body',
                  param: pathKey,
                  value: body[pathKey].substring(0, 80),
                  severity: 'high',
                  description: `Body field \`${pathKey}\` contains a path value targeting \`__proto__\` or \`constructor.prototype\`: \`${body[pathKey].substring(0, 60)}\`. This is a strong indicator of a deep set prototype pollution attack.`
                });
              }
            }
          }
        });
      }
    }

    if (issues.length === 0) return;

    const findId = 'prototype-jsonpath-deepset';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const overallSeverity = issues.some(i => i.severity === 'high') ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'prototype-pollution',
      name: 'JSONPath / Deep Set Expression Injection',
      description: `Detected ${issues.length} JSONPath or deep set expression indicator(s): ${issues.map(i => i.description).join(' ')}. Libraries supporting JSONPath, lodash.set, or deep property assignment with user-controlled paths can be exploited for prototype pollution.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        vectors: issues.map(i => ({ type: i.type, ...(i.pattern ? { pattern: i.pattern } : {}), ...(i.param ? { param: i.param } : {}), ...(i.value ? { valueSample: i.value.substring(0, 50) } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: overallSeverity === 'high' ? 80 : 45
    });
  });
}

// =========================
// DETECTOR 6: ARRAY-BASED PROTOTYPE POLLUTION
// =========================
/**
 * Detect array-based prototype pollution attempts:
 * - __proto__ as array element
 * - constructor.prototype via array methods
 * - Array.prototype modifications via pollution
 * - Sparse array pollution patterns
 */
function detectArrayBasedProtoPollution(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const bodyText = getRequestBodyText(req);
    const params = getAllParams(req);
    const path = getPathname(req.request && req.request.url);

    const issues = [];

    // 1. Check JSON body for array-based pollution
    if (bodyText) {
      const body = tryParseJSON(bodyText);

      // Check if top-level is an array with __proto__ element
      if (bodyText.includes('__proto__')) {
        const body = tryParseJSON(bodyText);
        if (Array.isArray(body)) {
          // Arrays with __proto__ key set
          if (body.__proto__ !== undefined) {
            issues.push({
              type: 'array-proto-property',
              severity: 'high',
              description: 'Request body is an array with a \`__proto__\` property set. Arrays with \`__proto__\` properties can pollute Array.prototype when merged or assigned.'
            });
          }

          // Check array elements for __proto__ or constructor.prototype
          body.forEach((item, itemIdx) => {
            if (item && typeof item === 'object') {
              const hasProto = deepFindKey(item, '__proto__').length > 0;
              const hasCtor = deepFindPrototypeChain(item).length > 0;
              if (hasProto || hasCtor) {
                issues.push({
                  type: 'array-element-proto',
                  elementIndex: itemIdx,
                  severity: 'high',
                  description: `Array element at index ${itemIdx} contains prototype pollution keys. Array elements with \`__proto__\` or \`constructor.prototype\` keys can pollute prototypes when the array is recursively merged.`
                });
              }
            }
          });
        } else if (body && typeof body === 'object') {
          // Check for keys that look like array indices (numerical) with proto values
          Object.keys(body).forEach(k => {
            if (/^\d+$/.test(k)) {
              const val = body[k];
              if (val && typeof val === 'object') {
                const hasProto = deepFindKey(val, '__proto__').length > 0;
                if (hasProto) {
                  issues.push({
                    type: 'numeric-key-proto',
                    key: k,
                    severity: 'high',
                    description: `Object has numeric key \`${k}\` whose value contains \`__proto__\`. Numeric keys with prototype pollution payloads may exploit array-notation parsing vulnerabilities.`
                  });
                }
              }
            }
          });
        }
      }

      // Check for array-like params with proto keys
      if (body && typeof body === 'object') {
        Object.keys(body).forEach(k => {
          if (Array.isArray(body[k])) {
            const arr = body[k];
            if (arr.__proto__ !== undefined) {
              issues.push({
                type: 'nested-array-proto',
                key: k,
                severity: 'high',
                description: `Nested array \`${k}\` has a \`__proto__\` property. This can pollute Array.prototype when the parent object is recursively merged.`
              });
            }
            arr.forEach((item, idx) => {
              if (item && typeof item === 'object') {
                const hasProto = deepFindKey(item, '__proto__').length > 0;
                if (hasProto) {
                  issues.push({
                    type: 'nested-array-element-proto',
                    key: `${k}[${idx}]`,
                    severity: 'high',
                    description: `Element \`${k}[${idx}]\` contains \`__proto__\` keys inside an array. Array elements with prototype pollution keys can achieve pollution through recursive merge.`
                  });
                }
              }
            });
          }
        });
      }
    }

    // 2. Check query params for array-style pollution (param[0]=value)
    Object.keys(params).forEach(key => {
      if (/^__proto__\[\d+\]/i.test(key)) {
        issues.push({
          type: 'array-index-proto-param',
          param: key,
          value: String(params[key]).substring(0, 60),
          severity: 'high',
          description: `Parameter \`${key}\` uses array index notation with \`__proto__\`. This can pollute Array.prototype through vulnerable query string parsers.`
        });
      }

      // Check for prototype[0] or similar
      if (/prototype\[\d+\]/i.test(key)) {
        issues.push({
          type: 'prototype-array-index',
          param: key,
          value: String(params[key]).substring(0, 60),
          severity: 'high',
          description: `Parameter \`${key}\` uses array index with \`prototype\`. This targets Array.prototype through array index notation.`
        });
      }
    });

    if (issues.length === 0) return;

    const findId = 'prototype-array-based';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    findings.push({
      id: findId,
      category: 'prototype-pollution',
      name: 'Array-Based Prototype Pollution',
      description: `Detected ${issues.length} array-based prototype pollution vector(s): ${issues.map(i => i.description).join(' ')}. Array-based prototype pollution targets Array.prototype through array elements, numerical keys, or array index notation.`,
      severity: 'high',
      requestIndex: idx,
      evidence: {
        vectors: issues.map(i => ({ type: i.type, ...(i.key ? { key: i.key } : {}), ...(i.param ? { param: i.param } : {}), ...(i.elementIndex !== undefined ? { elementIndex: i.elementIndex } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: 80
    });
  });
}

// =========================
// DETECTOR 7: HTTP HEADER-BASED POLLUTION
// =========================
/**
 * Detect HTTP header-based prototype pollution:
 * - X-Override-* headers that merge into objects
 * - Custom headers with proto patterns
 * - Headers that get processed into object keys
 * - Proxy/forwarded headers that could inject properties
 */
function detectHTTPHeaderBasedPollution(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const headers = getAllHeaderValues(req);
    const path = getPathname(req.request && req.request.url);

    const issues = [];

    // 1. Check for override headers that can inject properties
    const overrideHeaders = [];
    headers.forEach(h => {
      const name = h.name || '';
      const val = h.value || '';
      const lowerName = name.toLowerCase();

      // Headers commonly used for property injection
      if (/^x-override/i.test(lowerName) || /^override/i.test(lowerName) || /^x-set/i.test(lowerName) || /^x-inject/i.test(lowerName)) {
        const suffix = name.replace(/^x-override[-:]/i, '').replace(/^override[-:]/i, '').replace(/^x-set[-:]/i, '');
        if (suffix && suffix !== name) {
          overrideHeaders.push({ name, suffix, value: val.substring(0, 60) });
        }
      }
    });

    if (overrideHeaders.length > 0) {
      // Check if any injected property targets prototype
      const protoOverrides = overrideHeaders.filter(oh => /__proto__|constructor|prototype/i.test(oh.suffix));
      if (protoOverrides.length > 0) {
        issues.push({
          type: 'header-override-proto',
          headers: protoOverrides,
          severity: 'high',
          description: `Override header(s) targeting prototype properties detected: ${protoOverrides.map(h => `\`${h.name}: ${h.value.substring(0, 30)}\``).join(', ')}. Custom override headers that get merged into application objects can achieve prototype pollution.`
        });
      }

      // Even without proto targets, flag suspicious override headers
      if (protoOverrides.length === 0 && overrideHeaders.length > 0) {
        issues.push({
          type: 'header-override-suspicious',
          headers: overrideHeaders,
          severity: 'medium',
          description: `Custom override header(s) detected: ${overrideHeaders.map(h => `\`${h.name}\``).join(', ')}. Custom headers that get processed into object properties are a potential prototype pollution vector if they accept \`__proto__\` keys.`
        });
      }
    }

    // 2. Check for headers with __proto__ in their names
    headers.forEach(h => {
      const name = h.name || '';
      const val = h.value || '';

      if (containsProtoPollutionPattern(name)) {
        issues.push({
          type: 'header-name-proto',
          header: name,
          value: val.substring(0, 60),
          severity: 'high',
          description: `HTTP header name \`${name}\` contains \`__proto__\` or \`constructor.prototype\` patterns. Headers with prototype pollution names could be used if the application processes header names into object keys.`
        });
      }

      if (containsProtoPollutionPattern(val)) {
        issues.push({
          type: 'header-value-proto',
          header: name,
          value: val.substring(0, 80),
          severity: 'high',
          description: `HTTP header \`${name}\` has a value containing \`__proto__\` or \`constructor.prototype\` patterns: \`${val.substring(0, 60)}\`. Header values with prototype pollution patterns could be dangerous if merged into application state.`
        });
      }
    });

    // 3. Check for X-Forwarded-* or proxy headers that could be used for pollution
    const proxyHeaders = headers.filter(h => {
      const lower = (h.name || '').toLowerCase();
      return /^x-forwarded/i.test(lower) || /^x-real/i.test(lower) || /^x-proxy/i.test(lower) || /^client/i.test(lower);
    });

    if (proxyHeaders.length > 3) {
      issues.push({
        type: 'excessive-proxy-headers',
        count: proxyHeaders.length,
        severity: 'low',
        description: `Found ${proxyHeaders.length} proxy/forwarded headers. While not directly a pollution vector, excessive proxy headers processed into objects could be an attack surface.`
      });
    }

    if (issues.length === 0) return;

    const findId = 'prototype-header-based';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const overallSeverity = issues.some(i => i.severity === 'high') ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'prototype-pollution',
      name: 'HTTP Header-Based Prototype Pollution',
      description: `Detected ${issues.length} HTTP header-based prototype pollution indicator(s): ${issues.map(i => i.description).join(' ')}. HTTP headers can be a vector for prototype pollution when applications process custom headers into object properties (e.g., Express.js header parsing, custom middleware).`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        vectors: issues.map(i => ({ type: i.type, ...(i.headers ? { headers: i.headers.slice(0, 3).map(h => ({ name: h.name, valueSample: h.value.substring(0, 30) })) } : {}), ...(i.header ? { header: i.header } : {}), ...(i.value ? { valueSample: i.value.substring(0, 40) } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: overallSeverity === 'high' ? 75 : 40
    });
  });
}

// =========================
// DETECTOR 8: CROSS-REQUEST MERGE CHAIN DETECTION
// =========================
/**
 * Detect cross-request merge chain patterns:
 * - Multiple sequential requests to merge endpoints
 * - Incremental configuration building across requests
 * - Merge operations that accumulate attacker data
 * - Chained object building that could lead to prototype pollution
 */
function detectCrossRequestMergeChain(sortedReqs, findings) {
  const requestFindings = new Map();

  const mergeRequests = [];

  sortedReqs.forEach((req, idx) => {
    const path = getPathname(req.request && req.request.url);
    const isMergeEndpoint = MERGE_ENDPOINT_PATTERNS.some(p => p.test(path));
    const isMutating = isMutatingRequest(req);
    const bodyText = getRequestBodyText(req);

    if (isMergeEndpoint && isMutating) {
      const body = bodyText ? tryParseJSON(bodyText) : null;
      const hasProtoPayload = bodyText ? containsProtoPollutionPattern(bodyText) : false;

      mergeRequests.push({
        idx,
        path,
        timestamp: new Date(req.startedDateTime).getTime(),
        hasProtoPayload,
        bodyKeys: body && typeof body === 'object' ? Object.keys(body) : []
      });
    }
  });

  if (mergeRequests.length < 2) return;

  // Look for sequential merge operations with proto payloads
  for (let i = 1; i < mergeRequests.length; i++) {
    const prev = mergeRequests[i - 1];
    const curr = mergeRequests[i];
    const timeGap = curr.timestamp - prev.timestamp;

    if (timeGap < 5000 && timeGap >= 0) {
      // Check if the sequence includes a proto payload
      if (prev.hasProtoPayload || curr.hasProtoPayload) {
        const issues = [];

        if (prev.hasProtoPayload) {
          issues.push({
            type: 'proto-merge-chain-start',
            previousPath: prev.path,
            currentPath: curr.path,
            severity: 'high',
            description: `Merge chain detected: request to \`${prev.path}\` containing prototype pollution keys followed by another merge request to \`${curr.path}\` (gap: ${timeGap}ms). Sequential merge operations with proto payloads indicate a deliberate multi-step prototype pollution attack.`
          });
        }

        // Check if the first request sets a property that the second exploits
        const sharedKeys = prev.bodyKeys.filter(k => curr.bodyKeys.includes(k));
        if (sharedKeys.length > 0 && prev.hasProtoPayload) {
          issues.push({
            type: 'proto-merge-shared-keys',
            sharedKeys: sharedKeys.slice(0, 5),
            severity: 'high',
            description: `Shared merge key(s) \`${sharedKeys.slice(0, 5).join(', ')}\` appear in sequential merge requests where the first contains prototype pollution payloads. This could indicate a two-step attack: first polluting Object.prototype, then exploiting the polluted property.`
          });
        }

        if (issues.length > 0) {
          const findId = 'prototype-merge-chain';
          const requestIdx = curr.idx;
          if (requestFindings.has(requestIdx) && requestFindings.get(requestIdx).has(findId)) return;
          if (!requestFindings.has(requestIdx)) requestFindings.set(requestIdx, new Set());
          requestFindings.get(requestIdx).add(findId);

          findings.push({
            id: findId,
            category: 'prototype-pollution',
            name: 'Cross-Request Merge Chain Detection',
            description: `Detected multi-step merge chain with prototype pollution indicators: ${issues.map(i => i.description).join(' ')}. Sequential merge operations with prototype pollution payloads suggest a deliberate, multi-step exploitation attempt.`,
            severity: 'high',
            requestIndex: requestIdx,
            evidence: {
              vectors: issues.map(i => ({ type: i.type, ...(i.previousPath ? { previousPath: i.previousPath } : {}), ...(i.currentPath ? { currentPath: i.currentPath } : {}), ...(i.sharedKeys ? { sharedKeys: i.sharedKeys } : {}) })),
              sequence: mergeRequests.slice(Math.max(0, i - 2), i + 1).map(mr => ({ path: mr.path, hasProto: mr.hasProtoPayload }))
            },
            score: 85
          });
        }
      }
    }
  }
}

// =========================
// DETECTOR 9: COOKIE/BODY-BASED PROTOTYPE POLLUTION
// =========================
/**
 * Detect cookie and body-based prototype pollution:
 * - __proto__ in cookie values
 * - __proto__ in multipart form data
 * - __proto__ in URL-encoded form body
 * - Cookie parsing that creates object properties
 */
function detectCookieBodyBasedPollution(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const headers = getAllHeaderValues(req);
    const params = getAllParams(req);
    const path = getPathname(req.request && req.request.url);

    const issues = [];

    // 1. Check cookies for __proto__ patterns
    headers.forEach(h => {
      if (h.name.toLowerCase() === 'cookie') {
        const cookieVal = h.value || '';
        const cookieParts = cookieVal.split(';').map(c => c.trim());

        cookieParts.forEach(cp => {
          const eqIdx = cp.indexOf('=');
          if (eqIdx > 0) {
            const cookieName = cp.substring(0, eqIdx).trim();
            const cookieValue = cp.substring(eqIdx + 1).trim();

            if (/__proto__/i.test(cookieName)) {
              issues.push({
                type: 'cookie-proto-name',
                cookieName,
                cookieValue: cookieValue.substring(0, 40),
                severity: 'high',
                description: `Cookie name \`${cookieName}\` contains \`__proto__\`. Cookies with \`__proto__\` names can pollute Object.prototype when parsed by vulnerable cookie parsers.`
              });
            }

            if (containsProtoPollutionPattern(cookieValue)) {
              issues.push({
                type: 'cookie-proto-value',
                cookieName,
                cookieValue: cookieValue.substring(0, 60),
                severity: 'high',
                description: `Cookie \`${cookieName}\` has a value containing \`__proto__\` or \`constructor.prototype\` patterns. Cookie values with prototype pollution patterns can be dangerous if merged into application objects.`
              });
            }
          }
        });
      }
    });

    // 2. Check params from body (URL-encoded or multipart) for proto patterns
    Object.keys(params).forEach(key => {
      if (/__proto__/i.test(key)) {
        // Only flag if it came from body (not query string) — query string is covered by detector 4
        const url = req.request && req.request.url ? req.request.url : '';
        const urlParams = [];
        try {
          const urlObj = new URL(url);
          urlObj.searchParams.forEach((val, k) => urlParams.push(k));
        } catch (_) {}

        if (!urlParams.includes(key)) {
          issues.push({
            type: 'body-param-proto',
            param: key,
            value: String(params[key]).substring(0, 60),
            severity: 'high',
            description: `Body parameter \`${key}\` contains \`__proto__\`. URL-encoded or multipart form body parameters with \`__proto__\` keys can pollute Object.prototype when parsed by vulnerable body parsers (e.g., Express.js urlencoded middleware).`
          });
        }
      }
    });

    // 3. Check for JSON body with proto keys (complementary to detector 1)
    const bodyText = getRequestBodyText(req);
    if (bodyText && bodyText.includes('__proto__')) {
      // Check Content-Type for form-encoded or multipart
      const contentType = headers.find(h => h.name.toLowerCase() === 'content-type');
      const isForm = contentType && /x-www-form-urlencoded|multipart\/form-data/i.test(contentType.value || '');

      if (isForm) {
        issues.push({
          type: 'form-body-proto',
          severity: 'high',
          description: 'URL-encoded or multipart form body contains \`__proto__\'. Form body parsing with vulnerable libraries (e.g., qs, body-parser) can result in prototype pollution.'
        });
      }
    }

    if (issues.length === 0) return;

    const findId = 'prototype-cookie-body';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    findings.push({
      id: findId,
      category: 'prototype-pollution',
      name: 'Cookie / Body-Based Prototype Pollution',
      description: `Detected ${issues.length} cookie or body-based prototype pollution indicator(s): ${issues.map(i => i.description).join(' ')}. Cookies and form bodies are common but often overlooked vectors for prototype pollution, especially when parsed by vulnerable middleware.`,
      severity: 'high',
      requestIndex: idx,
      evidence: {
        vectors: issues.map(i => ({ type: i.type, ...(i.cookieName ? { cookieName: i.cookieName } : {}), ...(i.cookieValue ? { cookieValueSample: i.cookieValue.substring(0, 30) } : {}), ...(i.param ? { param: i.param } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: 80
    });
  });
}

// =========================
// DETECTOR 10: SENSITIVE PROPERTY OVERRIDE DETECTION
// =========================
/**
 * Detect attempts to override sensitive Object.prototype properties:
 * - toString, valueOf, hasOwnProperty in request parameters
 * - constructor, __defineGetter__ in body
 * - Known gadget properties that enable further exploitation
 */
function detectSensitivePropertyOverride(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const bodyText = getRequestBodyText(req);
    const params = getAllParams(req);
    const path = getPathname(req.request && req.request.url);

    const issues = [];

    // 1. Scan for sensitive property keys in body
    if (bodyText) {
      const body = tryParseJSON(bodyText);
      if (body && typeof body === 'object') {
        SENSITIVE_PROTOTYPE_PROPERTIES.forEach(sensitiveProp => {
          const found = deepFindKey(body, sensitiveProp);
          if (found.length > 0) {
            const propValue = found[0].value;

            // Only flag if the value is something that could be set (not just a reference)
            if (propValue !== undefined) {
              // Check if it's a non-function (functions are legitimate method definitions)
              const isMethodOverride = typeof propValue === 'function';
              const isDataOverride = !isMethodOverride && (typeof propValue === 'string' || typeof propValue === 'number' || typeof propValue === 'boolean' || typeof propValue === 'object');

              if (isDataOverride) {
                issues.push({
                  type: 'sensitive-property-override',
                  property: sensitiveProp,
                  path: found[0].path,
                  valueType: typeof propValue,
                  severity: 'high',
                  description: `Sensitive Object.prototype property \`${sensitiveProp}\` found at \`${found[0].path}\` with value type \`${typeof propValue}\`. Overriding \`${sensitiveProp}\` on Object.prototype can break fundamental object behavior and enable further exploitation.`
                });
              }

              if (isMethodOverride) {
                issues.push({
                  type: 'sensitive-method-override',
                  property: sensitiveProp,
                  path: found[0].path,
                  severity: 'high',
                  description: `Object.prototype method \`${sensitiveProp}\` is being overridden at \`${found[0].path}\`. Replacing prototype methods like \`${sensitiveProp}\` can enable XSS, denial of service, or logic bypass.`
                });
              }
            }
          }
        });
      }
    }

    // 2. Check params for sensitive property names with values
    Object.keys(params).forEach(key => {
      const isSensitive = SENSITIVE_PROTOTYPE_PROPERTIES.some(sp => {
        return key === sp || key.endsWith(`.${sp}`) || key.includes(`[${sp}]`);
      });

      if (isSensitive) {
        const val = String(params[key]);
        // Method overrides from query params are less common but worth flagging
        if (val === 'function' || val === 'true' || val === 'false' || /^{|\[/.test(val)) {
          issues.push({
            type: 'sensitive-property-param',
            param: key,
            value: val.substring(0, 40),
            severity: 'high',
            description: `Parameter \`${key}\` targets a sensitive Object.prototype property (\`${key.split('.').pop() || key}\`). Query parameters targeting \`toString\`, \`valueOf\`, or \`constructor\` can be used in prototype pollution gadget chains.`
          });
        }
      }
    });

    // 3. Check for gadget property patterns commonly used with prototype pollution
    const gadgetProperties = [
      'shell', 'exec', 'cmd', 'command', 'args', 'argv',
      '__defineGetter__', '__defineSetter__',
      'then', 'catch', 'finally',  // Promise prototype pollution
      'status', 'statusText', 'headers', 'body',  // Response-like gadget
      'url', 'method', 'redirect',  // Request-like gadget
      'type', 'contentType', 'accept',
      'onerror', 'onload', 'onsuccess',
      'emit', 'on', 'trigger', 'dispatch'
    ];

    if (bodyText) {
      const body = tryParseJSON(bodyText);
      if (body && typeof body === 'object' && !Array.isArray(body)) {
        const foundGadgets = gadgetProperties.filter(gp => body[gp] !== undefined);
        if (foundGadgets.length >= 3) {
          issues.push({
            type: 'gadget-property-set',
            properties: foundGadgets,
            count: foundGadgets.length,
            severity: 'medium',
            description: `Multiple gadget-compatible properties found in request body: ${foundGadgets.join(', ')}. Setting these properties via Object.prototype pollution can enable XSS, RCE, or SSRF gadgets.`
          });
        }
      }
    }

    if (issues.length === 0) return;

    const findId = 'prototype-sensitive-override';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const overallSeverity = issues.some(i => i.severity === 'high') ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'prototype-pollution',
      name: 'Sensitive Property Override Detection',
      description: `Detected ${issues.length} sensitive property override attempt(s): ${issues.map(i => i.description).join(' ')}. Overriding core Object.prototype methods or properties can break application logic and enable gadget chains for XSS, RCE, and SSRF.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        vectors: issues.map(i => ({ type: i.type, property: i.property, ...(i.path ? { path: i.path } : {}), ...(i.param ? { param: i.param } : {}), ...(i.valueType ? { valueType: i.valueType } : {}), ...(i.properties ? { gadgetProperties: i.properties.slice(0, 5) } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: overallSeverity === 'high' ? 80 : 40
    });
  });
}

// =========================
// DETECTOR 11: NESTED MERGE LOOP DETECTION
// =========================
/**
 * Detect deeply nested merge loops with prototype pollution:
 * - Deeply nested objects with __proto__ at multiple levels
 * - Recursive merge patterns
 * - Objects designed to exploit recursive merge functions
 * - High nesting depth combined with prototype keys
 */
function detectNestedMergeLoop(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const bodyText = getRequestBodyText(req);
    const path = getPathname(req.request && req.request.url);

    if (!bodyText) return;

    const body = tryParseJSON(bodyText);
    if (!body || typeof body !== 'object') return;

    const issues = [];

    // 1. Calculate nesting depth and check for repeated __proto__
    const measureDepthAndProto = (obj, currentDepth = 0, maxScanDepth = 15) => {
      if (!obj || typeof obj !== 'object' || currentDepth > maxScanDepth) return { depth: currentDepth, protoCount: 0, protoDepths: [] };

      let depth = currentDepth;
      let protoCount = 0;
      let protoDepths = [];

      if (obj.__proto__ !== undefined) {
        protoCount++;
        protoDepths.push(currentDepth);
      }

      Object.keys(obj).forEach(k => {
        if (obj[k] && typeof obj[k] === 'object') {
          const result = measureDepthAndProto(obj[k], currentDepth + 1, maxScanDepth);
          depth = Math.max(depth, result.depth);
          protoCount += result.protoCount;
          protoDepths.push(...result.protoDepths);
        }
      });

      return { depth, protoCount, protoDepths };
    };

    const { depth, protoCount, protoDepths } = measureDepthAndProto(body);

    // Flag if high nesting depth and multiple __proto__ occurrences
    if (depth >= 5 && protoCount >= 2) {
      issues.push({
        type: 'deep-nested-multiple-proto',
        depth,
        protoCount,
        protoDepths: [...new Set(protoDepths)],
        severity: 'high',
        description: `Deeply nested object (depth: ${depth}) with ${protoCount} \`__proto__\` occurrences across ${[...new Set(protoDepths)].length} depth level(s). Recursive merge functions processing this object would pollute Object.prototype at multiple levels.`
      });
    }

    // 2. Check for repeated identical structure with __proto__ (template-like pollution)
    const findRepeatedPatterns = (obj, seen = new Map(), pathStr = '') => {
      if (!obj || typeof obj !== 'object') return;

      // Generate a structural fingerprint
      const keys = Object.keys(obj).sort().join(',');
      if (keys) {
        const existing = seen.get(keys);
        if (existing) {
          // Similar structure found at two different paths — could be template exploitation
          if (containsProtoPollutionPattern(JSON.stringify(obj)) && containsProtoPollutionPattern(JSON.stringify(existing.value))) {
            issues.push({
              type: 'repeated-proto-pattern',
              path1: existing.path,
              path2: pathStr,
              keys: keys.split(',').slice(0, 8),
              severity: 'medium',
              description: `Repeated object structure with prototype pollution keys at \`${existing.path}\` and \`${pathStr}\`. Repeated patterns may indicate a template-based prototype pollution attempt.`
            });
          }
        } else {
          seen.set(keys, { path: pathStr, value: obj });
        }
      }

      Object.keys(obj).forEach(k => {
        const newPath = pathStr ? `${pathStr}.${k}` : k;
        findRepeatedPatterns(obj[k], seen, newPath);
      });
    };
    findRepeatedPatterns(body);

    // 3. Check for recursive/polluting structure (object containing itself or proto chain)
    const checkRecursiveStructure = (obj, visited = new WeakSet(), pathStr = '') => {
      if (!obj || typeof obj !== 'object' || visited.has(obj)) return;
      visited.add(obj);

      Object.keys(obj).forEach(k => {
        const newPath = pathStr ? `${pathStr}.${k}` : k;
        const val = obj[k];

        if (val && typeof val === 'object') {
          // Check if the same object is referenced at multiple paths (circular)
          if (visited.has(val)) {
            if (containsProtoPollutionPattern(k)) {
              issues.push({
                type: 'circular-proto-reference',
                path: newPath,
                severity: 'high',
                description: `Circular reference detected at \`${newPath}\` with prototype pollution key \`${k}\`. Circular structures with \`__proto__\` references can cause infinite recursion in merge functions and unexpected prototype mutations.`
              });
            }
          } else {
            checkRecursiveStructure(val, visited, newPath);
          }
        }
      });
    };
    try {
      checkRecursiveStructure(body);
    } catch (_) {
      // Circular reference detection might throw on some complex objects
    }

    if (issues.length === 0) return;

    const findId = 'prototype-nested-merge-loop';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const overallSeverity = issues.some(i => i.severity === 'high') ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'prototype-pollution',
      name: 'Nested Merge Loop Detection',
      description: `Detected ${issues.length} nested merge loop indicator(s): ${issues.map(i => i.description).join(' ')}. Deeply nested objects with multiple \`__proto__\` occurrences are designed to exploit recursive merge functions that don't track visited objects or depth.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        vectors: issues.map(i => ({ type: i.type, ...(i.depth !== undefined ? { depth: i.depth } : {}), ...(i.protoCount !== undefined ? { protoCount: i.protoCount } : {}), ...(i.protoDepths ? { protoDepths: i.protoDepths } : {}), ...(i.path ? { path: i.path } : {}), ...(i.path1 ? { patternPath1: i.path1, patternPath2: i.path2 } : {}) })),
        url: path,
        method: req.request && req.request.method
      },
      score: overallSeverity === 'high' ? 80 : 45
    });
  });
}

// =========================
// DETECTOR 12: RESPONSE-BASED PROTOTYPE POLLUTION
// =========================
/**
 * Detect response-based prototype pollution:
 * - Server responses that reflect __proto__ or constructor.prototype
 * - Responses containing prototype pollution patterns
 * - Confirmation of successful pollution via response
 */
function detectResponseBasedProtoPollution(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const path = getPathname(req.request && req.request.url);

    // Check response content and headers for reflected proto patterns
    if (!req.response) return;

    const issues = [];

    // 1. Check response headers for prototype pollution patterns
    if (Array.isArray(req.response.headers)) {
      req.response.headers.forEach(h => {
        const headerName = h.name || '';
        const headerValue = h.value || '';

        if (containsProtoPollutionPattern(headerValue)) {
          issues.push({
            type: 'response-header-reflected',
            header: headerName,
            value: headerValue.substring(0, 80),
            severity: 'high',
            description: `Response header \`${headerName}\` contains \`__proto__\` or \`constructor.prototype\` pattern: \`${headerValue.substring(0, 60)}\`. Reflected prototype pollution patterns in responses may indicate successful server-side pollution or unsafe deserialization.`
          });
        }
      });
    }

    // 2. Check response body content
    let responseBody = null;
    if (req.response.content && req.response.content.text) {
      responseBody = req.response.content.text;
    }

    if (responseBody) {
      // Check for __proto__ reflected in response
      if (containsProtoPollutionPattern(responseBody)) {
        // Try to parse as JSON for better analysis
        const parsed = tryParseJSON(responseBody);
        if (parsed && typeof parsed === 'object') {
          const hasProto = deepFindKey(parsed, '__proto__').length > 0;
          const hasConstructorChain = deepFindPrototypeChain(parsed).length > 0;

          if (hasProto || hasConstructorChain) {
            issues.push({
              type: 'response-body-prototype',
              severity: 'high',
              description: `Response body contains \`__proto__\` or \`constructor.prototype\` keys. This indicates that the server-side operation may have processed prototype pollution payloads and reflected them back, confirming a potential successful prototype pollution.`
            });
          } else {
            // Proto pattern in raw text but not in parsed JSON (e.g., in string values)
            issues.push({
              type: 'response-body-proto-string',
              severity: 'medium',
              description: 'Response body contains the string \`__proto__\` or \`constructor.prototype\` in its raw content. This may indicate reflection of attacker input or server-side processing of prototype pollution payloads.'
            });
          }
        } else {
          // Non-JSON response with proto pattern
          issues.push({
            type: 'response-body-proto-raw',
            severity: 'medium',
            description: `Response body contains \`__proto__\` or \`constructor.prototype\` string pattern. This may indicate reflection of user input or server-side processing of prototype pollution attempts.`
          });
        }
      }

      // Check for status/error messages that indicate prototype pollution
      const pollutionIndicators = [
        /prototype.*polluted/i,
        /cannot.*read.*property.*of.*undefined/i,  // Common error after prototype override
        /invalid.*prototype/i,
        /prototype.*override/i
      ];

      pollutionIndicators.forEach(indicator => {
        if (indicator.test(responseBody)) {
          issues.push({
            type: 'response-pollution-indicator',
            severity: 'high',
            description: `Response contains error string related to prototype pollution: \`${responseBody.match(indicator)?.[0] || indicator}\`. Error messages about prototype pollution may confirm a successful attack.`
          });
          break;
        }
      });
    }

    if (issues.length === 0) return;

    const findId = 'prototype-response-based';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const overallSeverity = issues.some(i => i.severity === 'high') ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'prototype-pollution',
      name: 'Response-Based Prototype Pollution Confirmation',
      description: `Detected ${issues.length} response-based prototype pollution indicator(s): ${issues.map(i => i.description).join(' ')}. Response content reflecting prototype pollution patterns can confirm successful exploitation, and server error messages may leak information about the application's internal state.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        vectors: issues.map(i => ({ type: i.type, ...(i.header ? { header: i.header } : {}), ...(i.value ? { valueSample: i.value.substring(0, 50) } : {}) })),
        url: path,
        method: req.request && req.request.method,
        statusCode: req.response.status
      },
      score: overallSeverity === 'high' ? 85 : 45
    });
  });
}

