/**
 * Logic Flaws Detection Engine
 * 
 * Analyzes workflows and individual requests for common business logic
 * vulnerabilities:
 *   - IDOR (Insecure Direct Object Reference)
 *   - Parameter Tampering
 *   - Auth / Privilege Escalation
 *   - Mass Assignment
 *   - Business Process Bypass
 *   - Input Validation Flaws
 *   - Race Condition / TOCTOU
 */

// =========================
// PUBLIC INTERFACE
// =========================

/**
 * Run all logic flaw detectors against a workflow.
 * Returns an array of flaw findings, each with:
 *   { id, name, description, severity, category, requestIndex?, evidence }
 */
export function detectFlaws(workflow) {
  if (!workflow || !Array.isArray(workflow.requests) || workflow.requests.length === 0) {
    return [];
  }

  const sortedReqs = [...workflow.requests].sort((a, b) => {
    return new Date(a.startedDateTime).getTime() - new Date(b.startedDateTime).getTime();
  });

  const findings = [];

  // Run each detector; pass sorted requests + the raw workflow
  detectIDOR(sortedReqs, findings);
  detectParameterTampering(sortedReqs, findings);
  detectAuthEscalation(sortedReqs, findings);
  detectMassAssignment(sortedReqs, findings);
  detectProcessBypass(sortedReqs, workflow, findings);
  detectInputValidation(sortedReqs, findings);
  detectRaceCondition(sortedReqs, workflow, findings);

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
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.request.method) ||
    (req._graphql && req._graphql.operations && req._graphql.operations.some(op => op.type === 'mutation'));
}

function isGraphQLRequest(req) {
  return !!(req._graphql && req._graphql.operations && req._graphql.operations.length);
}

function getRequestBodyText(req) {
  if (req.request.postData && req.request.postData.text) {
    return req.request.postData.text;
  }
  return null;
}

function tryParseJSON(str) {
  if (!str) return null;
  try { return JSON.parse(str); } catch (_) { return null; }
}

function getAllParams(req) {
  // Collect all parameters from query string + body + GraphQL variables
  const params = {};

  // Query string
  if (Array.isArray(req.request.queryString)) {
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
        Object.keys(op.variables).forEach(k => {
          params[k] = op.variables[k];
        });
      }
    });
  }

  return params;
}

function findNumericIdsInString(str) {
  // Find potential ID-like numbers (sequences of 3+ digits, or hex strings)
  const ids = [];
  // Decimal IDs: sequences of 3+ digits
  const decimalMatches = str.match(/\b\d{3,10}\b/g);
  if (decimalMatches) ids.push(...decimalMatches);
  // UUIDs
  const uuidMatches = str.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi);
  if (uuidMatches) ids.push(...uuidMatches);
  // Hex IDs
  const hexMatches = str.match(/[0-9a-f]{6,12}/gi);
  if (hexMatches) ids.push(...hexMatches);
  return ids;
}

const SENSITIVE_ID_PARAM_NAMES = [
  'id', 'userId', 'user_id', 'accountId', 'account_id', 'customerId',
  'orderId', 'order_id', 'transactionId', 'paymentId', 'productId',
  'itemId', 'item_id', 'resourceId', 'docId', 'documentId',
  'profileId', 'uid', 'guid', 'uuid', 'token'
];

const PRICE_PARAM_NAMES = [
  'price', 'amount', 'total', 'cost', 'subtotal', 'discount',
  'tax', 'shipping', 'fee', 'tip', 'donation', 'value',
  'rate', 'charge', 'paid', 'balance', 'credit', 'debit'
];

const QUANTITY_PARAM_NAMES = [
  'quantity', 'qty', 'count', 'num', 'number', 'limit',
  'max', 'min', 'size', 'capacity', 'stock'
];

const ROLE_PARAM_NAMES = [
  'role', 'roles', 'userRole', 'user_type', 'type', 'access',
  'accessLevel', 'permission', 'permissions', 'scope', 'scopes',
  'isAdmin', 'is_admin', 'isPremium', 'is_premium', 'admin',
  'privilege', 'privileges', 'group', 'groups', 'level'
];

const PROTECTED_FIELD_NAMES = [
  'isAdmin', 'is_admin', 'role', 'roles', 'permissions',
  'balance', 'credit', 'credit_limit', 'account_balance',
  'isVerified', 'is_verified', 'isPremium', 'is_premium',
  'accessLevel', 'access_level', 'privilege', 'privileges',
  'internal', 'hidden', 'secret', 'approved', 'status',
  'isActive', 'is_active', 'emailVerified', 'phoneVerified',
  'adminNotes', 'internalNotes', 'private'
];

const SQL_INJECTION_PATTERNS = [
  /'\s*OR\s*'?\s*1\s*=\s*1/i,
  /'\s*OR\s*'?\s*1\s*=\s*1\s*--/i,
  /'\s*OR\s*'\s*'\s*=\s*'/i,
  /admin'\s*--/i,
  /'\s*UNION\s+SELECT/i,
  /\bDROP\s+TABLE/i,
  /\bDELETE\s+FROM/i,
  /\bINSERT\s+INTO/i,
  /\bEXEC\b/i,
  /\bXP_CMDSHELL/i,
  /1\s*=\s*1\s*--/i,
  /\bOR\b.*\bSLEEP\b/i,
  /\bWAITFOR\s+DELAY/i,
  /pg_sleep/i
];

const NOSQL_INJECTION_PATTERNS = [
  /\$ne/i,
  /\$gt/i,
  /\$gte/i,
  /\$lt/i,
  /\$lte/i,
  /\$regex/i,
  /\$where/i,
  /\$exists/i,
  /\$nin/i,
  /\$in/i
];

// =========================
// DETECTOR: IDOR
// =========================
/**
 * Detect Insecure Direct Object References:
 * - Sequential numeric IDs in path segments
 * - Predictable/sequential IDs across multiple requests
 * - User-supplied IDs that reference other resources
 * - Missing ownership validation
 */
function detectIDOR(sortedReqs, findings) {
  // 1. Extract all resource identifiers from requests
  const idRefs = [];

  sortedReqs.forEach((req, idx) => {
    const url = req.request.url || '';
    const path = getPathname(url);
    const params = getAllParams(req);

    // Check path segments for numeric IDs
    const segments = path.split('/').filter(Boolean);
    segments.forEach((seg, segIdx) => {
      const ids = findNumericIdsInString(seg);
      ids.forEach(id => {
        // Determine the resource type from context (previous segment)
        const resourceType = segIdx > 0 ? segments[segIdx - 1] : 'resource';
        idRefs.push({
          id,
          resourceType,
          source: 'path',
          requestIndex: idx,
          url: path,
          paramName: null
        });
      });
    });

    // Check query params and body params for ID-like values
    Object.keys(params).forEach(key => {
      const isSensitive = SENSITIVE_ID_PARAM_NAMES.some(p =>
        key.toLowerCase() === p || key.toLowerCase().includes(p)
      );
      if (!isSensitive) return;

      const val = String(params[key]);
      const ids = findNumericIdsInString(val);
      ids.forEach(id => {
        idRefs.push({
          id,
          resourceType: key,
          source: 'parameter',
          requestIndex: idx,
          url: path,
          paramName: key
        });
      });
    });

    // Check GraphQL variables
    if (req._graphql && req._graphql.operations) {
      req._graphql.operations.forEach(op => {
        if (op.variables && typeof op.variables === 'object') {
          Object.keys(op.variables).forEach(vk => {
            const val = String(op.variables[vk]);
            const isId = SENSITIVE_ID_PARAM_NAMES.some(p => vk.toLowerCase().includes(p));
            if (!isId) return;
            const ids = findNumericIdsInString(val);
            ids.forEach(id => {
              idRefs.push({
                id,
                resourceType: vk,
                source: 'graphql',
                requestIndex: idx,
                url: path,
                paramName: vk
              });
            });
          });
        }
      });
    }
  });

  if (idRefs.length === 0) return;

  // 2. Look for sequential/predictable IDs for the same resource type
  // Group by resource type
  const byResource = {};
  idRefs.forEach(ref => {
    const key = ref.resourceType.toLowerCase();
    if (!byResource[key]) byResource[key] = [];
    byResource[key].push(ref);
  });

  Object.keys(byResource).forEach(resourceKey => {
    const refs = byResource[resourceKey];
    if (refs.length < 2) return;

    // Check if IDs are sequential or have small gaps
    const numericIds = refs
      .map(r => parseInt(r.id, 10))
      .filter(n => !isNaN(n) && n > 0);

    if (numericIds.length < 2) return;

    numericIds.sort((a, b) => a - b);
    const gaps = [];
    for (let i = 1; i < numericIds.length; i++) {
      gaps.push(numericIds[i] - numericIds[i - 1]);
    }

    const avgGap = gaps.reduce((s, g) => s + g, 0) / gaps.length;
    const maxGap = Math.max(...gaps);

    // If gaps are consistently small (sequential or near-sequential), flag IDOR
    if (avgGap <= 10 && maxGap <= 20 && numericIds.length >= 2) {
      findings.push({
        id: 'idor-sequential',
        category: 'idor',
        name: 'Sequential/Predictable Object References',
        description: `Detected ${numericIds.length} predictable resource IDs for "${resourceKey}" (IDs: ${numericIds.slice(0, 5).join(', ')}${numericIds.length > 5 ? '...' : ''}). Sequential numeric IDs allow attackers to enumerate and access other users' resources by simply incrementing the ID.`,
        severity: numericIds.length >= 5 ? 'high' : 'medium',
        evidence: {
          resourceType: resourceKey,
          ids: numericIds,
          urls: [...new Set(refs.map(r => r.url))].slice(0, 3)
        },
        score: numericIds.length >= 5 ? 60 : 35
      });
    }
  });

  // 3. Check for ID in path without auth headers
  // Flag when a mutation uses a path-based ID but no Authorization/ Bearer token or similar
  sortedReqs.forEach((req, idx) => {
    if (!isMutatingRequest(req)) return;

    const path = getPathname(req.request.url);
    const hasIdInPath = path.split('/').some(seg => /\b\d{3,10}\b/.test(seg));
    if (!hasIdInPath) return;

    // Check for auth headers
    const headers = req.request.headers || [];
    const hasAuth = headers.some(h => {
      const name = (h.name || '').toLowerCase();
      return name === 'authorization' || name === 'x-api-key' || name === 'api-key' || name === 'token';
    });

    // Also check cookies if available
    const hasAuthCookie = headers.some(h => {
      const name = (h.name || '').toLowerCase();
      return name === 'cookie' && (h.value || '').toLowerCase().includes('session');
    });

    if (!hasAuth && !hasAuthCookie) {
      findings.push({
        id: 'idor-no-auth',
        category: 'idor',
        name: 'Direct Object Reference Without Authentication',
        description: `Mutating request to \`${path}\` contains a resource ID in the path but lacks an Authorization header or session cookie. This may allow direct access to any user's resource without authentication.`,
        severity: 'high',
        requestIndex: idx,
        evidence: { url: path, method: req.request.method },
        score: 70
      });
    }
  });
}

// =========================
// DETECTOR: PARAMETER TAMPERING
// =========================
/**
 * Detect Parameter Tampering:
 * - Price/amount/discount manipulation in requests
 * - Negative or zero values for numeric fields
 * - Hidden/readonly field tampering
 * - Quantity overflow / underflow
 * - Coupon/discount code manipulation
 */
function detectParameterTampering(sortedReqs, findings) {
  sortedReqs.forEach((req, idx) => {
    if (!isMutatingRequest(req)) return;

    const params = getAllParams(req);
    const bodyText = getRequestBodyText(req);
    const body = tryParseJSON(bodyText);

    // 1. Check price/amount fields for suspicious values
    PRICE_PARAM_NAMES.forEach(priceKey => {
      Object.keys(params).forEach(paramKey => {
        const lowerKey = paramKey.toLowerCase();
        if (!lowerKey.includes(priceKey.toLowerCase()) && lowerKey !== priceKey.toLowerCase()) return;

        const val = params[paramKey];
        const numVal = parseFloat(val);

        if (isNaN(numVal)) return;

        const issues = [];

        // Negative amount
        if (numVal < 0) {
          issues.push('negative value');
        }

        // Zero pricing
        if (numVal === 0) {
          issues.push('zero value');
        }

        // Extremely large amount (potential overflow)
        if (Math.abs(numVal) > 999999999) {
          issues.push('extremely large value (potential overflow)');
        }

        // Very small fraction
        if (numVal > 0 && numVal < 0.01 && numVal !== 0) {
          issues.push('suspiciously small fractional value');
        }

        if (issues.length > 0) {
          findings.push({
            id: 'param-tamper-price',
            category: 'parameter-tampering',
            name: 'Suspicious Financial Parameter Value',
            description: `Parameter \`${paramKey}\` has value \`${numVal}\` (${issues.join(', ')}). This is commonly exploited to manipulate pricing, discounts, or transaction amounts.`,
            severity: numVal < 0 || numVal === 0 ? 'high' : 'medium',
            requestIndex: idx,
            evidence: {
              paramName: paramKey,
              value: numVal,
              issues,
              url: getPathname(req.request.url)
            },
            score: numVal < 0 || numVal === 0 ? 60 : 30
          });
        }
      });
    });

    // 2. Check quantity fields for suspicious values
    QUANTITY_PARAM_NAMES.forEach(qtyKey => {
      Object.keys(params).forEach(paramKey => {
        const lowerKey = paramKey.toLowerCase();
        if (lowerKey !== qtyKey.toLowerCase() && !lowerKey.includes(qtyKey.toLowerCase())) return;

        const val = params[paramKey];
        const numVal = parseInt(val, 10);

        if (isNaN(numVal)) return;

        const issues = [];

        // Negative quantity
        if (numVal < 0) {
          issues.push('negative quantity (potential inventory manipulation)');
        }

        // Zero quantity
        if (numVal === 0) {
          issues.push('zero quantity');
        }

        // Extremely large quantity
        if (numVal > 10000) {
          issues.push(`excessive quantity (${numVal} — potential integer overflow)`);
        }

        if (issues.length > 0) {
          findings.push({
            id: 'param-tamper-quantity',
            category: 'parameter-tampering',
            name: 'Suspicious Quantity Parameter Value',
            description: `Parameter \`${paramKey}\` has value \`${numVal}\` (${issues.join(', ')}). This may allow attackers to manipulate inventory, pricing, or cause integer overflow.`,
            severity: numVal < 0 ? 'high' : 'medium',
            requestIndex: idx,
            evidence: {
              paramName: paramKey,
              value: numVal,
              issues,
              url: getPathname(req.request.url)
            },
            score: numVal < 0 ? 55 : 25
          });
        }
      });
    });

    // 3. Check raw body for hidden field tampering (fields that look like hidden/readonly)
    if (body && typeof body === 'object') {
      const unexpectedFields = [];

      // Look for fields that are typically server-side computed but sent from client
      Object.keys(body).forEach(key => {
        const lowerKey = key.toLowerCase();
        if (lowerKey === 'id' || lowerKey.endsWith('_id') || lowerKey.endsWith('id')) {
          // IDs in mutation bodies should be validated server-side
        }
        if (lowerKey.includes('discount') || lowerKey.includes('coupon') || lowerKey.includes('promo')) {
          if (body[key] && typeof body[key] === 'string' && body[key].length > 0) {
            unexpectedFields.push(key);
          }
        }
      });

      if (unexpectedFields.length > 0) {
        findings.push({
          id: 'param-tamper-hidden',
          category: 'parameter-tampering',
          name: 'Client-Supplied Discount/Coupon Code',
          description: `Request body contains discount-related fields (${unexpectedFields.join(', ')}) that are modifiable by the client. This could allow attackers to apply arbitrary discounts.`,
          severity: 'medium',
          requestIndex: idx,
          evidence: {
            fields: unexpectedFields,
            url: getPathname(req.request.url)
          },
          score: 35
        });
      }
    }
  });
}

// =========================
// DETECTOR: AUTH / PRIVILEGE ESCALATION
// =========================
/**
 * Detect Auth and Privilege Escalation:
 * - Role/privilege parameters controlled by client
 * - Admin/privileged endpoints accessible without proper auth
 * - Privilege escalation patterns (user → admin)
 * - Weak or missing authorization checks
 */
function detectAuthEscalation(sortedReqs, findings) {
  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const path = getPathname(req.request.url);

    // 1. Check for client-supplied role/privilege parameters
    const roleParamsFound = [];
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      const isRoleParam = ROLE_PARAM_NAMES.some(rp => lowerKey === rp.toLowerCase() || lowerKey.includes(rp.toLowerCase()));
      if (!isRoleParam) return;

      const val = String(params[key]);
      // Flag if it looks like a privilege escalation attempt
      if (/admin|super|owner|manager|premium|vip|moderator/i.test(val)) {
        roleParamsFound.push({ key, value: val });
      }
    });

    if (roleParamsFound.length > 0) {
      const roleDesc = roleParamsFound.map(r => `\`${r.key}=${r.value}\``).join(', ');
      findings.push({
        id: 'auth-client-role',
        category: 'auth-escalation',
        name: 'Client-Controlled Privilege Parameter',
        description: `Request contains client-supplied role/privilege parameter(s): ${roleDesc}. Attackers can modify these to escalate privileges (e.g., regular user → admin). Role/access control must happen server-side only.`,
        severity: 'high',
        requestIndex: idx,
        evidence: {
          params: roleParamsFound,
          url: path
        },
        score: 75
      });
    }

    // 2. Check for admin endpoint access patterns
    const isAdminEndpoint = /admin|dashboard|manage|console|backoffice|internal/i.test(path);
    const isMutation = isMutatingRequest(req);

    if (isAdminEndpoint && isMutation) {
      // Check for auth headers
      const headers = req.request.headers || [];
      const hasStrongAuth = headers.some(h => {
        const name = (h.name || '').toLowerCase();
        const val = (h.value || '');
        if (name === 'authorization') {
          // Check if it's a weak token (short, simple pattern)
          const token = val.replace(/^Bearer\s+/i, '');
          if (token.length < 20) return 'weak'; // weak token
          return 'strong';
        }
        return false;
      });

      if (hasStrongAuth === false) {
        findings.push({
          id: 'auth-admin-no-token',
          category: 'auth-escalation',
          name: 'Admin Endpoint Without Authorization',
          description: `Admin-level endpoint \`${path}\` (${req.request.method}) is accessed without an Authorization header. This could allow unauthorized privilege escalation.`,
          severity: 'high',
          requestIndex: idx,
          evidence: { url: path, method: req.request.method },
          score: 80
        });
      } else if (hasStrongAuth === 'weak') {
        findings.push({
          id: 'auth-weak-token',
          category: 'auth-escalation',
          name: 'Weak Authorization Token on Admin Endpoint',
          description: `Admin endpoint \`${path}\` uses a suspiciously short authorization token (< 20 chars). Short/predictable tokens are vulnerable to forgery.`,
          severity: 'high',
          requestIndex: idx,
          evidence: { url: path },
          score: 65
        });
      }
    }

    // 3. Check for authentication enumeration (different responses for existing vs non-existing users)
    // This is better checked across requests, so we do it after the loop
  });

  // 3. Cross-request auth checks
  // Look for login/auth endpoints that leak user existence
  const loginEndpoints = {};
  sortedReqs.forEach((req, idx) => {
    const url = req.request.url;
    const path = getPathname(url);
    const isAuthEndpoint = /login|signin|auth|signup|register|forgot|reset|verify/i.test(path);

    if (!isAuthEndpoint) return;

    const status = req.response && req.response.status;
    const params = getAllParams(req);

    if (!loginEndpoints[path]) {
      loginEndpoints[path] = { requests: [], statuses: new Set(), methods: new Set() };
    }
    loginEndpoints[path].requests.push({ params, status, idx });
    loginEndpoints[path].statuses.add(status);
    loginEndpoints[path].methods.add(req.request.method);
  });

  // Check for varying responses on auth endpoints (user enumeration)
  Object.keys(loginEndpoints).forEach(path => {
    const info = loginEndpoints[path];
    if (info.statuses.size >= 2 && info.statuses.has(200) && info.statuses.has(404)) {
      // Different status codes could indicate user enumeration
      const differentCodes = [...info.statuses].filter(s => s >= 400).join(', ');
      findings.push({
        id: 'auth-enumeration',
        category: 'auth-escalation',
        name: 'User Enumeration via Auth Endpoint',
        description: `Auth endpoint \`${path}\` returned varying HTTP status codes (${[...info.statuses].join(', ')}). Different responses for valid vs invalid credentials/users enable username enumeration attacks.`,
        severity: 'medium',
        evidence: {
          endpoint: path,
          statusCodes: [...info.statuses],
          methods: [...info.methods]
        },
        score: 30
      });
    }
  });
}

// =========================
// DETECTOR: MASS ASSIGNMENT
// =========================
/**
 * Detect Mass Assignment Vulnerabilities:
 * - Unexpected/internal fields in request body
 * - Protected fields (like isAdmin, balance) being sent from client
 * - Extra fields beyond what's expected for the endpoint
 */
function detectMassAssignment(sortedReqs, findings) {
  sortedReqs.forEach((req, idx) => {
    if (!isMutatingRequest(req)) return;

    const bodyText = getRequestBodyText(req);
    if (!bodyText) return;

    const body = tryParseJSON(bodyText);
    if (!body || typeof body !== 'object' || Array.isArray(body)) return;

    const bodyKeys = Object.keys(body);
    if (bodyKeys.length === 0) return;

    const protectedFieldsFound = [];

    bodyKeys.forEach(key => {
      const lowerKey = key.toLowerCase();
      // Check if this looks like a protected/internal field
      const isProtected = PROTECTED_FIELD_NAMES.some(pf => {
        return lowerKey === pf.toLowerCase() ||
               lowerKey.includes(pf.toLowerCase());
      });

      if (isProtected) {
        protectedFieldsFound.push({
          key,
          value: typeof body[key] === 'object' ? JSON.stringify(body[key]).substring(0, 50) : String(body[key])
        });
      }
    });

    if (protectedFieldsFound.length > 0) {
      const fieldDesc = protectedFieldsFound.map(f => `\`${f.key}\``).join(', ');
      findings.push({
        id: 'mass-assignment',
        category: 'mass-assignment',
        name: 'Mass Assignment of Protected Fields',
        description: `Request body contains ${protectedFieldsFound.length} protected/internal field(s): ${fieldDesc}. These fields should be set server-side only. Client-supplied values allow attackers to escalate privileges, modify balances, or bypass verification.`,
        severity: protectedFieldsFound.some(f =>
          /isAdmin|role|balance|credit|privilege/i.test(f.key)
        ) ? 'high' : 'medium',
        requestIndex: idx,
        evidence: {
          fields: protectedFieldsFound,
          url: getPathname(req.request.url),
          method: req.request.method
        },
        score: protectedFieldsFound.some(f => /isAdmin|role|balance|credit/i.test(f.key)) ? 75 : 40
      });
    }

    // Check for unexpected fields that don't match URL resource context
    const path = getPathname(req.request.url).toLowerCase();
    const expectedResourceFields = getExpectedFieldsForPath(path);
    const unexpectedKeys = bodyKeys.filter(k => {
      const lowerK = k.toLowerCase();
      return !expectedResourceFields.some(ef => lowerK.includes(ef)) &&
             !lowerK.startsWith('_') &&
             !lowerK.startsWith('__') &&
             !['query', 'operationName', 'variables'].includes(lowerK); // graphql wrapper fields
    });

    if (unexpectedKeys.length >= 3 && unexpectedKeys.length > bodyKeys.length * 0.5) {
      findings.push({
        id: 'mass-assignment-unexpected',
        category: 'mass-assignment',
        name: 'Unexpected Parameters in Request Body',
        description: `Request contains ${unexpectedKeys.length} parameter(s) not typical for this endpoint: ${unexpectedKeys.slice(0, 5).join(', ')}${unexpectedKeys.length > 5 ? ` (+${unexpectedKeys.length - 5} more)` : ''}. This may indicate a mass assignment attack vector where extra fields are processed.`,
        severity: 'medium',
        requestIndex: idx,
        evidence: {
          unexpectedKeys: unexpectedKeys.slice(0, 8),
          url: path
        },
        score: 30
      });
    }
  });
}

function getExpectedFieldsForPath(path) {
  // Return common expected field names for common endpoint patterns
  if (/user|account|profile/.test(path)) {
    return ['name', 'email', 'username', 'bio', 'avatar', 'phone', 'address',
            'firstName', 'lastName', 'nickname', 'password', 'currentPassword',
            'newPassword', 'description', 'website', 'location', 'locale'];
  }
  if (/order|checkout|purchase|cart/.test(path)) {
    return ['items', 'productId', 'quantity', 'price', 'shipping', 'address',
            'payment', 'card', 'coupon', 'promo', 'note', 'instructions',
            'currency', 'shippingMethod', 'billing'];
  }
  if (/product|item|listing/.test(path)) {
    return ['name', 'description', 'price', 'category', 'tags', 'image',
            'images', 'sku', 'stock', 'attributes', 'variants'];
  }
  if (/payment|pay|transaction/.test(path)) {
    return ['amount', 'currency', 'card', 'cardNumber', 'expiry', 'cvv',
            'method', 'paymentMethod', 'billing', 'source', 'token'];
  }
  // Generic common fields
  return ['id', 'name', 'type', 'value', 'status', 'action', 'data', 'config',
          'settings', 'options', 'metadata', 'enabled', 'disabled'];
}

// =========================
// DETECTOR: BUSINESS PROCESS BYPASS
// =========================
/**
 * Detect Business Process Bypass:
 * - Skipping required workflow steps
 * - Irregular ordering of operations
 * - Accessing final steps without completing prerequisites
 * - Bypassing validation/guard steps
 */
function detectProcessBypass(sortedReqs, workflow, findings) {
  if (sortedReqs.length < 2) return;

  // 1. Build step sequence
  const steps = sortedReqs.map((req, idx) => {
    const path = getPathname(req.request.url).toLowerCase();
    const method = req.request.method;
    const gqlOps = req._graphql ? req._graphql.operations : [];
    const isMutation = isMutatingRequest(req);

    // Classify step
    let stepType = 'read';
    if (isMutation) stepType = 'write';
    if (gqlOps.some(o => o.type === 'mutation')) stepType = 'gql-mutation';

    // Detect step purpose from path
    let purpose = 'unknown';
    if (/login|signin|auth/.test(path)) purpose = 'authentication';
    else if (/cart|add.?item|remove.?item/.test(path)) purpose = 'cart-operation';
    else if (/checkout|purchase|buy|order/.test(path)) purpose = 'checkout';
    else if (/payment|pay|charge/.test(path)) purpose = 'payment';
    else if (/confirm|verify|validate/.test(path)) purpose = 'validation';
    else if (/cancel|refund|return/.test(path)) purpose = 'cancellation';
    else if (/shipping|fulfill|deliver/.test(path)) purpose = 'fulfillment';
    else if (/review|rate|feedback/.test(path)) purpose = 'review';
    else if (/search|browse|catalog|explore/.test(path)) purpose = 'browsing';
    else if (gqlOps.some(o => /check|validate|verify|auth|perm/i.test(o.operationName))) purpose = 'validation';
    else if (gqlOps.some(o => /pay|checkout|buy|purchase|submit|delete|update/i.test(o.operationName))) purpose = 'write-operation';

    return { idx, path, method, isMutation, stepType, purpose, req };
  });

  // 2. Check for payment without cart/order
  const paymentSteps = steps.filter(s => s.purpose === 'payment');
  const cartSteps = steps.filter(s => s.purpose === 'cart-operation');
  const checkoutSteps = steps.filter(s => s.purpose === 'checkout');

  if (paymentSteps.length > 0 && cartSteps.length === 0 && checkoutSteps.length === 0) {
    findings.push({
      id: 'bypass-payment-no-cart',
      category: 'process-bypass',
      name: 'Payment Without Cart/Checkout Preparation',
      description: 'Payment operation detected without any preceding cart or checkout preparation step. This suggests the business process validation might be bypassed, allowing direct payment manipulation.',
      severity: 'high',
      evidence: {
        paymentEndpoint: paymentSteps[0].path,
        workflowUrl: workflow.url
      },
      score: 70
    });
  }

  // 3. Check for write operations without preceding validation
  const hasValidation = steps.some(s => s.purpose === 'validation');
  const writeSteps = steps.filter(s => s.purpose === 'write-operation' || s.purpose === 'payment' || s.purpose === 'checkout');

  if (writeSteps.length > 0 && !hasValidation && steps.length > 1) {
    findings.push({
      id: 'bypass-validation-gap',
      category: 'process-bypass',
      name: 'Write Operation Without Validation Step',
      description: `Detected ${writeSteps.length} write operation(s) (${writeSteps.map(s => s.path).join(', ')}) without any preceding validation/verification step. Critical operations should be guarded by server-side validation.`,
      severity: 'high',
      requestIndex: writeSteps[0].idx,
      evidence: {
        writeEndpoints: writeSteps.map(s => `${s.method} ${s.path}`),
        totalSteps: steps.length
      },
      score: 65
    });
  }

  // 4. Check for checkout before browsing or cart
  if (checkoutSteps.length > 0) {
    const firstCheckout = checkoutSteps[0];
    const beforeCheckout = steps.slice(0, firstCheckout.idx);
    const hasPriorInteraction = beforeCheckout.some(s =>
      s.purpose === 'browsing' || s.purpose === 'cart-operation' ||
      s.purpose === 'authentication'
    );

    if (!hasPriorInteraction && beforeCheckout.length === 0) {
      findings.push({
        id: 'bypass-direct-checkout',
        category: 'process-bypass',
        name: 'Direct Checkout Without Prior Interaction',
        description: `Checkout endpoint (${firstCheckout.path}) was accessed as the first operation, without user browsing, cart actions, or authentication. This may allow bypassing cart validation and business rules.`,
        severity: 'high',
        requestIndex: firstCheckout.idx,
        evidence: {
          endpoint: firstCheckout.path,
          method: firstCheckout.method
        },
        score: 60
      });
    }
  }

  // 5. Check for missing auth before privileged operations
  const authSteps = steps.filter(s => s.purpose === 'authentication');
  const privilegedOps = steps.filter(s =>
    s.purpose === 'payment' || s.purpose === 'checkout' ||
    s.purpose === 'cancellation' || s.purpose === 'fulfillment'
  );

  if (privilegedOps.length > 0 && authSteps.length === 0) {
    // Only flag if the workflow contains privileged operations without any auth
    findings.push({
      id: 'bypass-no-auth-privileged',
      category: 'process-bypass',
      name: 'Privileged Operations Without Authentication',
      description: `Privileged operations (${privilegedOps.map(s => s.path).join(', ')}) performed without a preceding authentication step. This could allow unauthorized users to execute sensitive transactions.`,
      severity: 'high',
      evidence: {
        privilegedEndpoints: privilegedOps.map(s => `${s.method} ${s.path}`)
      },
      score: 75
    });
  }

  // 6. Detect out-of-order process execution
  // If payment occurs before checkout, that's out of order
  const processOrder = steps.map(s => s.purpose).filter(p => p !== 'unknown' && p !== 'browsing' && p !== 'read');
  if (processOrder.length >= 2) {
    // Define expected order for e-commerce: cart → checkout → payment → fulfillment
    const expectedSequence = ['cart-operation', 'checkout', 'payment', 'fulfillment', 'cancellation'];
    const filteredOrder = processOrder.filter(p => expectedSequence.includes(p));

    for (let i = 1; i < filteredOrder.length; i++) {
      const prevIdx = expectedSequence.indexOf(filteredOrder[i - 1]);
      const currIdx = expectedSequence.indexOf(filteredOrder[i]);
      if (currIdx < prevIdx && currIdx >= 0 && prevIdx >= 0) {
        findings.push({
          id: 'bypass-out-of-order',
          category: 'process-bypass',
          name: 'Out-of-Order Process Execution',
          description: `Business process steps executed out of order: \`${filteredOrder[i - 1]}\` → \`${filteredOrder[i]}\`. Expected order is: ${expectedSequence.filter(s => filteredOrder.includes(s)).join(' → ')}. This may indicate process flow bypass.`,
          severity: 'high',
          evidence: {
            actualSequence: filteredOrder,
            expectedSequence: expectedSequence.filter(s => filteredOrder.includes(s))
          },
          score: 65
        });
      }
    }
  }
}

// =========================
// DETECTOR: INPUT VALIDATION FLAWS
// =========================
/**
 * Detect Input Validation Flaws:
 * - SQL/NoSQL injection patterns
 * - Cross-site scripting (XSS) in request params
 * - Boundary violations (empty/null/undefined values)
 * - Type confusion
 * - Path traversal
 * - Special character abuse
 */
function detectInputValidation(sortedReqs, findings) {
  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const bodyText = getRequestBodyText(req);
    const body = tryParseJSON(bodyText);

    // 1. Check all string parameters for injection patterns
    const injectionFindings = [];

    Object.keys(params).forEach(key => {
      const val = String(params[key]);

      // SQL Injection patterns
      for (const pattern of SQL_INJECTION_PATTERNS) {
        if (pattern.test(val)) {
          injectionFindings.push({
            type: 'SQL Injection',
            param: key,
            value: val.substring(0, 80),
            evidence: val.match(pattern)?.[0] || val.substring(0, 30)
          });
          break;
        }
      }

      // NoSQL Injection patterns
      if (typeof params[key] === 'object' || val.startsWith('{') || val.startsWith('$')) {
        for (const pattern of NOSQL_INJECTION_PATTERNS) {
          if (pattern.test(val)) {
            injectionFindings.push({
              type: 'NoSQL Injection',
              param: key,
              value: val.substring(0, 80),
              evidence: val.match(pattern)?.[0] || val.substring(0, 30)
            });
            break;
          }
        }
      }

      // XSS patterns
      if (/<script|<img|<svg|<iframe|onerror=|onload=|onclick=|javascript:/i.test(val)) {
        injectionFindings.push({
          type: 'XSS (Cross-Site Scripting)',
          param: key,
          value: val.substring(0, 80),
          evidence: val.match(/<[^>]+>/)?.[0] || 'script tag'
        });
      }

      // Path traversal
      if (/\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\\/i.test(val)) {
        injectionFindings.push({
          type: 'Path Traversal',
          param: key,
          value: val.substring(0, 80),
          evidence: '../ pattern'
        });
      }
    });

    if (injectionFindings.length > 0) {
      // Group by type
      const byType = {};
      injectionFindings.forEach(f => {
        if (!byType[f.type]) byType[f.type] = [];
        byType[f.type].push(f);
      });

      Object.keys(byType).forEach(injType => {
        const items = byType[injType];
        findings.push({
          id: `input-injection-${injType.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
          category: 'input-validation',
          name: `${injType} Detected in Request Parameters`,
          description: `Found ${items.length} parameter(s) containing ${injType} patterns: ${items.map(i => `\`${i.param}\``).join(', ')}. Value sample: \`${items[0].value.substring(0, 60)}\`.`,
          severity: 'high',
          requestIndex: idx,
          evidence: {
            injectionType: injType,
            parameters: items.map(i => ({ name: i.param, evidence: i.evidence })),
            url: getPathname(req.request.url)
          },
          score: 80
        });
      });
    }

    // 2. Check for empty/null boundary values in required fields
    if (body && typeof body === 'object' && !Array.isArray(body)) {
      const emptyFields = [];
      const nullFields = [];

      Object.keys(body).forEach(key => {
        if (body[key] === null || body[key] === undefined) {
          nullFields.push(key);
        } else if (body[key] === '' && key.length > 1) {
          emptyFields.push(key);
        }
      });

      if (nullFields.length >= 2) {
        findings.push({
          id: 'input-null-fields',
          category: 'input-validation',
          name: 'Null/Undefined Fields in Request Body',
          description: `Request body contains ${nullFields.length} null/undefined field(s): ${nullFields.join(', ')}. This may cause unexpected server behavior, type confusion, or bypass validation checks.`,
          severity: 'medium',
          requestIndex: idx,
          evidence: {
            nullFields,
            url: getPathname(req.request.url)
          },
          score: 25
        });
      }

      // 3. Check for type confusion (numbers where strings expected, etc.)
      const typeConfusions = [];
      Object.keys(body).forEach(key => {
        const val = body[key];
        const lowerKey = key.toLowerCase();
        // If key suggests numeric but value is string (or vice versa)
        if (PRICE_PARAM_NAMES.some(p => lowerKey.includes(p)) || QUANTITY_PARAM_NAMES.some(p => lowerKey.includes(p))) {
          if (typeof val === 'string' && val.trim() !== '' && isNaN(parseFloat(val))) {
            typeConfusions.push({ key, expected: 'number', actual: 'string', value: val });
          }
        }
        if (lowerKey === 'enabled' || lowerKey === 'active' || lowerKey === 'verified' || lowerKey === 'confirmed') {
          if (typeof val === 'string' && !['true', 'false', '1', '0', 'yes', 'no'].includes(val.toLowerCase())) {
            typeConfusions.push({ key, expected: 'boolean', actual: 'string', value: val });
          }
        }
      });

      if (typeConfusions.length > 0) {
        findings.push({
          id: 'input-type-confusion',
          category: 'input-validation',
          name: 'Type Confusion in Request Parameters',
          description: `Potential type confusion in ${typeConfusions.length} field(s): ${typeConfusions.map(t => `\`${t.key}\` (expected ${t.expected}, got ${t.actual})`).join(', ')}. This may bypass validation or cause logic errors.`,
          severity: 'medium',
          requestIndex: idx,
          evidence: {
            typeConfusions,
            url: getPathname(req.request.url)
          },
          score: 30
        });
      }
    }

    // 4. Check query params for special character abuse
    const suspiciousChars = [];
    Object.keys(params).forEach(key => {
      const val = String(params[key]);
      if (val.includes('\x00') || val.includes('\r\n') || val.includes('\n') || val.includes('\r')) {
        suspiciousChars.push(key);
      }
    });

    if (suspiciousChars.length > 0) {
      findings.push({
        id: 'input-special-chars',
        category: 'input-validation',
        name: 'Control Characters in Request Parameters',
        description: `Request contains control characters (null bytes, CRLF) in parameters: ${suspiciousChars.join(', ')}. This may enable HTTP response splitting, log injection, or other attacks.`,
        severity: 'high',
        requestIndex: idx,
        evidence: {
          params: suspiciousChars,
          url: getPathname(req.request.url)
        },
        score: 70
      });
    }
  });
}

// =========================
// DETECTOR: RACE CONDITION / TOCTOU
// =========================
/**
 * Detect Race Condition and TOCTOU vulnerabilities:
 * - Check-then-act with time windows large enough for interference
 * - Concurrent mutations on shared resources
 * - Missing versioning/locking headers
 * - Multiple rapid mutations on same endpoint
 */
function detectRaceCondition(sortedReqs, workflow, findings) {
  if (sortedReqs.length < 2) return;

  const isCheckLikeRequest = (req) => {
    const isGetOrGqlQuery = req.request.method === 'GET' ||
      (req._graphql && req._graphql.operations && req._graphql.operations.some(op => op.type === 'query'));

    const path = getPathname(req.request.url).toLowerCase();
    return isGetOrGqlQuery &&
      (/check|validate|verify|auth|perm|exist|status|search|lookup/.test(path) ||
        (req._graphql && req._graphql.operations?.some(op =>
          /check|validate|verify|auth|perm|exist|status|search|lookup/i.test(op.operationName)
        )));
  };

  const isMutating = (req) => isMutatingRequest(req);

  const getPathGroup = (req) => {
    const p = getPathname(req.request.url).toLowerCase();
    const segs = p.split('/').filter(Boolean);
    return segs.slice(0, 3).join('/') || p;
  };

  // 1. Check-then-act timing analysis
  // Find pairs of (check, mutation) on the same resource path group
  const checkActPairs = [];

  for (let i = 0; i < sortedReqs.length; i++) {
    if (!isCheckLikeRequest(sortedReqs[i])) continue;

    const checkReq = sortedReqs[i];
    const checkEnd = new Date(checkReq.startedDateTime).getTime() + (checkReq.time || 0);
    const checkPathGroup = getPathGroup(checkReq);

    // Look for a mutation on the same resource group after this check
    for (let j = i + 1; j < sortedReqs.length; j++) {
      if (!isMutating(sortedReqs[j])) continue;
      if (getPathGroup(sortedReqs[j]) !== checkPathGroup) continue;

      const mutStart = new Date(sortedReqs[j].startedDateTime).getTime();
      const gap = mutStart - checkEnd;

      // TOCTOU window: check completed BEFORE mutation starts
      if (gap >= 0) {
        checkActPairs.push({
          checkIdx: i,
          mutationIdx: j,
          checkEnd,
          mutStart,
          gapMs: gap,
          checkPath: getPathname(checkReq.request.url),
          mutationPath: getPathname(sortedReqs[j].request.url)
        });
        break; // Pair with the nearest mutation on same path group
      }
    }
  }

  // Flag pairs with large TOCTOU window
  checkActPairs.forEach(pair => {
    if (pair.gapMs > 50) {
      // Larger gap = larger race window
      const severity = pair.gapMs > 500 ? 'high' : (pair.gapMs > 200 ? 'medium' : 'low');
      const score = pair.gapMs > 500 ? 60 : (pair.gapMs > 200 ? 35 : 15);

      findings.push({
        id: 'toctou-check-act',
        category: 'race-condition',
        name: 'TOCTOU Race Window in Check-Then-Act Pattern',
        description: `Time-of-check to time-of-use window of ${pair.gapMs}ms between guard/check (\`${pair.checkPath}\`) and mutation (\`${pair.mutationPath}\`). A larger window increases the chance that the check's result is stale by the time the mutation executes.`,
        severity,
        requestIndex: pair.mutationIdx,
        evidence: {
          checkEndpoint: pair.checkPath,
          mutationEndpoint: pair.mutationPath,
          gapMs: pair.gapMs,
          timing: `${new Date(pair.checkEnd).toISOString()} → ${new Date(pair.mutStart).toISOString()}`
        },
        score
      });
    }
  });

  // 2. Check for missing versioning/locking on mutation endpoints
  sortedReqs.forEach((req, idx) => {
    if (!isMutating(req)) return;

    const headers = req.request.headers || [];
    const hasVersioning = headers.some(h => {
      const name = (h.name || '').toLowerCase();
      return name === 'if-match' || name === 'if-none-match' ||
             name === 'if-unmodified-since' || name === 'x-version' ||
             name === 'version' || name === 'etag' || name === 'x-request-id';
    });

    if (!hasVersioning) {
      const path = getPathname(req.request.url);
      // Only flag for endpoints that look like they should have versioning
      const shouldHaveVersioning = /update|edit|save|modify|change|patch|delete|remove/i.test(path);

      if (shouldHaveVersioning) {
        findings.push({
          id: 'race-no-versioning',
          category: 'race-condition',
          name: 'Missing Optimistic Locking/Versioning',
          description: `Mutation endpoint \`${path}\` does not include versioning headers (If-Match, ETag, If-Unmodified-Since). Without optimistic locking, concurrent updates may silently overwrite each other (lost update problem).`,
          severity: 'medium',
          requestIndex: idx,
          evidence: {
            url: path,
            method: req.request.method,
            missingHeaders: ['If-Match', 'If-Unmodified-Since', 'ETag']
          },
          score: 30
        });
      }
    }
  });

  // 3. Rapid concurrent mutations on same resource
  const mutatingReqs = sortedReqs
    .map((req, idx) => ({ req, idx }))
    .filter(({ req }) => isMutating(req));

  if (mutatingReqs.length >= 2) {
    let raceyCount = 0;
    for (let k = 1; k < mutatingReqs.length; k++) {
      const prev = mutatingReqs[k - 1];
      const curr = mutatingReqs[k];
      const prevTime = new Date(prev.req.startedDateTime).getTime();
      const currTime = new Date(curr.req.startedDateTime).getTime();
      const gap = currTime - prevTime;

      if (gap >= 0 && gap < 150 && getPathGroup(prev.req) === getPathGroup(curr.req)) {
        raceyCount++;
      }
    }

    if (raceyCount > 0) {
      findings.push({
        id: 'race-concurrent-mutations',
        category: 'race-condition',
        name: 'Concurrent Mutation Race Condition',
        description: `Detected ${raceyCount} near-concurrent mutation(s) (start-gap < 150ms) targeting the same resource path group. This pattern can lead to race conditions where concurrent requests interfere with each other.`,
        severity: raceyCount >= 2 ? 'high' : 'medium',
        evidence: {
          raceyMutationCount: raceyCount,
          totalMutations: mutatingReqs.length,
          targets: [...new Set(mutatingReqs.map(({ req }) => getPathGroup(req)))]
        },
        score: raceyCount >= 2 ? 55 : 35
      });
    }
  }
}

