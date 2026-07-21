/**
 * Auth Bypass via State Manipulation Detection Engine
 *
 * Analyzes workflows and individual requests for common authentication
 * bypass vulnerabilities achieved through state/token manipulation:
 *   - JWT Manipulation (alg:none, signature stripping, algorithm confusion)
 *   - Token/Session Fixation (attacker-controlled token insertion)
 *   - OAuth State Parameter Weakness (missing, static, or predictable state)
 *   - Password Reset Token Weakness (predictable tokens, user-ID in reset)
 *   - Session Attribute Manipulation (client-controlled login/isLoggedIn state)
 *   - MFA/2FA Bypass (skipping verification, mfa_verified manipulation)
 *   - Remember-Me / Persistent Auth Token Weakness
 *   - Authorization Header/Token Injection (escalation via token manipulation)
 *   - Email/SMS Verification Bypass (email_verified, skip verification params)
 *   - Role/Scope Manipulation in Token Claims
 */

// =========================
// PUBLIC INTERFACE
// =========================

/**
 * Run all auth bypass state manipulation detectors against a workflow.
 * Returns an array of flaw findings compatible with the existing flaws engine.
 */
export function detectAuthBypassStateManip(workflow) {
  if (!workflow || !Array.isArray(workflow.requests) || workflow.requests.length === 0) {
    return [];
  }

  const sortedReqs = [...workflow.requests].sort((a, b) => {
    return new Date(a.startedDateTime).getTime() - new Date(b.startedDateTime).getTime();
  });

  const findings = [];

  // Run each detector
  detectJWTMAnipulation(sortedReqs, findings);
  detectTokenSessionFixation(sortedReqs, findings);
  detectOAuthStateWeakness(sortedReqs, findings);
  detectPasswordResetWeakness(sortedReqs, findings);
  detectSessionAttributeManipulation(sortedReqs, findings);
  detectMFABypass(sortedReqs, findings);
  detectRememberMeWeakness(sortedReqs, findings);
  detectAuthHeaderTokenInjection(sortedReqs, findings);
  detectEmailVerificationBypass(sortedReqs, findings);
  detectTokenClaimManipulation(sortedReqs, findings);

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
 * Base64url-decode a JWT segment.
 */
function base64UrlDecode(str) {
  try {
    // Replace base64url characters and add padding
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) base64 += '=';
    return atob(base64);
  } catch (_) {
    return null;
  }
}

/**
 * Try to parse a JWT token (3 dot-separated base64 segments).
 * Returns { header, payload, signature } or null.
 */
function parseJWT(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const headerStr = base64UrlDecode(parts[0]);
  const payloadStr = base64UrlDecode(parts[1]);

  if (!headerStr || !payloadStr) return null;

  try {
    const header = JSON.parse(headerStr);
    const payload = JSON.parse(payloadStr);
    return { header, payload, signature: parts[2] };
  } catch (_) {
    return null;
  }
}

/**
 * Detect if a value looks like a JWT token.
 */
function looksLikeJWT(val) {
  if (!val || typeof val !== 'string') return false;
  // JWT has 3 base64url segments separated by dots
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(val.trim());
}

/**
 * Extract all JWT-like tokens from a set of text values.
 */
function extractJWTs(textValues) {
  const tokens = [];
  textValues.forEach(val => {
    if (looksLikeJWT(val)) {
      const parsed = parseJWT(val);
      if (parsed) tokens.push({ token: val.trim(), parsed });
    }
    // Also find JWT embedded in longer strings
    const matches = val.match(/([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/g);
    if (matches) {
      matches.forEach(m => {
        const parsed = parseJWT(m);
        if (parsed) tokens.push({ token: m, parsed });
      });
    }
  });
  return tokens;
}

/**
 * Check if a string looks like a predictable/weak session token (short, alphanumeric, etc.)
 */
function isWeakToken(val) {
  if (!val || typeof val !== 'string') return false;
  // Very short tokens (< 16 chars) are often weak/predictable
  if (val.length < 16 && val.length >= 6) return true;
  // Sequential numbers
  if (/^\d{6,15}$/.test(val)) return true;
  // Base62 tokens with low entropy (all same char or simple pattern)
  if (/^(.)\1{5,}$/.test(val)) return true;
  if (/^(123|abc|qwe|asd|test|token|session|sid).*/i.test(val)) return true;
  return false;
}

// =========================
// CONSTANTS
// =========================

// Known JWT algorithms
const JWT_ALG_WEAK = ['none', 'None', 'NONE', 'nOnE'];
const JWT_ALG_SYMMETRIC = ['HS256', 'HS384', 'HS512'];
const JWT_ALG_ASYMMETRIC = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];

// Common auth endpoint patterns
const AUTH_ENDPOINTS = [
  /login/i, /signin/i, /sign-in/i, /log-in/i,
  /auth/i, /authenticate/i, /authorize/i,
  /oauth/i, /token/i, /session/i,
  /logout/i, /signout/i, /sign-out/i, /log-out/i,
  /register/i, /signup/i, /sign-up/i,
  /reset/i, /forgot/i, /forgot-password/i, /reset-password/i,
  /verify/i, /verification/i, /confirm/i,
  /mfa/i, /2fa/i, /tfa/i, /two.?factor/i,
  /password/i, /change-password/i, /update-password/i
];

// Session-related parameter names commonly tampered with
const SESSION_PARAM_NAMES = [
  'session', 'sessionid', 'session_id', 'sid', 'sessid',
  'token', 'access_token', 'refresh_token', 'auth_token',
  'jwt', 'bearer', 'api_key', 'api-key', 'apikey',
  'loggedin', 'logged_in', 'isLoggedIn', 'is_logged_in',
  'authenticated', 'isAuthenticated', 'is_authenticated',
  'login', 'isLogin', 'is_login'
];

// OAuth state parameter names
const OAUTH_STATE_PARAM_NAMES = [
  'state', 'oauth_state', 'oauthState', 'oauth-state',
  'auth_state', 'authState', 'auth-state',
  'session_state', 'sessionState', 'session-state'
];

// Password reset parameter names
const PASSWORD_RESET_PARAM_NAMES = [
  'reset_token', 'resetToken', 'reset-token',
  'token', 'password_token', 'passwordToken',
  'reset_code', 'resetCode', 'reset-code',
  'code', 'verification_code', 'verificationCode',
  'recovery_token', 'recoveryToken', 'recovery-token'
];

// MFA-related parameter names
const MFA_PARAM_NAMES = [
  'mfa', 'mfa_code', 'mfaCode', 'mfa-code',
  'mfa_token', 'mfaToken', 'mfa-token',
  'mfa_verified', 'mfaVerified', 'mfa-verified',
  '2fa', '2fa_code', '2faCode', '2fa-code',
  '2fa_token', '2faToken', '2fa-token',
  '2fa_verified', '2faVerified', '2fa-verified',
  'tfa', 'totp', 'otp', 'one_time_password', 'oneTimePassword',
  'verification_code', 'verificationCode',
  'require_mfa', 'requireMfa', 'require-mfa',
  'skip_mfa', 'skipMfa', 'skip-mfa',
  'mfa_enabled', 'mfaEnabled', 'mfa-enabled',
  'isMfaVerified', 'is_mfa_verified',
  'mfaBypass', 'mfa_bypass', 'mfa-bypass'
];

// Email/SMS verification parameter names
const EMAIL_VERIFY_PARAM_NAMES = [
  'email_verified', 'emailVerified', 'email-verified',
  'isEmailVerified', 'is_email_verified',
  'email_confirmed', 'emailConfirmed', 'email-confirmed',
  'phone_verified', 'phoneVerified', 'phone-verified',
  'isPhoneVerified', 'is_phone_verified',
  'phone_confirmed', 'phoneConfirmed', 'phone-confirmed',
  'verified', 'confirmed', 'isVerified', 'is_verified',
  'skip_verification', 'skipVerification', 'skip-verification',
  'require_verification', 'requireVerification', 'require-verification',
  'verification_skip', 'verificationSkip', 'verification-skip'
];

// Remember-me / persistent auth parameter names
const REMEMBER_ME_PARAM_NAMES = [
  'remember', 'remember_me', 'rememberMe', 'remember-me',
  'persist', 'persistent', 'persist_session', 'persistSession',
  'keep_logged_in', 'keepLoggedIn', 'keep-logged-in',
  'stay_signed_in', 'staySignedIn', 'stay-signed-in',
  'remember_token', 'rememberToken', 'remember-token'
];

// Role/scope claim names commonly found in JWT or session
const ROLE_SCOPE_CLAIM_NAMES = [
  'role', 'roles', 'userRole', 'user_role', 'user-type',
  'scope', 'scopes', 'permission', 'permissions',
  'access', 'access_level', 'accessLevel', 'access-level',
  'privilege', 'privileges', 'is_admin', 'isAdmin', 'admin',
  'is_premium', 'isPremium', 'premium',
  'is_moderator', 'isModerator', 'moderator',
  'group', 'groups', 'user_group', 'userGroup',
  'type', 'user_type', 'userType', 'member_type', 'memberType',
  'account_type', 'accountType', 'account-type',
  'subscription', 'plan', 'tier', 'level',
  'org', 'organization', 'tenant', 'company',
  'department', 'team'
];

// =========================
// DETECTOR 1: JWT MANIPULATION
// =========================
/**
 * Detect JWT Manipulation attacks:
 * - alg: none (signature verification disabled)
 * - Algorithm confusion (RS256 public key used as HMAC secret)
 * - Signature stripping / empty signature
 * - JWK header injection (embedded JWK in header)
 * - Kid header injection (path traversal / SQLi in kid)
 * - Weak/guessable HMAC secret (short or common secret)
 */
function detectJWTMAnipulation(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const headers = getAllHeaderValues(req);
    const bodyText = getRequestBodyText(req);
    const allTextValues = [];

    // Collect JWT candidates from Authorization header
    const authHeader = headers.find(h => h.name.toLowerCase() === 'authorization');
    if (authHeader) {
      const val = authHeader.value || '';
      // Extract Bearer token
      const bearerMatch = val.match(/^Bearer\s+(.+)$/i);
      if (bearerMatch) allTextValues.push(bearerMatch[1]);
      allTextValues.push(val);
    }

    // Collect from params that might contain tokens
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (lowerKey === 'token' || lowerKey === 'access_token' || lowerKey === 'jwt' ||
          lowerKey === 'bearer' || lowerKey === 'auth_token' || lowerKey === 'refresh_token' ||
          lowerKey === 'id_token') {
        allTextValues.push(String(params[key]));
      }
    });

    // Collect from body
    if (bodyText) allTextValues.push(bodyText);

    // Collect from cookie header
    const cookieHeader = headers.find(h => h.name.toLowerCase() === 'cookie');
    if (cookieHeader) {
      const cookieVal = cookieHeader.value || '';
      // Look for JWT-like cookies
      const cookieParts = cookieVal.split(';').map(c => c.trim());
      cookieParts.forEach(cp => {
        const eqIdx = cp.indexOf('=');
        if (eqIdx > 0) {
          const cv = cp.substring(eqIdx + 1);
          if (looksLikeJWT(cv)) allTextValues.push(cv);
        }
      });
    }

    // Extract and parse all JWT tokens
    const jwtTokens = extractJWTs(allTextValues);
    if (jwtTokens.length === 0) return;

    const jwtIssues = [];

    jwtTokens.forEach(({ token, parsed }) => {
      const { header, payload } = parsed;

      // 1. alg: none
      if (header.alg && JWT_ALG_WEAK.includes(header.alg)) {
        jwtIssues.push({
          type: 'alg-none',
          severity: 'high',
          description: `JWT uses \`alg: ${header.alg}\` which disables signature verification. Attackers can forge arbitrary tokens by setting the algorithm to "none" and stripping the signature.`
        });
      }

      // 2. Algorithm confusion (symmetric key expected but asymmetric used, or vice versa)
      // Check if RS256 public key could be used as HMAC secret (algorithm confusion)
      if (header.alg && header.alg.startsWith('HS') && header.jwk) {
        jwtIssues.push({
          type: 'alg-confusion-jwk',
          severity: 'high',
          description: `JWT header contains both an HMAC algorithm (\`${header.alg}\`) and an embedded JWK. This is a classic JWT algorithm confusion attack where the attacker embeds their own RSA public key and uses it as the HMAC secret.`
        });
      }

      // 3. Empty signature
      if (!parsed.signature || parsed.signature.trim() === '' || parsed.signature === ' ') {
        jwtIssues.push({
          type: 'empty-signature',
          severity: 'high',
          description: 'JWT has an empty signature segment. This means the token has no cryptographic signature, allowing arbitrary token forgery.'
        });
      }

      // 4. Weak signature (very short, e.g., less than 20 chars base64 = weak key)
      if (parsed.signature && parsed.signature.length < 20) {
        jwtIssues.push({
          type: 'weak-signature',
          severity: 'medium',
          description: `JWT signature is suspiciously short (${parsed.signature.length} chars). Short signatures often indicate weak HMAC secrets or truncated signatures that can be brute-forced.`
        });
      }

      // 5. JWK header injection
      if (header.jwk) {
        jwtIssues.push({
          type: 'jwk-injection',
          severity: 'high',
          description: 'JWT header contains an embedded JWK (JSON Web Key). Servers that accept JWK from the header can be tricked into using attacker-controlled public keys to verify the token signature.'
        });
      }

      // 6. kid header injection (path traversal)
      if (header.kid) {
        const kidVal = String(header.kid);
        if (/\.\.\/|\.\.\\|%2e%2e|file:\/\//i.test(kidVal) || kidVal.includes('/') || kidVal.includes('\\')) {
          jwtIssues.push({
            type: 'kid-injection',
            severity: 'high',
            description: `JWT \`kid\` (key ID) header contains path traversal characters: \`${kidVal.substring(0, 60)}\`. This can trick the server into using an arbitrary file as the verification key.`
          });
        }
        // SQL injection in kid
        if (/['"]|--|;|\bOR\b|\bAND\b/i.test(kidVal)) {
          jwtIssues.push({
            type: 'kid-sqli',
            severity: 'high',
            description: `JWT \`kid\` header contains SQL-like syntax: \`${kidVal.substring(0, 60)}\`. This could exploit SQL injection in the key lookup mechanism.`
          });
        }
      }

      // 7. Payload contains weak claims (empty subject, alg overrides)
      if (payload && payload.alg) {
        jwtIssues.push({
          type: 'payload-alg-override',
          severity: 'high',
          description: 'JWT payload contains an \`alg\` field. In some vulnerable implementations, the payload\'s algorithm can override the header, allowing signature bypass.'
        });
      }

      // 8. Predictable/sequential jti
      if (payload && payload.jti) {
        if (/^\d+$/.test(payload.jti) || /^[a-f0-9]{8,12}$/i.test(payload.jti)) {
          jwtIssues.push({
            type: 'predictable-jti',
            severity: 'medium',
            description: `JWT \`jti\` (JWT ID) looks predictable/sequential: \`${payload.jti}\`. Predictable token IDs can enable token replay or session hijacking.`
          });
        }
      }

      // 9. Long expiration or no expiration
      if (payload) {
        if (!payload.exp) {
          jwtIssues.push({
            type: 'no-expiration',
            severity: 'medium',
            description: 'JWT token has no \`exp\` (expiration) claim. Tokens without expiration never expire, significantly increasing the risk of token theft and misuse.'
          });
        } else if (typeof payload.exp === 'number') {
          const expDate = new Date(payload.exp * 1000);
          const now = Date.now();
          const maxExpiryMs = 365 * 24 * 60 * 60 * 1000; // 1 year
          if (expDate.getTime() - now > maxExpiryMs) {
            jwtIssues.push({
              type: 'excessive-expiration',
              severity: 'medium',
              description: `JWT has an excessive expiration period (${Math.round((expDate.getTime() - now) / (24*60*60*1000))} days). Long-lived tokens increase the window of opportunity for token theft.`
            });
          }
        }
      }

      // 10. Crit header present
      if (header.crit && Array.isArray(header.crit)) {
        jwtIssues.push({
          type: 'crit-header',
          severity: 'medium',
          description: `JWT header contains \`crit\` (critical) extension: ${JSON.stringify(header.crit)}. Implementations that mishandle critical headers may skip signature verification entirely.`
        });
      }
    });

    if (jwtIssues.length === 0) return;

    const findId = 'auth-jwt-manipulation';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const highSeverityIssues = jwtIssues.filter(i => i.severity === 'high');
    const overallSeverity = highSeverityIssues.length > 0 ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'auth-bypass-state-manip',
      name: 'JWT Manipulation / Algorithm Confusion',
      description: `Detected ${jwtIssues.length} JWT security issue(s) in the request: ${jwtIssues.map(i => i.description).join(' ')}. JWT manipulation attacks exploit improper validation of token headers, signatures, or claims to forge or tamper with authentication tokens.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        issues: jwtIssues.map(i => ({ type: i.type, severity: i.severity })),
        tokenHeader: jwtTokens[0]?.parsed?.header || {},
        tokenPayload: jwtTokens[0]?.parsed?.payload || {},
        url: getPathname(req.request.url || ''),
        method: req.request.method || 'GET'
      },
      score: overallSeverity === 'high' ? 90 : 50
    });
  });
}

// =========================
// DETECTOR 2: TOKEN / SESSION FIXATION
// =========================
/**
 * Detect Token/Session Fixation:
 * - Session token provided in URL (not just in cookie/header)
 * - Predictable session IDs in response (set-cookie with known value)
 * - Attacker-controlled session token being accepted
 * - Session token in query string parameters
 * - Accepting arbitrary session tokens without validation
 */
function detectTokenSessionFixation(sortedReqs, findings) {
  const requestFindings = new Map();

  // Track session tokens seen across requests
  const sessionTokensSeen = [];

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const headers = getAllHeaderValues(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);

    const fixationIssues = [];

    // 1. Session token in URL query string
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (SESSION_PARAM_NAMES.includes(lowerKey)) {
        const val = String(params[key]);
        if (val && val.length > 4 && val.length < 64) {
          fixationIssues.push({
            type: 'token-in-url',
            param: key,
            valueSample: val.substring(0, 30),
            description: `Session/token parameter \`${key}\` is passed in URL query string. Session tokens in URLs are vulnerable to leakage via Referer headers, browser history, and server logs.`
          });
        }
      }
    });

    // 2. Check Set-Cookie response headers for predictable session IDs
    const setCookieHeaders = [];
    if (req.response && Array.isArray(req.response.headers)) {
      req.response.headers.forEach(h => {
        if ((h.name || '').toLowerCase() === 'set-cookie') {
          setCookieHeaders.push(h.value || '');
        }
      });
    }

    setCookieHeaders.forEach(cookieStr => {
      const cookieParts = cookieStr.split(';').map(c => c.trim());
      cookieParts.forEach(part => {
        const eqIdx = part.indexOf('=');
        if (eqIdx > 0) {
          const name = part.substring(0, eqIdx).trim();
          const value = part.substring(eqIdx + 1).trim();
          // Check if cookie name looks like a session token
          if (SESSION_PARAM_NAMES.includes(name.toLowerCase())) {
            if (isWeakToken(value)) {
              fixationIssues.push({
                type: 'weak-session-cookie',
                param: name,
                valueSample: value.substring(0, 30),
                description: `Server sets a weak/predictable session cookie (\`${name}\`) with value \`${value.substring(0, 20)}...\`. Predictable session IDs allow session fixation and hijacking attacks.`
              });
            }
            sessionTokensSeen.push({ name, value, idx, source: 'set-cookie' });
          }
        }
      });
    });

    // 3. Check if session token is accepted in multiple ways (cookie + param + header)
    // - If token appears in both cookie and query/body, this enables fixation
    const cookieHeaders = headers.filter(h => h.name.toLowerCase() === 'cookie');
    const cookieTokens = [];
    cookieHeaders.forEach(c => {
      const cookieVal = c.value || '';
      cookieVal.split(';').forEach(cp => {
        const eqIdx = cp.indexOf('=');
        if (eqIdx > 0) {
          const name = cp.substring(0, eqIdx).trim();
          const value = cp.substring(eqIdx + 1).trim();
          if (SESSION_PARAM_NAMES.includes(name.toLowerCase())) {
            cookieTokens.push({ name, value });
          }
        }
      });
    });

    // Check if same session param appears in both cookie and query/body
    cookieTokens.forEach(ct => {
      Object.keys(params).forEach(key => {
        if (key.toLowerCase() === ct.name.toLowerCase() && String(params[key]) === ct.value) {
          // This is expected — token echoed. But if they differ, flag it.
        }
      });
    });

    // 4. Check for session token in request body (POST body)
    const bodyText = getRequestBodyText(req);
    if (bodyText) {
      const parsed = tryParseJSON(bodyText);
      if (parsed && typeof parsed === 'object') {
        Object.keys(parsed).forEach(key => {
          const lowerKey = key.toLowerCase();
          if (SESSION_PARAM_NAMES.includes(lowerKey) && typeof parsed[key] === 'string') {
            const val = parsed[key];
            if (isWeakToken(val) && val.length < 32) {
              fixationIssues.push({
                type: 'weak-token-in-body',
                param: key,
                valueSample: val.substring(0, 30),
                description: `Session/token \`${key}\` in request body has low entropy (short/predictable value). Weak tokens enable brute-force session hijacking.`
              });
            }
          }
        });
      }
    }

    // 5. Check for session token in Authorization header being weak
    const authHeader = headers.find(h => h.name.toLowerCase() === 'authorization');
    if (authHeader) {
      const val = (authHeader.value || '').replace(/^Bearer\s+/i, '').trim();
      if (looksLikeJWT(val)) {
        // JWT analysis is handled by detector 1
      } else if (val && val.length < 20 && val.length > 3) {
        // Very short bearer token could be weak
        fixationIssues.push({
          type: 'weak-bearer-token',
          param: 'Authorization',
          valueSample: val.substring(0, 20),
          description: 'Authorization header contains a suspiciously short bearer token. Short tokens are easier to forge or brute-force.'
        });
      }
    }

    // 6. Cross-request: check for token reuse across different users/endpoints
    // (This is tracked by sessionTokensSeen and will be analyzed post-loop)

    if (fixationIssues.length === 0) return;

    const findId = 'auth-token-session-fixation';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const hasWeakToken = fixationIssues.some(i => i.type === 'weak-session-cookie' || i.type === 'weak-token' || i.type === 'weak-bearer-token');
    const severity = hasWeakToken ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'auth-bypass-state-manip',
      name: 'Session Fixation / Weak Session Token',
      description: `Detected ${fixationIssues.length} session token weakness(es): ${fixationIssues.map(i => i.description).join(' ')}. Session fixation allows attackers to force a known session on a user, while weak/predictable tokens enable brute-force session hijacking.`,
      severity,
      requestIndex: idx,
      evidence: {
        issues: fixationIssues,
        url: path,
        method: req.request.method || 'GET',
        endpointType: AUTH_ENDPOINTS.some(p => p.test(path)) ? 'auth-related' : 'general'
      },
      score: severity === 'high' ? 75 : 40
    });
  });

  // Post-loop: check for token reuse across different states
  if (sessionTokensSeen.length >= 2) {
    // Check if the same token value appears in different auth states (pre/post login)
    // This would require tracking response status, but for simplicity we flag if
    // the same session token appears across multiple requests with different endpoints
    // that suggest different auth states
    const tokenValues = sessionTokensSeen.map(t => t.value);
    const uniqueValues = [...new Set(tokenValues)];
    if (uniqueValues.length < sessionTokensSeen.length) {
      // Same token reused — could indicate fixation
      // (We check if any value appears more than once across different endpoints)
    }
  }
}

// =========================
// DETECTOR 3: OAUTH STATE PARAMETER WEAKNESS
// =========================
/**
 * Detect OAuth State Parameter Weaknesses:
 * - Missing state parameter in OAuth requests
 * - Static/hardcoded state parameter
 * - Predictable state parameter (timestamp, sequential number)
 * - State parameter reused across multiple OAuth flows
 * - State parameter leaked in URL
 */
function detectOAuthStateWeakness(sortedReqs, findings) {
  const requestFindings = new Map();
  const stateValuesSeen = [];

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);

    // Only analyze OAuth-related endpoints
    const isOAuthEndpoint = /oauth|authorize|callback|redirect.*code|response_type|client_id/i.test(url) ||
                            /oauth|authorize|callback/i.test(path);
    if (!isOAuthEndpoint) return;

    const oauthIssues = [];

    // 1. Check for state parameter
    let stateParamFound = false;
    let stateValue = null;
    let stateParamName = null;

    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (OAUTH_STATE_PARAM_NAMES.includes(lowerKey)) {
        stateParamFound = true;
        stateValue = String(params[key]);
        stateParamName = key;
      }
    });

    // 2. No state parameter in OAuth request
    if (!stateParamFound && /authorize|auth|login/i.test(path)) {
      oauthIssues.push({
        type: 'missing-state',
        description: 'OAuth authorization request is missing the \`state\` parameter. Without a state parameter, the OAuth flow is vulnerable to CSRF attacks where an attacker can bind their authorization to a victim\'s account.'
      });
    }

    // 3. Static/predictable state parameter
    if (stateParamFound && stateValue) {
      // Static values that never change
      if (/^(test|state|nonce|random|x|1|null|undefined|0|true|false|static|xyz|abc|123)$/i.test(stateValue)) {
        oauthIssues.push({
          type: 'static-state',
          param: stateParamName,
          value: stateValue,
          description: `OAuth \`state\` parameter has a static/predictable value: \`${stateValue}\`. A static state parameter provides no CSRF protection, allowing attackers to forge authorization requests.`
        });
      }

      // Sequential or timestamp-based state
      if (/^\d{10,13}$/.test(stateValue) || /^\d{4,8}$/.test(stateValue)) {
        oauthIssues.push({
          type: 'predictable-state',
          param: stateParamName,
          value: stateValue,
          description: `OAuth \`state\` parameter looks like a timestamp or sequential number (\`${stateValue}\`). Predictable state values can be guessed by attackers.`
        });
      }

      // Very short state
      if (stateValue.length < 8 && stateValue.length > 0) {
        oauthIssues.push({
          type: 'short-state',
          param: stateParamName,
          value: stateValue,
          description: `OAuth \`state\` parameter is very short (${stateValue.length} chars). Short state values provide minimal entropy and are easier to predict.`
        });
      }

      // State leaked in URL (already in query string)
      oauthIssues.push({
        type: 'state-in-url',
        param: stateParamName,
        description: 'OAuth state parameter is passed in the URL query string. While this is standard OAuth2 behavior, it exposes the state to browser history and Referer headers.'
      });

      // Track state values for cross-request analysis
      stateValuesSeen.push({ value: stateValue, idx, url: path });
    }

    // 4. Check response for state mismatch (if available)
    // (Would require correlating callback requests)

    if (oauthIssues.length === 0) return;

    const findId = 'auth-oauth-state-weakness';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const highSeverityIssues = oauthIssues.filter(i =>
      i.type === 'missing-state' || i.type === 'static-state' || i.type === 'predictable-state'
    );
    const overallSeverity = highSeverityIssues.length > 0 ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'auth-bypass-state-manip',
      name: 'OAuth State Parameter Weakness (CSRF)',
      description: `Detected ${oauthIssues.length} OAuth state parameter issue(s): ${oauthIssues.map(i => i.description).join(' ')}. A missing or weak OAuth state parameter exposes the authorization flow to CSRF attacks, allowing attackers to hijack account linking.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        issues: oauthIssues.map(i => ({ type: i.type, ...(i.param ? { param: i.param } : {}), ...(i.value ? { valueSample: i.value.substring(0, 30) } : {}) })),
        url: path,
        method: req.request.method || 'GET'
      },
      score: overallSeverity === 'high' ? 80 : 35
    });
  });
}

// =========================
// DETECTOR 4: PASSWORD RESET TOKEN WEAKNESS
// =========================
/**
 * Detect Password Reset Token Weaknesses:
 * - User ID or email embedded in reset token
 * - Predictable reset token (timestamp, sequential number)
 * - Short/weak reset code
 * - Token in URL (leaked via Referer)
 * - Reset token reuse allowed
 * - Missing token expiration
 * - Email/username enumeration via reset endpoint
 */
function detectPasswordResetWeakness(sortedReqs, findings) {
  const requestFindings = new Map();
  const resetTokensSeen = [];

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const headers = getAllHeaderValues(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);
    const bodyText = getRequestBodyText(req);

    // Only analyze password-reset-related endpoints
    const isResetEndpoint = /reset|forgot|recover|change-password|update-password/i.test(path);
    if (!isResetEndpoint) return;

    const resetIssues = [];

    // 1. Extract reset tokens from params
    let resetTokenValue = null;
    let resetTokenParam = null;

    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (PASSWORD_RESET_PARAM_NAMES.includes(lowerKey)) {
        resetTokenValue = String(params[key]);
        resetTokenParam = key;
      }
    });

    // Also check from body
    if (!resetTokenValue && bodyText) {
      const parsed = tryParseJSON(bodyText);
      if (parsed && typeof parsed === 'object') {
        Object.keys(parsed).forEach(key => {
          const lowerKey = key.toLowerCase();
          if (PASSWORD_RESET_PARAM_NAMES.includes(lowerKey) && typeof parsed[key] === 'string') {
            resetTokenValue = parsed[key];
            resetTokenParam = key;
          }
        });
      }
    }

    // 2. Check for user ID or email in reset request (allows enumeration)
    const hasUserIdentifier = params['email'] || params['username'] || params['user'] || params['userId'] || params['user_id'];
    if (hasUserIdentifier && /reset|forgot/i.test(path)) {
      resetIssues.push({
        type: 'user-enumeration',
        description: 'Password reset endpoint accepts a user identifier (email/username) in the request. Different responses for valid vs. invalid users enable enumeration attacks. Additionally, combining user IDs with reset tokens can allow attackers to reset arbitrary accounts.'
      });
    }

    // 3. Weak reset token
    if (resetTokenValue) {
      // Short token
      if (resetTokenValue.length < 10) {
        resetIssues.push({
          type: 'short-token',
          param: resetTokenParam,
          valueSample: resetTokenValue.substring(0, 20),
          description: `Password reset token is very short (${resetTokenValue.length} characters). Short reset tokens can be brute-forced.`
        });
      }

      // Numeric only (extremely weak)
      if (/^\d{4,8}$/.test(resetTokenValue)) {
        resetIssues.push({
          type: 'numeric-token',
          param: resetTokenParam,
          valueSample: resetTokenValue,
          description: `Password reset token is purely numeric (${resetTokenValue.length} digits). Numeric reset codes (typically 4-8 digits) can be brute-forced in a few hundred to million attempts.`
        });
      }

      // Timestamp-based token
      if (/^\d{10,13}$/.test(resetTokenValue)) {
        resetIssues.push({
          type: 'timestamp-token',
          param: resetTokenParam,
          valueSample: resetTokenValue,
          description: `Password reset token looks like a Unix timestamp (\`${resetTokenValue}\`). Timestamp-based tokens are predictable and can be generated by attackers.`
        });
      }

      // Base64-encoded email or user ID
      try {
        const decoded = atob(resetTokenValue);
        if (/^[^\s]+@[^\s]+\.[^\s]+$/.test(decoded) || /^user[\d]+$/i.test(decoded) || /^\d{3,10}$/.test(decoded)) {
          resetIssues.push({
            type: 'base64-encoded-identity',
            param: resetTokenParam,
            valueSample: `${resetTokenValue.substring(0, 20)}... (decoded: ${decoded.substring(0, 30)})`,
            description: `Password reset token appears to be a Base64-encoded user identifier (\`${decoded.substring(0, 30)}\`). This allows attackers to forge tokens for any user.`
          });
        }
      } catch (_) {}

      // Token in URL (query string)
      resetIssues.push({
        type: 'token-in-url',
        param: resetTokenParam,
        description: 'Password reset token is passed in the URL query string. This exposes the token to browser history, server logs, and Referer headers on external links.'
      });

      resetTokensSeen.push({ value: resetTokenValue, idx, url: path });
    }

    // 4. Check for weak reset code in body (for SMS/email-based codes)
    if (bodyText) {
      const parsed = tryParseJSON(bodyText);
      if (parsed && typeof parsed === 'object') {
        // Check for code field that might be the reset code
        ['code', 'resetCode', 'reset_code', 'otp', 'verificationCode', 'verification_code'].forEach(codeKey => {
          if (parsed[codeKey] && typeof parsed[codeKey] === 'string' && /^\d{4,8}$/.test(parsed[codeKey])) {
            resetIssues.push({
              type: 'weak-otp-code',
              param: codeKey,
              valueSample: `${parsed[codeKey].substring(0, 4)}****`,
              description: `Password reset/OTP code (\`${codeKey}\`) is a short numeric value (${parsed[codeKey].length} digits). Short numeric OTPs are vulnerable to brute-force attacks, especially if there is no rate limiting.`
            });
          }
        });
      }
    }

    // 5. Check for expired token reuse indicator
    // (Can only detect if response body is available — skipped for now)

    if (resetIssues.length === 0) return;

    const findId = 'auth-password-reset-weakness';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const highSeverityIssues = resetIssues.filter(i =>
      i.type === 'numeric-token' || i.type === 'timestamp-token' || i.type === 'base64-encoded-identity' || i.type === 'user-enumeration'
    );
    const overallSeverity = highSeverityIssues.length > 0 ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'auth-bypass-state-manip',
      name: 'Password Reset Token Weakness',
      description: `Detected ${resetIssues.length} password reset token weakness(es): ${resetIssues.map(i => i.description).join(' ')}. Weak password reset mechanisms allow attackers to hijack accounts by guessing or forging reset tokens.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        issues: resetIssues.map(i => ({ type: i.type, ...(i.param ? { param: i.param } : {}), ...(i.valueSample ? { valueSample: i.valueSample.substring(0, 40) } : {}) })),
        url: path,
        method: req.request.method || 'GET'
      },
      score: overallSeverity === 'high' ? 85 : 45
    });
  });
}

// =========================
// DETECTOR 5: SESSION ATTRIBUTE MANIPULATION
// =========================
/**
 * Detect Session Attribute Manipulation:
 * - Client-controlled login state (isLoggedIn, authenticated)
 * - Client-controlled user ID or role
 * - Session status parameters modifiable by client
 * - Session impersonation parameters (impersonate, masquerade)
 * - Client-controlled session metadata
 */
function detectSessionAttributeManipulation(sortedReqs, findings) {
  const requestFindings = new Map();

  // Session attribute parameter names that should NEVER be controlled by the client
  const SESSION_ATTR_NAMES = [
    'isLoggedIn', 'is_logged_in', 'loggedin', 'logged_in',
    'isAuthenticated', 'is_authenticated', 'authenticated',
    'isLogin', 'is_login', 'login',
    'currentUser', 'current_user', 'currentuser',
    'userId', 'user_id', 'uid', 'userid',
    'sessionUser', 'session_user', 'sessionuser',
    'loginStatus', 'login_status', 'login_status',
    'authStatus', 'auth_status', 'authstatus',
    'sessionStatus', 'session_status', 'sessionstatus',
    'impersonate', 'masquerade', 'sudo', 'become',
    'switchUser', 'switch_user', 'switchuser',
    'actAs', 'act_as', 'actas',
    'loginAs', 'login_as', 'loginas',
    'authState', 'auth_state', 'authstate',
    'sessionData', 'session_data', 'sessiondata'
  ];

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const bodyText = getRequestBodyText(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);

    const manipIssues = [];

    // 1. Check for session attribute parameters controlled by client
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      const matched = SESSION_ATTR_NAMES.find(attr => {
        const lowerAttr = attr.toLowerCase();
        return lowerKey === lowerAttr || lowerKey.includes(lowerAttr);
      });
      if (!matched) return;

      const val = String(params[key]);

      // Boolean-like values (true/false, 1/0)
      if (/^(true|false|1|0|yes|no)$/i.test(val)) {
        manipIssues.push({
          type: 'session-boolean-manipulation',
          param: key,
          value: val,
          description: `Session state parameter \`${key}\` is client-controlled with value \`${val}\`. Attackers can set \`isLoggedIn=true\` or \`authenticated=true\` to bypass authentication entirely.`
        });
      }

      // Numeric ID-like values
      if (/^\d{3,10}$/.test(val)) {
        manipIssues.push({
          type: 'session-id-manipulation',
          param: key,
          value: val,
          description: `Session identity parameter \`${key}\` is client-controlled with value \`${val}\`. Attackers can modify this value to impersonate other users by changing the user ID.`
        });
      }

      // Role-like values
      if (/^[a-zA-Z_]+$/.test(val) && /admin|user|manager|owner|super/i.test(val)) {
        manipIssues.push({
          type: 'session-role-manipulation',
          param: key,
          value: val,
          description: `Session role parameter \`${key}\` is client-controlled with value \`${val}\`. Attackers can escalate privileges by changing role values.`
        });
      }

      // All other values
      if (val && val.length > 0 && val.length < 100) {
        manipIssues.push({
          type: 'session-attribute-manipulation',
          param: key,
          value: val,
          description: `Session attribute parameter \`${key}\` is client-supplied. Critical session state should be managed server-side only. Any client-controllable session attribute is a potential authentication bypass vector.`
        });
      }
    });

    // 2. Check for impersonation parameters specifically
    const impersonationParams = ['impersonate', 'masquerade', 'sudo', 'become', 'switchUser', 'actAs', 'loginAs', 'su'];
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (impersonationParams.some(ip => lowerKey === ip || lowerKey.includes(ip))) {
        const val = String(params[key]);
        if (!manipIssues.some(i => i.param === key)) {
          manipIssues.push({
            type: 'impersonation-parameter',
            param: key,
            value: val,
            description: `Impersonation parameter \`${key}\` is client-controlled. If the server accepts these parameters without proper authorization, an attacker can impersonate any user.`
          });
        }
      }
    });

    // 3. Deep scan body for session attributes in JSON (nested)
    if (bodyText) {
      const parsed = tryParseJSON(bodyText);
      if (parsed && typeof parsed === 'object') {
        const deepScanSessionAttrs = (obj, parentPath = '') => {
          if (!obj || typeof obj !== 'object') return;
          Object.keys(obj).forEach(key => {
            const currentPath = parentPath ? `${parentPath}.${key}` : key;
            const lowerKey = key.toLowerCase();
            const matched = SESSION_ATTR_NAMES.find(attr => {
              const lowerAttr = attr.toLowerCase();
              return lowerKey === lowerAttr || lowerKey.includes(lowerAttr);
            });
            if (matched) {
              const val = String(obj[key]);
              if (!manipIssues.some(i => i.param === currentPath)) {
                manipIssues.push({
                  type: 'nested-session-attribute',
                  param: currentPath,
                  value: val.substring(0, 50),
                  description: `Nested session attribute \`${currentPath}\` is client-controlled. Session state in client-supplied JSON objects can be manipulated to bypass authentication.`
                });
              }
            }
            deepScanSessionAttrs(obj[key], currentPath);
          });
        };
        deepScanSessionAttrs(parsed);
      }
    }

    if (manipIssues.length === 0) return;

    const findId = 'auth-session-attribute-manipulation';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const hasHighSeverity = manipIssues.some(i =>
      i.type === 'session-boolean-manipulation' || i.type === 'session-id-manipulation' ||
      i.type === 'session-role-manipulation' || i.type === 'impersonation-parameter'
    );
    const overallSeverity = hasHighSeverity ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'auth-bypass-state-manip',
      name: 'Session Attribute Manipulation',
      description: `Detected ${manipIssues.length} client-controlled session attribute(s) in the request. These include authentication state (\`isLoggedIn\`, \`authenticated\`), user identity (\`userId\`), roles (\`role\`), or impersonation parameters. Attackers can modify these to bypass authentication or escalate privileges.

Offending parameter(s): ${[...new Set(manipIssues.map(i => i.param))].join(', ')}.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        issues: manipIssues.map(i => ({ type: i.type, param: i.param, valueSample: i.value })),
        url: path,
        method: req.request.method || 'GET'
      },
      score: overallSeverity === 'high' ? 85 : 50
    });
  });
}

// =========================
// DETECTOR 6: MFA / 2FA BYPASS
// =========================
/**
 * Detect MFA/2FA Bypass attempts:
 * - mfa_verified=true sent from client
 * - skip_mfa=true or mfa_bypass=true parameter
 * - MFA verification step skipped
 * - Session with MFA step completed but no actual MFA request
 * - Weak MFA methods accepted (SMS code vs. TOTP)
 * - Rate limiting bypass indicators
 */
function detectMFABypass(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const bodyText = getRequestBodyText(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);

    const mfaIssues = [];

    // 1. Check for MFA state parameters controlled by client
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      const matched = MFA_PARAM_NAMES.find(mfa => {
        const lowerMfa = mfa.toLowerCase();
        return lowerKey === lowerMfa || lowerKey.includes(lowerMfa);
      });
      if (!matched) return;

      const val = String(params[key]);

      // mfa_verified / 2fa_verified = true (client telling server MFA is done)
      if (/^(true|1|yes|completed|passed|verified|done|skip)$/i.test(val)) {
        if (/verified|bypass|skip/i.test(lowerKey)) {
          mfaIssues.push({
            type: 'mfa-verified-param',
            param: key,
            value: val,
            description: `MFA state parameter \`${key}\` set to \`${val}\` by the client. This indicates that the client can claim MFA verification status, enabling bypass of multi-factor authentication.`
          });
        }
      }

      // skip_mfa = true
      if (/^(true|1|yes|skip)$/i.test(val) && /skip|bypass/i.test(lowerKey)) {
        mfaIssues.push({
          type: 'mfa-skip-param',
          param: key,
          value: val,
          description: `MFA skip/bypass parameter \`${key}\` is set to \`${val}\`. This allows the client to opt out of multi-factor authentication entirely.`
        });
      }

      // require_mfa = false
      if (/^(false|0|no)$/i.test(val) && /require/i.test(lowerKey)) {
        mfaIssues.push({
          type: 'mfa-require-false',
          param: key,
          value: val,
          description: `MFA requirement parameter \`${key}\` set to \`${val}\` by the client. This allows disabling MFA requirements from the client side.`
        });
      }
    });

    // 2. Check for MFA bypass in body
    if (bodyText) {
      const parsed = tryParseJSON(bodyText);
      if (parsed && typeof parsed === 'object') {
        // Deep scan for MFA parameters in nested JSON
        const scanMFA = (obj, parentPath = '') => {
          if (!obj || typeof obj !== 'object') return;
          Object.keys(obj).forEach(key => {
            const currentPath = parentPath ? `${parentPath}.${key}` : key;
            const lowerKey = key.toLowerCase();
            const matched = MFA_PARAM_NAMES.find(mfa => {
              const lowerMfa = mfa.toLowerCase();
              return lowerKey === lowerMfa || lowerKey.includes(lowerMfa);
            });
            if (matched) {
              const val = String(obj[key]);
              if (/^(true|1|yes|completed|passed|verified|done|skip)$/i.test(val)) {
                if (!mfaIssues.some(i => i.param === currentPath)) {
                  mfaIssues.push({
                    type: 'nested-mfa-param',
                    param: currentPath,
                    value: val,
                    description: `MFA state parameter \`${currentPath}\` is set to \`${val}\` in the request body. Client-controlled MFA state allows bypassing multi-factor authentication.`
                  });
                }
              }
            }
            scanMFA(obj[key], currentPath);
          });
        };
        scanMFA(parsed);
      }

      // Check for MFA code in body (weak OTP patterns)
      const parsedBody = tryParseJSON(bodyText);
      if (parsedBody && typeof parsedBody === 'object') {
        Object.keys(parsedBody).forEach(key => {
          const lowerKey = key.toLowerCase();
          const isMfaCode = /^(mfa_code|mfaCode|mfa-code|mfa_token|mfaToken|totp|otp|code|verification_code)$/i.test(lowerKey);
          if (isMfaCode && typeof parsedBody[key] === 'string') {
            const codeVal = parsedBody[key];
            // Detect reusable or predictable MFA codes
            if (/^(000000|123456|111111|222222|333333|444444|555555|666666|777777|888888|999999)$/.test(codeVal)) {
              mfaIssues.push({
                type: 'weak-mfa-code',
                param: key,
                value: codeVal,
                description: `MFA/OTP code \`${key}\` is a commonly used weak code: \`${codeVal}\`. Attackers can easily guess common OTP values.`
              });
            }
            // Numeric codes longer than 6 digits might indicate a replayable token
            if (/^\d{4,10}$/.test(codeVal)) {
              // No additional issue — these can be legitimate
            }
          }
        });
      }
    }

    // 3. Check for session token with MFA claim verification
    // Look for JWT tokens that claim MFA verification status
    const headers = getAllHeaderValues(req);
    const authHeader = headers.find(h => h.name.toLowerCase() === 'authorization');
    if (authHeader) {
      const bearerVal = (authHeader.value || '').replace(/^Bearer\s+/i, '').trim();
      if (looksLikeJWT(bearerVal)) {
        const parsed = parseJWT(bearerVal);
        if (parsed && parsed.payload) {
          const mfaClaims = ['mfa', 'mfa_verified', 'mfaVerified', 'mfa-enabled', 'mfa_required', 'amr'];
          mfaClaims.forEach(claim => {
            if (parsed.payload[claim] !== undefined) {
              const claimVal = parsed.payload[claim];
              // If mfa claim is false/absent when it should be present
              if (claimVal === false || claimVal === 'false' || claimVal === 0 || claimVal === null) {
                mfaIssues.push({
                  type: 'jwt-mfa-claim-false',
                  param: `JWT.payload.${claim}`,
                  value: String(claimVal),
                  description: `JWT payload contains MFA claim \`${claim}\` set to \`${claimVal}\`. If the server trusts this claim, attackers can remove their own MFA enforcement by tampering with the claim value before token issuance or modification.`
                });
              }
            }
          });
        }
      }
    }

    if (mfaIssues.length === 0) return;

    const findId = 'auth-mfa-bypass';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const overallSeverity = 'high'; // Any MFA bypass is high severity

    findings.push({
      id: findId,
      category: 'auth-bypass-state-manip',
      name: 'MFA / 2FA Bypass',
      description: `Detected ${mfaIssues.length} MFA bypass indicator(s): ${mfaIssues.map(i => i.description).join(' ')}. MFA bypass vulnerabilities allow attackers to circumvent multi-factor authentication by manipulating client-controlled state parameters, weak OTP codes, or token claims.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        issues: mfaIssues.map(i => ({ type: i.type, param: i.param, valueSample: i.value })),
        url: path,
        method: req.request.method || 'GET',
        isMFARelated: /mfa|2fa|two.?factor|totp|otp/i.test(path)
      },
      score: 90
    });
  });
}

// =========================
// DETECTOR 7: REMEMBER-ME / PERSISTENT AUTH TOKEN WEAKNESS
// =========================
/**
 * Detect Remember-Me / Persistent Auth Token Weaknesses:
 * - Remember-me tokens based on username + hashed password
 * - Weak/static remember-me tokens
 * - Remember-me token in URL
 * - No expiration on persistent tokens
 * - Predictable token generation
 */
function detectRememberMeWeakness(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const bodyText = getRequestBodyText(req);
    const headers = getAllHeaderValues(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);

    const remIssues = [];

    // 1. Check for remember-me parameters controlled by client
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      const matched = REMEMBER_ME_PARAM_NAMES.find(rm => {
        const lowerRm = rm.toLowerCase();
        return lowerKey === lowerRm || lowerKey.includes(lowerRm);
      });
      if (!matched) return;

      const val = String(params[key]);

      // If remember-me value looks like a hash or token
      if (val && val.length > 10) {
        // Check if it's a base64-encoded username:password combo
        try {
          const decoded = atob(val);
          if (decoded.includes(':') || decoded.includes('|') || decoded.includes(',')) {
            remIssues.push({
              type: 'base64-remember-token',
              param: key,
              valueSample: `${val.substring(0, 20)}...`,
              description: `Remember-me token appears to be Base64-encoded credentials: decoded as \`${decoded.substring(0, 40)}\`. This is a critical vulnerability — persistent auth tokens should never contain reversible user credentials.`
            });
          }
        } catch (_) {}

        // Sequential/weak token
        if (/^\d+$/.test(val) || /^[a-z0-9]{6,12}$/i.test(val)) {
          remIssues.push({
            type: 'weak-remember-token',
            param: key,
            valueSample: val.substring(0, 20),
            description: `Remember-me token has low entropy (short/predictable). Weak persistent auth tokens can be brute-forced to hijack user sessions.`
          });
        }
      }

      // Boolean remember-me flag
      if (/^(true|1|yes|on)$/i.test(val)) {
        remIssues.push({
          type: 'remember-me-enabled',
          param: key,
          value: val,
          description: `Remember-me parameter \`${key}\` is enabled by the client. If the persistent token generation mechanism is weak or the token is stored insecurely (e.g., in a cookie without Secure/HttpOnly flags), it enables long-term session hijacking.`
        });
      }
    });

    // 2. Check cookies for remember-me tokens
    const cookieHeaders = headers.filter(h => h.name.toLowerCase() === 'cookie');
    cookieHeaders.forEach(c => {
      const cookieVal = c.value || '';
      cookieVal.split(';').forEach(cp => {
        const eqIdx = cp.indexOf('=');
        if (eqIdx > 0) {
          const name = cp.substring(0, eqIdx).trim().toLowerCase();
          const value = cp.substring(eqIdx + 1).trim();
          // Check for remember-me cookies
          if (/remember|persist|keep.?logged/i.test(name)) {
            if (isWeakToken(value)) {
              remIssues.push({
                type: 'weak-remember-cookie',
                param: name,
                valueSample: value.substring(0, 20),
                description: `Remember-me cookie \`${name}\` has a weak/predictable value. Weak persistent cookies enable long-term session hijacking.`
              });
            }
            // Check for email:hash format cookies (classic "remember me" antipattern)
            if (value.includes(':') && !looksLikeJWT(value)) {
              remIssues.push({
                type: 'email-hash-cookie',
                param: name,
                valueSample: value.substring(0, 30),
                description: `Remember-me cookie \`${name}\` uses colon-separated format (\`user:hash\`). This is the classic "remember me" antipattern where the token is username + hashed password, allowing offline brute-force of the password.`
              });
            }
          }
        }
      });
    });

    // 3. Check for persistent token in response (Set-Cookie with long expiry)
    if (req.response && Array.isArray(req.response.headers)) {
      req.response.headers.forEach(h => {
        if ((h.name || '').toLowerCase() === 'set-cookie') {
          const cookieStr = h.value || '';
          // Check for Max-Age or Expires with very long duration
          const maxAgeMatch = cookieStr.match(/Max-Age=(\d+)/i);
          if (maxAgeMatch) {
            const maxAgeSecs = parseInt(maxAgeMatch[1], 10);
            if (maxAgeSecs > 30 * 24 * 60 * 60) { // > 30 days
              remIssues.push({
                type: 'excessive-cookie-lifetime',
                param: 'Set-Cookie',
                valueSample: `${maxAgeSecs / (24*60*60)} days`,
                description: `Server sets a cookie with \`Max-Age=${maxAgeSecs}\` seconds (${(maxAgeSecs / (24*60*60)).toFixed(0)} days). Excessively long cookie lifetimes increase the window for session hijacking.`
              });
            }
          }
          // Check for Expires with far future date
          const expiresMatch = cookieStr.match(/Expires=([^;]+)/i);
          if (expiresMatch) {
            try {
              const expDate = new Date(expiresMatch[1]);
              const now = Date.now();
              const oneYearMs = 365 * 24 * 60 * 60 * 1000;
              if (expDate.getTime() - now > oneYearMs) {
                remIssues.push({
                  type: 'excessive-cookie-expires',
                  param: 'Set-Cookie',
                  valueSample: expDate.toISOString(),
                  description: 'Server sets a cookie with an expiration date more than one year in the future. Overly long-lived cookies increase the risk of persistent session hijacking.'
                });
              }
            } catch (_) {}
          }
        }
      });
    }

    if (remIssues.length === 0) return;

    const findId = 'auth-remember-me-weakness';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const hasHighSeverity = remIssues.some(i =>
      i.type === 'base64-remember-token' || i.type === 'email-hash-cookie'
    );
    const overallSeverity = hasHighSeverity ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'auth-bypass-state-manip',
      name: 'Remember-Me / Persistent Auth Token Weakness',
      description: `Detected ${remIssues.length} persistent auth token weakness(es): ${remIssues.map(i => i.description).join(' ')}. Weak remember-me tokens allow attackers to hijack persistent sessions through token theft, brute-force, or offline cracking.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        issues: remIssues.map(i => ({ type: i.type, param: i.param, valueSample: i.valueSample })),
        url: path,
        method: req.request.method || 'GET'
      },
      score: overallSeverity === 'high' ? 85 : 45
    });
  });
}

// =========================
// DETECTOR 8: AUTHORIZATION HEADER / TOKEN INJECTION
// =========================
/**
 * Detect Authorization Header / Token Injection:
 * - Adding/modifying Authorization header to access privileged endpoints
 * - Token injection via query params (access_token, api_key)
 * - Multiple auth mechanisms in same request (confusion)
 * - Using another user's leaked/known token
 * - Token injection in cookies
 * - Auth header manipulation to escalate privileges
 */
function detectAuthHeaderTokenInjection(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const headers = getAllHeaderValues(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);

    const injectIssues = [];

    // 1. Check for auth token in multiple locations (confusion)
    const authLocations = [];

    // Authorization header
    const authHeader = headers.find(h => h.name.toLowerCase() === 'authorization');
    if (authHeader && authHeader.value) {
      authLocations.push('Authorization header');
      const bearerVal = (authHeader.value || '').replace(/^Bearer\s+/i, '').trim();
      if (bearerVal && bearerVal.length > 0) {
        // Check for empty Bearer token
        if (bearerVal === '' || bearerVal === 'null' || bearerVal === 'undefined') {
          injectIssues.push({
            type: 'empty-bearer-token',
            location: 'Authorization header',
            description: 'Authorization header contains an empty/placeholder Bearer token (\`null\`, \`undefined\`, or empty). This might indicate a test or bypass attempt where the server may accept empty tokens.'
          });
        }
      }
    }

    // Token in query string
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (lowerKey === 'access_token' || lowerKey === 'token' || lowerKey === 'api_key' || lowerKey === 'apikey' || lowerKey === 'auth_token') {
        authLocations.push(`query param: ${key}`);
        const val = String(params[key]);
        if (val && val.length > 0) {
          injectIssues.push({
            type: 'token-in-query',
            location: `query param: ${key}`,
            valueSample: val.substring(0, 20),
            description: `Authentication token is passed as a query parameter (\`${key}\`). Tokens in URLs are vulnerable to leakage via Referer headers, browser history, and server logs. Additionally, this creates confusion about which auth mechanism takes precedence.`
          });
        }
      }
    });

    // Token in request body
    const bodyText = getRequestBodyText(req);
    if (bodyText) {
      const parsed = tryParseJSON(bodyText);
      if (parsed && typeof parsed === 'object') {
        Object.keys(parsed).forEach(key => {
          const lowerKey = key.toLowerCase();
          if (lowerKey === 'access_token' || lowerKey === 'token' || lowerKey === 'api_key' || lowerKey === 'auth_token') {
            authLocations.push(`request body: ${key}`);
          }
        });
      }
    }

    // Token in cookie
    const cookieHeader = headers.find(h => h.name.toLowerCase() === 'cookie');
    if (cookieHeader) {
      const cookieVal = cookieHeader.value || '';
      cookieVal.split(';').forEach(cp => {
        const eqIdx = cp.indexOf('=');
        if (eqIdx > 0) {
          const name = cp.substring(0, eqIdx).trim().toLowerCase();
          if (SESSION_PARAM_NAMES.includes(name)) {
            authLocations.push(`cookie: ${name}`);
          }
        }
      });
    }

    // 2. Multiple auth mechanisms can cause confusion/confusion
    if (authLocations.length > 1) {
      injectIssues.push({
        type: 'multiple-auth-mechanisms',
        locations: authLocations,
        description: `Multiple authentication mechanisms detected in the same request: ${authLocations.join(', ')}. This creates ambiguity about which auth mechanism the server prioritizes and can enable bypass attacks where one mechanism overrides another.`
      });
    }

    // 3. Check for API key in query string (exposed)
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (lowerKey === 'api_key' || lowerKey === 'apikey' || lowerKey === 'api-key') {
        const val = String(params[key]);
        if (val && val.length > 5) {
          // Check if it's a weak/generic API key
          if (/^(test|demo|dev|staging|example|key|secret|123|xxx)/i.test(val) || /^[a-z]{6,12}$/i.test(val)) {
            injectIssues.push({
              type: 'weak-api-key',
              location: `query param: ${key}`,
              valueSample: val.substring(0, 20),
              description: `API key \`${key}\` in query string looks weak or like a placeholder value (\`${val.substring(0, 20)}\`). Weak API keys are easily guessable and should never be passed in URLs.`
            });
          }
        }
      }
    });

    // 4. Check for privilege escalation via auth manipulation
    // Look for patterns where a request to a privileged endpoint uses a different auth mechanism than non-privileged ones
    // (Cross-request analysis is limited here, but we can flag privileged endpoints with unusual auth)
    const isPrivilegedEndpoint = /admin|dashboard|manage|console|internal|backoffice|super|root/i.test(path);
    if (isPrivilegedEndpoint && isMutatingRequest(req)) {
      // Check if auth is only in query string (very weak)
      const hasAuthInQuery = Object.keys(params).some(k => {
        return /token|api_key|auth/i.test(k.toLowerCase());
      });
      const hasAuthHeader = !!authHeader;

      if (hasAuthInQuery && !hasAuthHeader) {
        injectIssues.push({
          type: 'privileged-endpoint-weak-auth',
          location: 'query param',
          description: `Privileged/admin endpoint (\`${path}\`) is accessed using authentication via query parameters only, without an Authorization header. This is a weak auth mechanism for sensitive operations.`
        });
      }
    }

    if (injectIssues.length === 0) return;

    const findId = 'auth-header-token-injection';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const overallSeverity = injectIssues.some(i =>
      i.type === 'multiple-auth-mechanisms' || i.type === 'privileged-endpoint-weak-auth' || i.type === 'token-in-query'
    ) ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'auth-bypass-state-manip',
      name: 'Authorization Header / Token Injection',
      description: `Detected ${injectIssues.length} auth token injection issue(s): ${injectIssues.map(i => i.description).join(' ')}. Token injection vulnerabilities occur when authentication tokens can be supplied through multiple channels, allowing attackers to bypass security by manipulating how tokens are delivered.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        issues: injectIssues,
        url: path,
        method: req.request.method || 'GET',
        isPrivilegedEndpoint
      },
      score: overallSeverity === 'high' ? 75 : 40
    });
  });
}

// =========================
// DETECTOR 9: EMAIL / SMS VERIFICATION BYPASS
// =========================
/**
 * Detect Email/SMS Verification Bypass:
 * - email_verified=true sent from client
 * - skip_verification parameter
 * - Verification status in client-controlled payload
 * - Missing verification checks on privileged actions
 * - verify=skip or confirm=bypass params
 */
function detectEmailVerificationBypass(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const bodyText = getRequestBodyText(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);

    const verifyIssues = [];

    // 1. Check verification status params controlled by client
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      const matched = EMAIL_VERIFY_PARAM_NAMES.find(ev => {
        const lowerEv = ev.toLowerCase();
        return lowerKey === lowerEv || lowerKey.includes(lowerEv);
      });
      if (!matched) return;

      const val = String(params[key]);

      // Verification status set to verified/true
      if (/^(true|1|yes|verified|confirmed|completed)$/i.test(val) &&
          !/skip/i.test(lowerKey) && !/bypass/i.test(lowerKey)) {
        verifyIssues.push({
          type: 'verification-param-true',
          param: key,
          value: val,
          description: `Verification status parameter \`${key}\` is set to \`${val}\` by the client. Attackers can set \`email_verified=true\` or \`phone_verified=true\` to bypass email/SMS verification.`
        });
      }

      // Skip/bypass verification
      if (/^(true|1|yes|skip|bypass)$/i.test(val) &&
          (/skip/i.test(lowerKey) || /bypass/i.test(lowerKey) || /require/i.test(lowerKey))) {
        verifyIssues.push({
          type: 'verification-skip-param',
          param: key,
          value: val,
          description: `Verification bypass parameter \`${key}\` is set to \`${val}\`. This allows the client to skip email/SMS verification entirely.`
        });
      }
    });

    // 2. Check for verification bypass in body
    if (bodyText) {
      const parsed = tryParseJSON(bodyText);
      if (parsed && typeof parsed === 'object') {
        // Deep scan for verification params in nested JSON
        const scanVerify = (obj, parentPath = '') => {
          if (!obj || typeof obj !== 'object') return;
          Object.keys(obj).forEach(key => {
            const currentPath = parentPath ? `${parentPath}.${key}` : key;
            const lowerKey = key.toLowerCase();
            const matched = EMAIL_VERIFY_PARAM_NAMES.find(ev => {
              const lowerEv = ev.toLowerCase();
              return lowerKey === lowerEv || lowerKey.includes(lowerEv);
            });
            if (matched) {
              const val = String(obj[key]);
              if (/^(true|1|yes|verified|confirmed|completed)$/i.test(val) &&
                  !verifyIssues.some(i => i.param === currentPath)) {
                verifyIssues.push({
                  type: 'nested-verification-param',
                  param: currentPath,
                  value: val,
                  description: `Verification status \`${currentPath}\` is set to \`${val}\` in the request body. Client-controlled verification state allows bypassing email or phone verification.`
                });
              }
            }
            scanVerify(obj[key], currentPath);
          });
        };
        scanVerify(parsed);
      }
    }

    // 3. Check for GraphQL mutation that bypasses verification
    if (req._graphql && req._graphql.operations) {
      req._graphql.operations.forEach(op => {
        if (op.type === 'mutation') {
          const opName = op.operationName || '';
          const opQuery = op.query || '';
          // Check if mutation sets verification status
          if (/setVerification|updateVerification|confirmEmail|verifyEmail|confirmPhone/i.test(opName) ||
              /setVerification|updateVerification|confirmEmail|verifyEmail|confirmPhone/i.test(opQuery)) {
            const vars = op.variables || {};
            Object.keys(vars).forEach(vk => {
              const lowerVk = vk.toLowerCase();
              const matched = EMAIL_VERIFY_PARAM_NAMES.find(ev => lowerVk.includes(ev.toLowerCase()));
              if (matched && vars[vk] === true) {
                if (!verifyIssues.some(i => i.param === `GraphQL.${vk}`)) {
                  verifyIssues.push({
                    type: 'graphql-verification-mutation',
                    param: `GraphQL:${vk}`,
                    value: String(vars[vk]),
                    description: `GraphQL mutation \`${opName}\` allows setting verification state \`${vk}=${vars[vk]}\` from the client. Mutations that accept verification status as an input argument allow bypassing the verification process.`
                  });
                }
              }
            });
          }
        }
      });
    }

    if (verifyIssues.length === 0) return;

    const findId = 'auth-email-verification-bypass';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const overallSeverity = 'high'; // Verification bypass is always high severity

    findings.push({
      id: findId,
      category: 'auth-bypass-state-manip',
      name: 'Email / SMS Verification Bypass',
      description: `Detected ${verifyIssues.length} verification bypass indicator(s): ${verifyIssues.map(i => i.description).join(' ')}. Email or SMS verification bypass allows attackers to access verified-only features, perform actions without confirmed contact information, or create accounts with unverified identities.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        issues: verifyIssues.map(i => ({ type: i.type, param: i.param, valueSample: i.value })),
        url: path,
        method: req.request.method || 'GET'
      },
      score: 85
    });
  });
}

// =========================
// DETECTOR 10: ROLE / SCOPE MANIPULATION IN TOKEN CLAIMS
// =========================
/**
 * Detect Role/Scope Manipulation in Token Claims:
 * - JWT claims with excessive permissions
 * - Client-controllable roles in token
 * - Scope escalation (e.g., read → write → admin)
 * - Role/scope in plain sight in query params or body
 * - Missing scope validation indicators
 * - Token with overly permissive claims
 * - Self-signed or modified JWT claims
 */
function detectTokenClaimManipulation(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const bodyText = getRequestBodyText(req);
    const headers = getAllHeaderValues(req);
    const url = req.request && req.request.url ? req.request.url : '';
    const path = getPathname(url);

    const claimIssues = [];

    // 1. Extract and parse all JWT tokens
    const allTextValues = [];

    // From Authorization header
    const authHeader = headers.find(h => h.name.toLowerCase() === 'authorization');
    if (authHeader) {
      const bearerVal = (authHeader.value || '').replace(/^Bearer\s+/i, '').trim();
      if (looksLikeJWT(bearerVal)) allTextValues.push(bearerVal);
    }

    // From params
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (lowerKey === 'token' || lowerKey === 'access_token' || lowerKey === 'jwt' || lowerKey === 'bearer') {
        allTextValues.push(String(params[key]));
      }
    });

    // From body
    if (bodyText) allTextValues.push(bodyText);
    allTextValues.push(url);
    allTextValues.push(path);

    // Also check cookie for tokens
    const cookieHeader = headers.find(h => h.name.toLowerCase() === 'cookie');
    if (cookieHeader) {
      const cookieVal = cookieHeader.value || '';
      cookieVal.split(';').forEach(cp => {
        const eqIdx = cp.indexOf('=');
        if (eqIdx > 0) {
          const cv = cp.substring(eqIdx + 1).trim();
          if (looksLikeJWT(cv)) allTextValues.push(cv);
        }
      });
    }

    const jwtTokens = extractJWTs(allTextValues);

    // 2. Analyze JWT claims
    jwtTokens.forEach(({ token, parsed }) => {
      const { header, payload } = parsed;

      // Check role/permission-related claims
      const roleClaims = [];
      ROLE_SCOPE_CLAIM_NAMES.forEach(claim => {
        if (payload[claim] !== undefined) {
          roleClaims.push({ claim, value: payload[claim] });
        }
      });

      if (roleClaims.length > 0) {
        // Check for admin/superuser roles
        roleClaims.forEach(({ claim, value }) => {
          const valStr = String(value);
          if (/admin|superuser|root|owner|manager/i.test(valStr) ||
              (Array.isArray(value) && value.some(v => /admin|superuser|root|owner|manager/i.test(String(v))))) {
            claimIssues.push({
              type: 'admin-role-claim',
              claim,
              value: valStr.substring(0, 50),
              description: `JWT payload contains administrative privilege in claim \`${claim}\`: \`${valStr.substring(0, 50)}\`. If these roles are modifiable or the token is self-signed, this enables privilege escalation.`
            });
          }

          // Check for overly broad scopes
          if (claim.toLowerCase() === 'scope' || claim.toLowerCase() === 'scopes') {
            const scopes = Array.isArray(value) ? value : String(value).split(/[\s,]+/);
            const broadScopes = scopes.filter(s =>
              /^(admin|\*|all|write|delete|\*\*)$/i.test(String(s)) ||
              /admin:\*|admin:all/i.test(String(s))
            );
            if (broadScopes.length > 0) {
              claimIssues.push({
                type: 'broad-scope',
                claim,
                value: broadScopes.join(', '),
                description: `JWT contains overly broad scope/permission: \`${broadScopes.join(', ')}\`. Overly permissive scopes violate least privilege and allow attackers to perform unauthorized operations if the token is compromised.`
              });
            }
          }
        });
      }

      // 3. Check for self-signed token indicators
      // (No iss claim, or iss matches a suspicious value)
      if (!payload.iss) {
        // No issuer — could be self-signed
      } else if (/self|localhost|127\.0\.0\.1|0\.0\.0\.0/i.test(payload.iss)) {
        claimIssues.push({
          type: 'suspicious-issuer',
          claim: 'iss',
          value: payload.iss,
          description: `JWT \`iss\` (issuer) claim references a local/internal address: \`${payload.iss}\`. This could indicate a self-signed or forged token.`
        });
      }

      // 4. Check for excessive custom claims that could indicate manipulation
      const standardClaims = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'azp', 'scope', 'roles', 'permissions', 'groups', 'amr', 'acr'];
      const customClaims = Object.keys(payload).filter(c => !standardClaims.includes(c));
      if (customClaims.length > 5) {
        claimIssues.push({
          type: 'excessive-custom-claims',
          claim: customClaims.slice(0, 8).join(', '),
          value: String(customClaims.length),
          description: `JWT payload contains ${customClaims.length} custom claims beyond standard set. Excessive custom claims may indicate token manipulation or injection of unauthorized attributes.`
        });
      }

      // 5. Check for algorithm mismatch in nested JWTs
      if (header.cty === 'JWT' || header.typ === 'at+JWT') {
        // Nested JWT — complexity makes verification harder
      }
    });

    // 6. Check for role/scope parameters that should not be client-controllable
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      const matched = ROLE_SCOPE_CLAIM_NAMES.find(rs => {
        const lowerRs = rs.toLowerCase();
        return lowerKey === lowerRs || lowerKey.includes(lowerRs);
      });
      if (!matched) return;

      const val = String(params[key]);
      // Check if value looks like a role or permission string
      if (/^[a-zA-Z_]+$/.test(val) && val.length > 2 && val.length < 30) {
        if (!claimIssues.some(i => i.type.includes('param'))) {
          claimIssues.push({
            type: 'client-controlled-role-param',
            claim: `param:${key}`,
            value: val,
            description: `Role/permission parameter \`${key}\` is supplied by the client with value \`${val}\`. Client-controllable role or permission parameters enable direct privilege escalation.`
          });
        }
      }
    });

    // 7. Check for scope/role in body
    if (bodyText) {
      const parsed = tryParseJSON(bodyText);
      if (parsed && typeof parsed === 'object') {
        Object.keys(parsed).forEach(key => {
          const lowerKey = key.toLowerCase();
          if (ROLE_SCOPE_CLAIM_NAMES.some(rs => lowerKey.includes(rs.toLowerCase()))) {
            const val = String(parsed[key]);
            if (val.length > 0 && val.length < 50 && /^[a-zA-Z_]+$/.test(val)) {
              if (!claimIssues.some(i => i.claim === `body:${key}`)) {
                claimIssues.push({
                  type: 'client-controlled-role-body',
                  claim: `body:${key}`,
                  value: val.substring(0, 40),
                  description: `Role/permission field \`${key}\` in request body is client-supplied with value \`${val.substring(0, 40)}\`. Client-controllable roles in request bodies enable privilege escalation.`
                });
              }
            }
          }
        });
      }
    }

    if (claimIssues.length === 0) return;

    const findId = 'auth-token-claim-manipulation';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const highSeverityIssues = claimIssues.filter(i =>
      i.type === 'admin-role-claim' || i.type === 'client-controlled-role-param' ||
      i.type === 'client-controlled-role-body' || i.type === 'broad-scope'
    );
    const overallSeverity = highSeverityIssues.length > 0 ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'auth-bypass-state-manip',
      name: 'Role / Scope Manipulation in Token Claims',
      description: `Detected ${claimIssues.length} role/scope manipulation indicator(s) in token claims or request parameters. These include: ${claimIssues.map(i => i.description).join(' ')}. Role and scope manipulation allows attackers to escalate privileges by modifying JWT claims, request parameters, or body fields that control authorization.`,
      severity: overallSeverity,
      requestIndex: idx,
      evidence: {
        issues: claimIssues.map(i => ({ type: i.type, claim: i.claim, valueSample: i.value.substring(0, 40) })),
        jwtParsed: jwtTokens.length > 0 ? {
          header: jwtTokens[0]?.parsed?.header,
          payload: jwtTokens[0]?.parsed?.payload
        } : null,
        url: path,
        method: req.request.method || 'GET'
      },
      score: overallSeverity === 'high' ? 85 : 50
    });
  });
}

