/**
 * File Parser Vulnerabilities Detection Engine
 *
 * Analyzes workflows and individual requests for common file parsing
 * and file-handling vulnerabilities:
 *   - Path Traversal / Directory Traversal
 *   - Local/Remote File Inclusion (LFI/RFI)
 *   - SSRF via File Protocol & Internal IPs
 *   - File Upload Vulnerabilities (malicious extensions, double ext, etc.)
 *   - XXE (XML External Entity) Injection
 *   - Zip Slip / Archive Traversal
 *   - Log Poisoning
 *   - Server-Side File Operations Abuse
 *   - File Permission / Access Control Exposure
 */

// =========================
// PUBLIC INTERFACE
// =========================

/**
 * Run all file parser vulnerability detectors against a workflow.
 * Returns an array of flaw findings compatible with the existing flaws engine.
 */
export function detectFileParserVulnerabilities(workflow) {
  if (!workflow || !Array.isArray(workflow.requests) || workflow.requests.length === 0) {
    return [];
  }

  const sortedReqs = [...workflow.requests].sort((a, b) => {
    return new Date(a.startedDateTime).getTime() - new Date(b.startedDateTime).getTime();
  });

  const findings = [];

  // Run each detector
  detectPathTraversal(sortedReqs, findings);
  detectFileInclusion(sortedReqs, findings);
  detectSSRFViaFileProtocol(sortedReqs, findings);
  detectFileUploadVulnerabilities(sortedReqs, findings);
  detectXXEInjection(sortedReqs, findings);
  detectZipSlip(sortedReqs, findings);
  detectLogPoisoning(sortedReqs, findings);
  detectServerSideFileOps(sortedReqs, findings);
  detectFilePermissionExposure(sortedReqs, findings);

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

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Known file parameter names commonly vulnerable to path traversal / inclusion
const FILE_PARAM_NAMES = [
  'file', 'files', 'filename', 'file_name', 'filepath', 'file_path',
  'path', 'dir', 'directory', 'dirpath', 'dir_path',
  'template', 'page', 'load', 'view', 'include', 'require',
  'document', 'document_path', 'attachment', 'upload',
  'source', 'src', 'href', 'icon', 'avatar', 'photo',
  'image', 'img', 'picture', 'pdf', 'doc', 'download',
  'backup', 'restore', 'import', 'export', 'config',
  'log', 'logfile', 'log_file', 'error_log', 'access_log',
  'theme', 'plugin', 'module', 'component', 'resource',
  'script', 'style', 'stylesheet', 'language', 'locale',
  'lang', 'translation', 'readfile', 'showfile', 'openfile'
];

// Sensitive system file paths
const SENSITIVE_FILE_PATHS = [
  // Linux/Unix
  '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/hostname',
  '/etc/ssh/sshd_config', '/etc/ssh/ssh_config',
  '/etc/apache2/apache2.conf', '/etc/httpd/httpd.conf',
  '/etc/nginx/nginx.conf', '/etc/my.cnf', '/etc/mysql/my.cnf',
  '/etc/php.ini', '/etc/php5/apache2/php.ini',
  '/etc/php7/apache2/php.ini', '/etc/php8/apache2/php.ini',
  '/proc/self/environ', '/proc/self/fd/0', '/proc/self/cmdline',
  '/proc/1/environ', '/proc/1/cmdline',
  '/root/.bash_history', '/root/.ssh/id_rsa',
  '/home/*/.bash_history', '/home/*/.ssh/id_rsa',
  '/var/log/apache2/access.log', '/var/log/apache2/error.log',
  '/var/log/nginx/access.log', '/var/log/nginx/error.log',
  '/var/log/messages', '/var/log/syslog', '/var/log/auth.log',
  '/var/log/httpd/access_log', '/var/log/httpd/error_log',
  '/etc/crontab', '/etc/issue', '/etc/issue.net',
  '/.dockerenv', '/run/secrets/*',
  // Windows
  'C:\\\\boot.ini', 'C:\\\\windows\\\\system32\\\\config\\\\SAM',
  'C:\\\\windows\\\\repair\\\\SAM', 'C:\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts',
  'C:\\\\windows\\\\system32\\\\inetsrv\\\\config\\\\applicationHost.config',
  'C:\\\\inetpub\\\\wwwroot\\\\web.config',
  // App configs
  '.env', '.env.local', '.env.production', '.env.development',
  'config.php', 'config.json', 'config.yml', 'config.yaml',
  'configuration.php', 'database.yml', 'wp-config.php',
  'composer.json', 'package.json', 'Dockerfile',
  'docker-compose.yml', 'docker-compose.yaml',
  '.git/config', '.git/HEAD', '.svn/entries',
  'adminer.php', 'phpinfo.php'
];

// Known dangerous file extensions for uploads
const DANGEROUS_UPLOAD_EXTENSIONS = {
  'php': 'PHP script',
  'php2': 'PHP script (alt)',
  'php3': 'PHP script (alt)',
  'php4': 'PHP script (alt)',
  'php5': 'PHP script (alt)',
  'phtml': 'PHP script (alt)',
  'pht': 'PHP script (alt)',
  'phtm': 'PHP script (alt)',
  'pgif': 'PHP script (alt)',
  'shtml': 'Server-parsed HTML',
  'jsp': 'Java Server Page',
  'jspx': 'Java Server Page (XML)',
  'jspf': 'Java Server Page fragment',
  'war': 'Java Web Archive',
  'asp': 'Active Server Page',
  'aspx': 'ASP.NET page',
  'ashx': 'ASP.NET handler',
  'asmx': 'ASP.NET web service',
  'svc': 'WCF service',
  'exe': 'Windows executable',
  'dll': 'Dynamic Link Library',
  'com': 'MS-DOS executable',
  'bat': 'Batch file',
  'cmd': 'Command script',
  'sh': 'Shell script',
  'bash': 'Bash script',
  'pl': 'Perl script',
  'py': 'Python script',
  'rb': 'Ruby script',
  'js': 'JavaScript (if executed server-side)',
  'vbs': 'VBScript',
  'ps1': 'PowerShell script',
  'cgi': 'CGI script',
  'htaccess': 'Apache config override',
  'htpasswd': 'Apache password file'
};

// PHP stream wrapper patterns for LFI
const PHP_WRAPPER_PATTERNS = [
  /php:\/\/filter/i, /php:\/\/input/i, /php:\/\/output/i,
  /php:\/\/memory/i, /php:\/\/temp/i, /php:\/\/fd/i,
  /expect:\/\//i, /zip:\/\//i, /phar:\/\//i,
  /glob:\/\//i, /data:\/\//i, /ogg:\/\//i,
  /compress\.zlib:\/\//i, /compress\.bzip2:\/\//i,
  /ssh2:\/\//i, /rar:\/\//i
];

// XXE patterns
const XXE_PATTERNS = [
  /<!DOCTYPE\s+\w+\s+(SYSTEM|PUBLIC)\s+["']/i,
  /<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)\s+["']/i,
  /<!ENTITY\s+\w+\s+SYSTEM\s+["']file:\/\//i,
  /<!ENTITY\s+\w+\s+SYSTEM\s+["']http/i,
  /<!ENTITY\s+\w+\s+SYSTEM\s+["']php:\/\//i,
  /<!ENTITY\s+\w+\s+SYSTEM\s+["']expect:\/\//i,
  /xinclude\s+parse=["']xml["']/i,
  /<!NOTATION/i
];

// Log poisoning payload patterns
const LOG_POISONING_PATTERNS = [
  /<\?php\s+/i, /<\?=\s*/i,
  /system\(['"]/i, /exec\(['"]/i,
  /shell_exec\(/i, /passthru\(/i,
  /eval\(/i, /assert\(/i,
  /file_put_contents\(/i, /file_get_contents\(/i,
  /popen\(/i, /proc_open\(/i,
  /`[^`]*`/, // backtick execution
  /base64_decode\(/i,
  /chmod\(/i, /chown\(/i,
  /curl_exec\(/i
];

// Internal/private IP patterns for SSRF
const INTERNAL_IP_PATTERNS = [
  /^https?:\/\/127\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
  /^https?:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
  /^https?:\/\/172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}/i,
  /^https?:\/\/192\.168\.\d{1,3}\.\d{1,3}/i,
  /^https?:\/\/0\.0\.0\.0/i,
  /^https?:\/\/localhost/i,
  /^https?:\/\/\[::1\]/i,
  /^https?:\/\/169\.254\.\d{1,3}\.\d{1,3}/i,
  /^https?:\/\/[0-9a-f]{32}\./i  // DNS rebinding short
];

// Cloud metadata endpoints
const CLOUD_METADATA_ENDPOINTS = [
  '169.254.169.254', // AWS/GCP/Azure metadata
  'metadata.google.internal', // GCP
  '100.100.100.200', // Alibaba Cloud
  'metadata.tencentyun.com' // Tencent Cloud
];

// Archive-related param names
const ARCHIVE_PARAM_NAMES = [
  'zip', 'archive', 'tar', 'gz', 'bz2', 'rar', '7z',
  'extract', 'unzip', 'decompress', 'expand',
  'zipfile', 'archivefile', 'compressed'
];

// =========================
// DETECTOR 1: PATH TRAVERSAL
// =========================
/**
 * Detect Path Traversal / Directory Traversal:
 * - ../ and ..\\ patterns in file parameters
 * - URL-encoded traversal (%2e%2e%2f, %252e%252e%252f)
 * - Absolute path injection (/etc/passwd, C:\\boot.ini)
 * - Unicode/Normalized traversal variants
 * - Double-encoded traversal
 */
function detectPathTraversal(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const pathParams = {};
    const traversalPatterns = [];

    // Check file-related parameters for traversal patterns
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      const isFileParam = FILE_PARAM_NAMES.some(fp => lowerKey.includes(fp) || lowerKey === fp);
      if (!isFileParam) return;

      const val = String(params[key]);
      if (!val || val.length < 3) return;

      // 1. Standard Unix path traversal
      if (/\.\.\//.test(val) || /\.\.\\/.test(val)) {
        pathParams[key] = val;
        traversalPatterns.push({ type: 'standard', key, value: val });
      }

      // 2. URL-encoded traversal (%2e%2e%2f, %2E%2E%2F)
      if (/%2e%2e%2f/i.test(val) || /%2E%2E%5C/i.test(val) ||
          /%252e%252e%252f/i.test(val) || /%c0%ae%c0%ae%c0%af/i.test(val)) {
        traversalPatterns.push({ type: 'url-encoded', key, value: val });
        if (!pathParams[key]) pathParams[key] = val;
      }

      // 3. Absolute path injection
      if (/^\/etc\//.test(val) || /^\/var\//.test(val) ||
          /^\/proc\//.test(val) || /^\/root\//.test(val) ||
          /^\/home\//.test(val) || /^\/tmp\//.test(val) ||
          /^\/usr\//.test(val) || /^\/opt\//.test(val) ||
          /^C:\\/i.test(val) || /^C:\//i.test(val)) {
        traversalPatterns.push({ type: 'absolute-path', key, value: val });
        if (!pathParams[key]) pathParams[key] = val;
      }

      // 4. Null byte injection (%00)
      if (/%00/.test(val) || val.includes('\x00')) {
        traversalPatterns.push({ type: 'null-byte', key, value: val });
        if (!pathParams[key]) pathParams[key] = val;
      }
    });

    if (traversalPatterns.length === 0) return;

    // Group by type and build findings
    const types = [...new Set(traversalPatterns.map(t => t.type))];
    const paramsList = Object.keys(pathParams).join(', ');

    const typesDescription = types.map(t => {
      switch (t) {
        case 'standard': return 'standard directory traversal (`../`, `..\\\\`)';
        case 'url-encoded': return 'URL-encoded traversal (`%2e%2e%2f`, double-encoded)';
        case 'absolute-path': return 'absolute path injection (`/etc/`, `C:\\\\`)';
        case 'null-byte': return 'null byte injection (`%00`)';
        default: return t;
      }
    }).join(', ');

    const isHigh = types.includes('standard') || types.includes('null-byte');
    const severity = isHigh ? 'high' : 'medium';

    const findId = 'file-parser-path-traversal';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    findings.push({
      id: findId,
      category: 'file-parser-vulns',
      name: 'Path Traversal / Directory Traversal',
      description: `Path traversal patterns detected in ${traversalPatterns.length} file parameter(s) (${paramsList}): ${typesDescription}. Path traversal allows attackers to read arbitrary files on the server, access configuration data, source code, or system files.`,
      severity,
      requestIndex: idx,
      evidence: {
        parameters: traversalPatterns.map(t => ({ key: t.key, type: t.type, sample: t.value.substring(0, 100) })),
        url: getPathname(req.request.url),
        method: req.request.method || 'GET'
      },
      score: isHigh ? 80 : 50
    });
  });
}

// =========================
// DETECTOR 2: FILE INCLUSION (LFI/RFI)
// =========================
/**
 * Detect Local/Remote File Inclusion:
 * - PHP wrapper usage (php://filter, expect://, zip://, phar://)
 * - Remote URL inclusion in file parameters
 * - Null byte termination for older PHP versions
 * - Data URI scheme injection
 */
function detectFileInclusion(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const bodyText = getRequestBodyText(req);
    const allTextValues = [];

    // Collect file-related parameter values + body + URL segments
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      const isFileParam = FILE_PARAM_NAMES.some(fp => lowerKey.includes(fp) || lowerKey === fp);
      if (isFileParam) {
        allTextValues.push(String(params[key]));
      }
    });

    if (bodyText) allTextValues.push(bodyText);
    allTextValues.push(req.request.url || '');
    allTextValues.push(getPathname(req.request.url || ''));

    // 1. PHP wrapper detection
    const wrappersFound = [];
    const rfiUrls = [];

    allTextValues.forEach(txt => {
      // PHP stream wrappers
      for (const pattern of PHP_WRAPPER_PATTERNS) {
        if (pattern.test(txt)) {
          const match = txt.match(pattern);
          if (match) {
            wrappersFound.push(match[0]);
          }
        }
      }

      // Remote URL inclusion (http/ftp in file params)
      if (/^https?:\/\//i.test(txt) || /^ftp:\/\//i.test(txt)) {
        // Only flag if the value appears to be in a file parameter context
        Object.keys(params).forEach(key => {
          const lowerKey = key.toLowerCase();
          const isFileParam = FILE_PARAM_NAMES.some(fp => lowerKey.includes(fp) || lowerKey === fp);
          if (isFileParam && String(params[key]) === txt) {
            rfiUrls.push({ key, url: txt });
          }
        });
      }
    });

    if (wrappersFound.length > 0) {
      const findId = 'file-parser-php-wrapper';
      if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
      if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
      requestFindings.get(idx).add(findId);

      findings.push({
        id: findId,
        category: 'file-parser-vulns',
        name: 'PHP Stream Wrapper (LFI)',
        description: `PHP stream wrapper(s) detected: ${wrappersFound.join(', ')}. PHP wrappers allow attackers to read source code (php://filter), execute commands (expect://), trigger deserialization (phar://), or include remote resources, bypassing allowlist filters.`,
        severity: 'high',
        requestIndex: idx,
        evidence: {
          wrappers: wrappersFound,
          url: getPathname(req.request.url || ''),
          method: req.request.method || 'GET'
        },
        score: 90
      });
    }

    if (rfiUrls.length > 0) {
      const findId = 'file-parser-rfi';
      if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
      if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
      requestFindings.get(idx).add(findId);

      findings.push({
        id: findId,
        category: 'file-parser-vulns',
        name: 'Remote File Inclusion (RFI)',
        description: `Remote URL found in file parameter(s): ${rfiUrls.map(r => `\`${r.key}\``).join(', ')}. Remote File Inclusion allows attackers to load and execute arbitrary remote code by including external scripts.`,
        severity: 'high',
        requestIndex: idx,
        evidence: {
          parameters: rfiUrls.map(r => ({ key: r.key, url: r.url.substring(0, 120) })),
          url: getPathname(req.request.url || ''),
          method: req.request.method || 'GET'
        },
        score: 85
      });
    }
  });
}

// =========================
// DETECTOR 3: SSRF VIA FILE PROTOCOL
// =========================
/**
 * Detect SSRF via file protocol and internal network:
 * - file:// protocol usage in URL parameters
 * - Internal IP targets (127.0.0.1, 10.x.x.x, 172.16-31.x.x, 192.168.x.x)
 * - Cloud metadata service endpoints
 * - DNS rebinding short patterns
 */
function detectSSRFViaFileProtocol(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const bodyText = getRequestBodyText(req);
    const reqUrl = req.request && req.request.url ? req.request.url : '';
    const allValues = [];

    // Collect all parameter values, body, and URL
    Object.keys(params).forEach(k => allValues.push(String(params[k])));
    if (bodyText) allValues.push(bodyText);
    allValues.push(reqUrl);

    // Check for file:// protocol
    const fileProtocolInstances = [];

    // Check for internal IP targets in URL-containing parameters
    const internalTargets = [];

    // Check for cloud metadata endpoints
    const cloudMetadataTargets = [];

    allValues.forEach(txt => {
      // file:// protocol
      if (/^file:\/\//i.test(txt.trim())) {
        fileProtocolInstances.push(txt.trim().substring(0, 120));
      }
      if (/["']file:\/\/\//.test(txt)) {
        const match = txt.match(/["'](file:\/\/\/[^"']*)["']/);
        if (match) fileProtocolInstances.push(match[1].substring(0, 120));
      }

      // Internal IP patterns (URLs pointing to private networks)
      for (const ipPattern of INTERNAL_IP_PATTERNS) {
        if (ipPattern.test(txt.trim())) {
          internalTargets.push(txt.trim().substring(0, 120));
          break;
        }
      }

      // Cloud metadata endpoints
      for (const endpoint of CLOUD_METADATA_ENDPOINTS) {
        if (txt.includes(endpoint)) {
          cloudMetadataTargets.push(endpoint);
        }
      }
    });

    if (fileProtocolInstances.length > 0) {
      const findId = 'file-parser-ssrf-file-protocol';
      if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
      if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
      requestFindings.get(idx).add(findId);

      findings.push({
        id: findId,
        category: 'file-parser-vulns',
        name: 'SSRF via file:// Protocol',
        description: `Server-side request forgery via \`file://\` protocol detected. Using \`file://\` in URL parameters can trick the server into reading local files and exposing sensitive system information.`,
        severity: 'high',
        requestIndex: idx,
        evidence: {
          instances: fileProtocolInstances,
          url: getPathname(reqUrl),
          method: req.request && req.request.method
        },
        score: 85
      });
    }

    if (internalTargets.length > 0) {
      const findId = 'file-parser-ssrf-internal-ip';
      if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
      if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
      requestFindings.get(idx).add(findId);

      findings.push({
        id: findId,
        category: 'file-parser-vulns',
        name: 'SSRF Targeting Internal Network',
        description: `Request parameters contain URLs pointing to private/internal IP ranges (${internalTargets.length} instance(s)). SSRF to internal networks can access internal services, cloud metadata, and pivot into the internal network.`,
        severity: 'high',
        requestIndex: idx,
        evidence: {
          targets: internalTargets,
          url: getPathname(reqUrl),
          method: req.request && req.request.method
        },
        score: 80
      });
    }

    if (cloudMetadataTargets.length > 0) {
      const findId = 'file-parser-ssrf-cloud-metadata';
      if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
      if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
      requestFindings.get(idx).add(findId);

      findings.push({
        id: findId,
        category: 'file-parser-vulns',
        name: 'SSRF Targeting Cloud Metadata Service',
        description: `Request targets cloud metadata endpoint(s): ${cloudMetadataTargets.join(', ')}. Cloud metadata services (e.g., 169.254.169.254) expose IAM credentials, instance metadata, and configuration secrets.`,
        severity: 'high',
        requestIndex: idx,
        evidence: {
          endpoints: cloudMetadataTargets,
          url: getPathname(reqUrl)
        },
        score: 95
      });
    }
  });
}

// =========================
// DETECTOR 4: FILE UPLOAD VULNERABILITIES
// =========================
/**
 * Detect File Upload Vulnerabilities:
 * - Dangerous file extensions (.php, .jsp, .war, .exe, .sh, etc.)
 * - Double extensions (file.php.jpg, file.php%00.jpg)
 * - Missing Content-Type for uploads
 * - Oversized payloads (>10MB)
 * - MIME type mismatch (Content-Type vs actual extension)
 * - Null byte in filename
 */
function detectFileUploadVulnerabilities(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    if (!isMutatingRequest(req)) return;

    const params = getAllParams(req);
    const bodyText = getRequestBodyText(req);
    const headers = (req.request && req.request.headers) || [];
    const contentType = headers.find(h => (h.name || '').toLowerCase() === 'content-type');
    const contentTypeVal = contentType ? (contentType.value || '') : '';

    // Check if this looks like a file upload request
    const isUploadEndpoint = /upload|avatar|photo|image|file|attach|import|document|media|resume|cv/.test(getPathname(req.request.url || ''));
    const hasFileContent = /multipart\/form-data/.test(contentTypeVal) || contentTypeVal.includes('application/octet-stream');
    const isPotentialUpload = isUploadEndpoint || hasFileContent;

    if (!isPotentialUpload && !isUploadEndpoint) return;

    const fileIssues = [];

    // 1. Check for dangerous extensions in any parameter values
    Object.keys(params).forEach(key => {
      const val = String(params[key]);
      const lowerKey = key.toLowerCase();

      // Check if key looks like a filename or extension field
      if (!/filename?|extension?|ext|type|mime|content_type/i.test(lowerKey) && !key.endsWith('[]')) return;

      // Check dangerous extensions
      const extMatch = val.match(/\.(\w+)$/);
      if (extMatch) {
        const ext = extMatch[1].toLowerCase();
        if (DANGEROUS_UPLOAD_EXTENSIONS[ext]) {
          fileIssues.push({
            type: 'dangerous-extension',
            param: key,
            extension: ext,
            description: DANGEROUS_UPLOAD_EXTENSIONS[ext]
          });
        }
      }

      // Check for double extensions (e.g., file.php.jpg, file.php.png)
      const doubleExtMatch = val.match(/\.(\w+)\.(\w+)$/);
      if (doubleExtMatch) {
        const innerExt = doubleExtMatch[1].toLowerCase();
        if (DANGEROUS_UPLOAD_EXTENSIONS[innerExt]) {
          fileIssues.push({
            type: 'double-extension',
            param: key,
            extension: innerExt,
            description: `Double extension bypass attempt: .${innerExt}.${doubleExtMatch[2]}`
          });
        }
      }

      // Check for null byte in filename
      if (val.includes('%00') || val.includes('\x00')) {
        fileIssues.push({
          type: 'null-byte-filename',
          param: key,
          description: 'Null byte in filename (potential extension truncation)'
        });
      }
    });

    // 2. Check body for embedded dangerous extension patterns
    if (bodyText) {
      // Check filename fields in multipart-like text
      const filenameMatches = bodyText.match(/filename\s*=\s*["']?([^"'\s&]+)/gi);
      if (filenameMatches) {
        filenameMatches.forEach(fm => {
          const extMatch = fm.match(/\.(\w+)/);
          if (extMatch) {
            const ext = extMatch[1].toLowerCase().replace(/["']/g, '');
            if (DANGEROUS_UPLOAD_EXTENSIONS[ext]) {
              fileIssues.push({
                type: 'dangerous-extension',
                param: 'filename (body)',
                extension: ext,
                description: DANGEROUS_UPLOAD_EXTENSIONS[ext]
              });
            }
          }
        });
      }
    }

    // 3. Check for oversized payload (bodySize > 10MB = potential DoS)
    const bodySize = req.response && req.response.bodySize ? req.response.bodySize : 0;
    if (bodySize > 10485760) { // 10MB
      fileIssues.push({
        type: 'oversized-payload',
        param: 'bodySize',
        description: `Oversized payload (${(bodySize / 1048576).toFixed(1)} MB) — potential denial of service`
      });
    }

    // 4. Check for missing Content-Type on upload endpoints
    if (isUploadEndpoint && !contentTypeVal && isMutatingRequest(req)) {
      fileIssues.push({
        type: 'missing-content-type',
        param: 'Content-Type',
        description: 'Missing Content-Type header on upload endpoint'
      });
    }

    if (fileIssues.length === 0) return;

    // Group findings
    const highSeverityIssues = fileIssues.filter(i => i.type === 'dangerous-extension' || i.type === 'null-byte-filename');
    const severity = highSeverityIssues.length > 0 ? 'high' : 'medium';

    const findId = 'file-parser-upload-vulns';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    findings.push({
      id: findId,
      category: 'file-parser-vulns',
      name: 'File Upload Vulnerability',
      description: `Detected ${fileIssues.length} file upload issue(s): ${fileIssues.map(i => i.description).join('; ')}. Malicious file uploads can lead to remote code execution, server compromise, or denial of service.`,
      severity,
      requestIndex: idx,
      evidence: {
        issues: fileIssues,
        url: getPathname(req.request.url || ''),
        method: req.request.method || 'POST',
        contentType: contentTypeVal || '(missing)'
      },
      score: severity === 'high' ? 85 : 40
    });
  });
}

// =========================
// DETECTOR 5: XXE INJECTION
// =========================
/**
 * Detect XML External Entity Injection:
 * - DOCTYPE with SYSTEM/PUBLIC identifiers
 * - ENTITY declarations referencing external resources
 * - file:// and http:// in entity definitions
 * - XXE in SVG, XML, or SOAP payloads
 * - XInclude attacks
 * - Blind XXE out-of-band patterns
 */
function detectXXEInjection(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const bodyText = getRequestBodyText(req);
    if (!bodyText) return;

    // Check Content-Type for XML or SOAP
    const headers = (req.request && req.request.headers) || [];
    const contentType = headers.find(h => (h.name || '').toLowerCase() === 'content-type');
    const contentTypeVal = contentType ? (contentType.value || '') : '';

    const isXmlContent = /xml|soap|xsd|wsdl|rss|atom|svg/.test(contentTypeVal) ||
                         /^<\?xml\s/i.test(bodyText.trim()) ||
                         /^<(\w+:)?\w+[^>]*xmlns/i.test(bodyText.trim());

    if (!isXmlContent) return;

    // Check body for XXE patterns
    const xxeMatches = [];

    XXE_PATTERNS.forEach(pattern => {
      const match = bodyText.match(pattern);
      if (match) {
        xxeMatches.push({
          pattern: match[0].substring(0, 80),
          type: getXXEPatternType(match[0])
        });
      }
    });

    // Check for out-of-band SSRF in entity values
    const oobMatches = bodyText.match(/<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)\s+["'](https?|ftp):\/\//gi);
    if (oobMatches) {
      oobMatches.forEach(m => {
        xxeMatches.push({
          pattern: m.substring(0, 80),
          type: 'oob-exfiltration'
        });
      });
    }

    // Check for blind XXE parameter entities
    if (/<!ENTITY\s+%\s+\w+\s+/i.test(bodyText)) {
      xxeMatches.push({
        pattern: 'Parameter entity found (%)',
        type: 'blind-xxe-parameter-entity'
      });
    }

    // Check for XInclude
    if (/<xi:include/i.test(bodyText) || /<include\s+parse=["']xml["']/i.test(bodyText)) {
      xxeMatches.push({
        pattern: 'XInclude directive',
        type: 'xinclude'
      });
    }

    if (xxeMatches.length === 0) return;

    const hasFileRead = xxeMatches.some(m => /file:\/\//i.test(m.pattern) || m.type === 'blind-xxe-parameter-entity');
    const severity = hasFileRead ? 'high' : 'high'; // XXE is always high severity

    const findId = 'file-parser-xxe';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    findings.push({
      id: findId,
      category: 'file-parser-vulns',
      name: 'XML External Entity (XXE) Injection',
      description: 'Detected ' + xxeMatches.length + ' XXE pattern(s) in XML payload. XXE injection can read local files (`file://`), perform SSRF, trigger denial of service (Billion Laughs), or exfiltrate data via out-of-band channels. Severity ranges from information disclosure to remote code execution.',
      severity,
      requestIndex: idx,
      evidence: {
        patterns: xxeMatches.slice(0, 5),
        totalMatches: xxeMatches.length,
        url: getPathname(req.request.url || ''),
        method: req.request.method || 'POST',
        contentType: contentTypeVal
      },
      score: 95
    });
  });
}

function getXXEPatternType(match) {
  if (/file:\/\//i.test(match)) return 'local-file-read';
  if (/https?:\/\//i.test(match)) return 'oob-exfiltration';
  if (/expect:\/\//i.test(match)) return 'rce-attempt';
  if (/php:\/\//i.test(match)) return 'lfi-attempt';
  if (/SYSTEM/i.test(match) && /PUBLIC/i.test(match)) return 'external-dtd';
  if (/SYSTEM/i.test(match)) return 'external-entity';
  if (/PUBLIC/i.test(match)) return 'public-entity';
  return 'xxe-suspicious';
}

// =========================
// DETECTOR 6: ZIP SLIP / ARCHIVE TRAVERSAL
// =========================
/**
 * Detect Zip Slip / Archive Traversal:
 * - Path traversal patterns in archive-related parameters
 * - ../ sequences inside ZIP entry filenames
 * - Archive extraction parameters with traversal
 * - Symlink in archive indicators
 */
function detectZipSlip(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const bodyText = getRequestBodyText(req);
    const allValues = [];

    // Collect parameter values for archive-related params
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      const isArchiveParam = ARCHIVE_PARAM_NAMES.some(ap => lowerKey.includes(ap) || lowerKey === ap);
      if (isArchiveParam) {
        allValues.push({ key, value: String(params[key]), source: 'param' });
      }
    });

    // Check file-related params
    Object.keys(params).forEach(key => {
      const lowerKey = key.toLowerCase();
      const isFileParam = FILE_PARAM_NAMES.some(fp => lowerKey.includes(fp) || lowerKey === fp);
      if (isFileParam) {
        allValues.push({ key, value: String(params[key]), source: 'file-param' });
      }
    });

    if (bodyText) {
      allValues.push({ key: 'body', value: bodyText, source: 'body' });
    }

    // Check for archive-related URL path
    const urlPath = getPathname(req.request.url || '');
    if (/extract|unzip|decompress|untar|expand/i.test(urlPath)) {
      allValues.push({ key: 'url-path', value: urlPath, source: 'url' });
    }

    const slipPatterns = [];

    allValues.forEach(item => {
      const val = item.value;

      // Traversal in archive extraction context
      if (/\.\.\/\w+\.\w+/.test(val) || /\.\.\\\w+\.\w+/.test(val)) {
        slipPatterns.push({
          param: item.key,
          sample: val.match(/\.\.\/\w+\.\w+|\.\.\\\w+\.\w+/)[0],
          type: 'path-traversal'
        });
      }

      // Symlink paths in archives
      if (/symlink|\.lnk|\/proc\/self\/fd\//i.test(val)) {
        slipPatterns.push({
          param: item.key,
          sample: val.substring(0, 80),
          type: 'symlink-reference'
        });
      }

      // Directory traversal sequences in archive content
      if (/(\w+\/){3,}\.\.\//.test(val)) {
        slipPatterns.push({
          param: item.key,
          sample: val.substring(0, 80),
          type: 'deep-traversal'
        });
      }
    });

    if (slipPatterns.length === 0) return;

    const findId = 'file-parser-zip-slip';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const hasTraversal = slipPatterns.some(p => p.type === 'path-traversal');
    const severity = hasTraversal ? 'high' : 'medium';

    findings.push({
      id: findId,
      category: 'file-parser-vulns',
      name: 'Zip Slip / Archive Path Traversal',
      description: `Zip Slip pattern detected (${slipPatterns.length} instance(s)). Archive extraction with path traversal can overwrite critical system files, write web shells, or escape the extraction directory, leading to remote code execution or system compromise.`,
      severity,
      requestIndex: idx,
      evidence: {
        patterns: slipPatterns,
        url: urlPath,
        method: req.request && req.request.method
      },
      score: hasTraversal ? 85 : 45
    });
  });
}

// =========================
// DETECTOR 7: LOG POISONING
// =========================
/**
 * Detect Log Poisoning:
 * - PHP code injection into log-related parameters
 * - System command injection in User-Agent, Referer, or other log fields
 * - Web shell payloads designed to be written to access/error logs
 * - Attempts to include log files via LFI after poisoning
 */
function detectLogPoisoning(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const headers = (req.request && req.request.headers) || [];
    const params = getAllParams(req);
    const bodyText = getRequestBodyText(req);

    // Fields commonly logged by servers
    const loggableFields = [];

    // User-Agent
    const userAgent = headers.find(h => (h.name || '').toLowerCase() === 'user-agent');
    if (userAgent) loggableFields.push({ field: 'User-Agent', value: userAgent.value || '' });

    // Referer
    const referer = headers.find(h => (h.name || '').toLowerCase() === 'referer' || (h.name || '').toLowerCase() === 'referrer');
    if (referer) loggableFields.push({ field: 'Referer', value: referer.value || '' });

    // Cookie
    const cookie = headers.find(h => (h.name || '').toLowerCase() === 'cookie');
    if (cookie) loggableFields.push({ field: 'Cookie', value: cookie.value || '' });

    // URL path and query params (often logged)
    const url = req.request && req.request.url ? req.request.url : '';
    loggableFields.push({ field: 'URL', value: url });

    // Request body for POST requests (can be logged)
    if (bodyText && isMutatingRequest(req)) {
      loggableFields.push({ field: 'Request Body', value: bodyText });
    }

    // Check for poisoning payloads in logged fields
    const poisonInstances = [];

    loggableFields.forEach(field => {
      for (const pattern of LOG_POISONING_PATTERNS) {
        if (pattern.test(field.value)) {
          const match = field.value.match(pattern);
          if (match) {
            poisonInstances.push({
              field: field.field,
              pattern: match[0].substring(0, 60),
              valueSample: field.value.substring(0, 80)
            });
          }
          break; // One finding per field
        }
      }
    });

    // Also check URL query params that might end up in logs
    Object.keys(params).forEach(key => {
      const val = String(params[key]);
      for (const pattern of LOG_POISONING_PATTERNS) {
        if (pattern.test(val)) {
          poisonInstances.push({
            field: `param:${key}`,
            pattern: val.match(pattern)[0].substring(0, 60),
            valueSample: val.substring(0, 80)
          });
          break;
        }
      }
    });

    if (poisonInstances.length === 0) return;

    const findId = 'file-parser-log-poisoning';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    findings.push({
      id: findId,
      category: 'file-parser-vulns',
      name: 'Log Poisoning / Log Injection',
      description: `Detected ${poisonInstances.length} log poisoning payload(s) in fields: ${[...new Set(poisonInstances.map(p => p.field))].join(', ')}. Log poisoning involves injecting PHP code, web shell payloads, or commands into log entries (access.log, error.log) that can later be executed via LFI.`,
      severity: 'high',
      requestIndex: idx,
      evidence: {
        instances: poisonInstances,
        url: getPathname(url),
        method: req.request && req.request.method
      },
      score: 85
    });
  });
}

// =========================
// DETECTOR 8: SERVER-SIDE FILE OPERATIONS ABUSE
// =========================
/**
 * Detect Server-Side File Operations Abuse:
 * - Requests attempting to read sensitive system files
 * - Access to configuration and secrets files
 * - Source code repository files (.git, .svn)
 * - Backup and temporary file access (.bak, .old, ~, .swp)
 * - Environment and secrets exposure
 */
function detectServerSideFileOps(sortedReqs, findings) {
  const requestFindings = new Map();

  sortedReqs.forEach((req, idx) => {
    const params = getAllParams(req);
    const urlPath = getPathname(req.request.url || '');
    const fullUrl = req.request && req.request.url ? req.request.url : '';
    const bodyText = getRequestBodyText(req);
    const allTextValues = [];

    // Collect all values to scan
    Object.keys(params).forEach(k => allTextValues.push({ key: k, value: String(params[k]) }));
    if (bodyText) allTextValues.push({ key: 'body', value: bodyText });
    allTextValues.push({ key: 'url', value: urlPath });
    allTextValues.push({ key: 'fullUrl', value: fullUrl });

    const sensitiveRefs = [];

    allTextValues.forEach(item => {
      const val = item.value;

      // Check against sensitive file paths
      for (const sensitivePath of SENSITIVE_FILE_PATHS) {
        // Exact or contained match
        if (val.includes(sensitivePath) || encodeURI(sensitivePath)) {
          sensitiveRefs.push({
            type: 'sensitive-file',
            path: sensitivePath,
            param: item.key,
            confidence: val.includes(sensitivePath) ? 'exact' : 'partial'
          });
          break;
        }
      }

      // Check for backup file extensions in file params
      if (FILE_PARAM_NAMES.some(fp => item.key.toLowerCase().includes(fp))) {
        if (/\.(bak|old|orig|backup|swp|swo|swn|~)/i.test(val)) {
          sensitiveRefs.push({
            type: 'backup-file',
            path: val.substring(0, 100),
            param: item.key
          });
        }
      }
    });

    // Check URL path for direct sensitive file access
    const urlSensitiveMatches = [];
    for (const sensitivePath of SENSITIVE_FILE_PATHS) {
      if (urlPath.includes(sensitivePath) || fullUrl.includes(sensitivePath) ||
          fullUrl.includes(encodeURIComponent(sensitivePath))) {
        urlSensitiveMatches.push(sensitivePath);
      }
    }

    if (urlSensitiveMatches.length > 0) {
      sensitiveRefs.push({
        type: 'direct-url-access',
        paths: urlSensitiveMatches,
        param: 'url-path'
      });
    }

    // Check for file:// combined with sensitive paths
    const fileProtoPaths = [];
    allTextValues.forEach(item => {
      const val = item.value;
      const match = val.match(/file:\/\/\/([^\s"']+)/i);
      if (match) {
        const filePath = '/' + match[1].replace(/^\/+/, '');
        for (const sensitivePath of SENSITIVE_FILE_PATHS) {
          if (filePath.includes(sensitivePath)) {
            fileProtoPaths.push({ path: filePath, sensitivePath });
            break;
          }
        }
      }
    });

    if (fileProtoPaths.length > 0) {
      sensitiveRefs.push({
        type: 'file-protocol-sensitive',
        paths: fileProtoPaths.map(p => p.path),
        param: 'file-protocol'
      });
    }

    if (sensitiveRefs.length === 0) return;

    const findId = 'file-parser-sensitive-file-access';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    const types = [...new Set(sensitiveRefs.map(r => r.type))];

    findings.push({
      id: findId,
      category: 'file-parser-vulns',
      name: 'Sensitive File Access / Server-Side File Read',
      description: `Sensitive system file references detected (${sensitiveRefs.length} match(es): ${types.join(', ')}). Attempting to read system files like /etc/passwd, .env, configuration files, or version control metadata can lead to credential disclosure, source code leaks, and full server compromise.`,
      severity: 'high',
      requestIndex: idx,
      evidence: {
        refs: sensitiveRefs.slice(0, 8),
        totalMatches: sensitiveRefs.length,
        url: urlPath,
        method: req.request && req.request.method
      },
      score: 85
    });
  });
}

// =========================
// DETECTOR 9: FILE PERMISSION / ACCESS CONTROL EXPOSURE
// =========================
/**
 * Detect File Permission / Access Control Exposure:
 * - Access to .git/config, .svn/entries, .DS_Store
 * - Access to backup/config files with sensitive info
 * - Directory listing attempts
 * - Path-based privilege escalation attempts
 * - Cross-directory access violations
 * - Server status/health endpoints that expose filesystem info
 */
function detectFilePermissionExposure(sortedReqs, findings) {
  const requestFindings = new Map();

  const EXPOSURE_PATTERNS = [
    // VCS and CI/CD
    { pattern: /\.git\/(config|HEAD|index|refs|objects|logs)/i, name: 'Git repository exposure', severity: 'high' },
    { pattern: /\.svn\/(entries|wc.db|pristine|text-base)/i, name: 'SVN repository exposure', severity: 'high' },
    { pattern: /\.hg\/(store|requires)/i, name: 'Mercurial repository exposure', severity: 'high' },
    { pattern: /\.DS_Store/i, name: 'macOS metadata file exposure', severity: 'medium' },
    // Backup files
    { pattern: /\.(bak|old|orig|backup|swp|swo|swn)\/?$/i, name: 'Backup file exposure', severity: 'medium' },
    { pattern: /~(?:$|[?#])/, name: 'Backup file (tilde) exposure', severity: 'medium' },
    // Config/database files
    { pattern: /\.sqlite|\.sqlite3|\.db|\.mdb|\.accdb|\.frm|\.myd|\.myi/i, name: 'Database file exposure', severity: 'high' },
    { pattern: /web\.config/i, name: 'ASP.NET web.config exposure', severity: 'high' },
    // Environment files
    { pattern: /\.env(?:\.\w+)?$/i, name: 'Environment file exposure', severity: 'high' },
    // Server status
    { pattern: /\/server-status|\/server-info|\/phpinfo/i, name: 'Server status/info page access', severity: 'medium' },
    // Directory listing
    { pattern: /\/$/, name: 'Directory listing attempt', severity: 'low' },
    // Cross-directory access indicators
    { pattern: /\.\.\/\.\.\/\.\.\//, name: 'Deep path traversal', severity: 'high' },
    // Log files
    { pattern: /\.log(?:\.\d+)?$/i, name: 'Log file exposure', severity: 'medium' }
  ];

  sortedReqs.forEach((req, idx) => {
    const urlPath = getPathname(req.request.url || '');
    const fullUrl = req.request && req.request.url ? req.request.url : '';

    const matchedPatterns = [];

    for (const ep of EXPOSURE_PATTERNS) {
      if (ep.pattern.test(urlPath) || ep.pattern.test(fullUrl)) {
        matchedPatterns.push(ep);
      }
    }

    if (matchedPatterns.length === 0) return;

    const severity = matchedPatterns.some(m => m.severity === 'high') ? 'high' : 'medium';
    const findId = 'file-parser-permission-exposure';
    if (requestFindings.has(idx) && requestFindings.get(idx).has(findId)) return;
    if (!requestFindings.has(idx)) requestFindings.set(idx, new Set());
    requestFindings.get(idx).add(findId);

    findings.push({
      id: findId,
      category: 'file-parser-vulns',
      name: 'File Permission / Access Control Exposure',
      description: `Exposed file/permission violation detected: ${matchedPatterns.map(m => m.name).join(', ')}. Unauthorized access to repository files, backup files, environment configuration, or server status pages can leak credentials, source code, database dumps, and sensitive configuration data.`,
      severity,
      requestIndex: idx,
      evidence: {
        patterns: matchedPatterns.map(m => ({ type: m.name, severity: m.severity })),
        url: urlPath,
        method: req.request && req.request.method
      },
      score: severity === 'high' ? 80 : 45
    });
  });
}

