/**
 * ShieldTier V2 — Preload Shim
 *
 * Recreates the window.shieldtier API that V1's React renderer expects,
 * routing calls through CEF's cefQuery (CefMessageRouter) instead of
 * Electron's ipcRenderer.invoke / ipcRenderer.on.
 *
 * Event bridge: C++ EventBridge calls window.__shieldtier_push(event, data)
 * which this shim dispatches to registered listeners.
 */

(function () {
  'use strict';

  // ── Event dispatcher ──────────────────────────────────────────────────
  // C++ EventBridge.push() calls: window.__shieldtier_push(event, data)
  const _listeners = {};

  function on(event, callback) {
    if (!_listeners[event]) _listeners[event] = [];
    _listeners[event].push(callback);
    // Return unsubscribe function (matches Electron preload pattern)
    return function () {
      const arr = _listeners[event];
      if (arr) {
        const idx = arr.indexOf(callback);
        if (idx !== -1) arr.splice(idx, 1);
      }
    };
  }

  window.__shieldtier_push = function (event, data) {
    const cbs = _listeners[event];
    if (cbs) {
      for (let i = 0; i < cbs.length; i++) {
        try { cbs[i](data); } catch (e) { console.error('[shim] event handler error:', event, e); }
      }
    }
  };

  // ── Email normalizer — ensures all required arrays exist ──────────────
  function normalizeEmail(e) {
    if (!e || typeof e !== 'object') return e;
    return {
      id: e.id || '',
      sessionId: e.sessionId || '',
      from: e.from || '',
      to: Array.isArray(e.to) ? e.to : (e.to ? [e.to] : []),
      cc: Array.isArray(e.cc) ? e.cc : [],
      subject: e.subject || '',
      date: e.date || '',
      headers: e.headers || {},
      receivedChain: Array.isArray(e.receivedChain) ? e.receivedChain : [],
      authentication: Array.isArray(e.authentication) ? e.authentication : [],
      bodyText: e.bodyText || e.textBody || e.body_text || '',
      bodyHtml: e.bodyHtml || e.htmlBody || e.body_html || '',
      textBody: e.textBody || e.bodyText || e.body_text || '',
      htmlBody: e.htmlBody || e.bodyHtml || e.body_html || '',
      urls: Array.isArray(e.urls) ? e.urls : [],
      attachments: Array.isArray(e.attachments) ? e.attachments : [],
      phishingScore: e.phishingScore || null,
      rawSource: e.rawSource || '',
      parsedAt: e.parsedAt || Date.now(),
      findings: Array.isArray(e.findings) ? e.findings : [],
      raw_output: e.raw_output || {},
    };
  }

  // ── IPC invoke via cefQuery ───────────────────────────────────────────
  function invoke(action, payload) {
    var p = new Promise(function (resolve, reject) {
      var msg = JSON.stringify({ action: action, payload: payload || {} });
      window.cefQuery({
        request: msg,
        onSuccess: function (response) {
          try {
            var parsed = JSON.parse(response);
            if (parsed.success) {
              var resolved = parsed.data !== undefined ? parsed.data : parsed;
              // V1 renderer expects .success on resolved objects
              if (resolved && typeof resolved === 'object' && !Array.isArray(resolved)) {
                resolved.success = true;
              }
              resolve(resolved);
            } else {
              reject(new Error(parsed.error || 'Unknown error'));
            }
          } catch (e) {
            // Raw string response
            resolve(response);
          }
        },
        onFailure: function (code, message) {
          reject(new Error(message || 'cefQuery failed (code ' + code + ')'));
        }
      });
    });
    // Prevent unhandled rejection noise in CEF console
    p.catch(function () {});
    return p;
  }

  // ── IOC Auto-Extraction Engine ──────────────────────────────────────
  // Extracts domains, IPs, and URLs from captured network traffic (HAR entries).
  // Matches V1's enrichment/extractors.ts pipeline.

  var _iocStore = {};         // sessionId → { normalized_value → IOCEntry }
  var _iocSeenGlobal = {};    // normalized_value → true (cross-session dedup)

  var PRIVATE_IP_RX = [
    /^127\./, /^10\./, /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./, /^169\.254\./, /^0\./, /^::1$/, /^fe80:/i, /^fc00:/i, /^fd/i
  ];
  var SAFE_DOMAIN_SUFFIXES = [
    'gstatic.com', 'googleapis.com', 'google.com', 'google-analytics.com',
    'googletagmanager.com', 'googlesyndication.com', 'doubleclick.net',
    'cloudflare.com', 'cloudflare-dns.com', 'cdn.jsdelivr.net',
    'cdnjs.cloudflare.com', 'unpkg.com', 'fonts.googleapis.com',
    'fonts.gstatic.com', 'chrome.google.com', 'accounts.google.com',
    'safebrowsing.googleapis.com', 'update.googleapis.com',
    'clients1.google.com', 'clients2.google.com',
  ];
  var IPV4_RX = /^(\d{1,3}\.){3}\d{1,3}$/;
  var DOMAIN_RX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  var HASH_MD5 = /^[a-fA-F0-9]{32}$/;
  var HASH_SHA1 = /^[a-fA-F0-9]{40}$/;
  var HASH_SHA256 = /^[a-fA-F0-9]{64}$/;

  function isPrivateIP(ip) {
    for (var i = 0; i < PRIVATE_IP_RX.length; i++) {
      if (PRIVATE_IP_RX[i].test(ip)) return true;
    }
    return false;
  }
  function isSafeDomain(domain) {
    var d = domain.toLowerCase();
    for (var i = 0; i < SAFE_DOMAIN_SUFFIXES.length; i++) {
      if (d === SAFE_DOMAIN_SUFFIXES[i] || d.endsWith('.' + SAFE_DOMAIN_SUFFIXES[i])) return true;
    }
    return false;
  }
  function isValidIPv4(v) {
    if (!IPV4_RX.test(v)) return false;
    var parts = v.split('.');
    for (var i = 0; i < parts.length; i++) {
      var n = parseInt(parts[i], 10);
      if (n < 0 || n > 255) return false;
    }
    return true;
  }
  function detectIOCType(value) {
    var t = value.trim();
    if (!t) return null;
    if (HASH_SHA256.test(t) || HASH_SHA1.test(t) || HASH_MD5.test(t)) return 'hash';
    if (isValidIPv4(t)) return 'ip';
    try { var u = new URL(t); if (u.protocol === 'http:' || u.protocol === 'https:') return 'url'; } catch (e) {}
    if (DOMAIN_RX.test(t)) return 'domain';
    return null;
  }

  function _iocEmit(sessionId, entry) {
    // Push enrichment_result event to AnalysisPanel
    var cbs = _listeners['enrichment_result'];
    if (cbs) {
      var payload = JSON.parse(JSON.stringify(entry));
      payload.sessionId = sessionId;
      for (var i = 0; i < cbs.length; i++) {
        try { cbs[i](payload); } catch (e) {}
      }
    }
  }

  function _iocAdd(sessionId, value, type, source, safe, domain) {
    var norm = value.toLowerCase();
    if (!_iocStore[sessionId]) _iocStore[sessionId] = {};
    var store = _iocStore[sessionId];

    // Skip if already seen in this session
    if (store[norm]) return;

    // Global dedup
    if (_iocSeenGlobal[norm]) {
      // Still register locally for display
    }
    _iocSeenGlobal[norm] = true;

    var entry = {
      value: value,
      type: type,
      source: source,
      firstSeen: Date.now(),
      results: [],
      status: safe ? 'skipped' : 'pending',
      safe: !!safe,
      domain: domain || ''
    };
    store[norm] = entry;
    _iocEmit(sessionId, entry);
  }

  function _iocExtractFromURL(sessionId, urlStr) {
    try {
      var u = new URL(urlStr);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
      var hostname = u.hostname.toLowerCase();

      if (isValidIPv4(hostname)) {
        var priv = isPrivateIP(hostname);
        _iocAdd(sessionId, hostname, 'ip', 'network_traffic', priv, '');
      } else if (DOMAIN_RX.test(hostname)) {
        var safe = isSafeDomain(hostname);
        _iocAdd(sessionId, hostname, 'domain', 'network_traffic', safe, hostname);
        // Register full URL as separate IOC (skip safe domains — matches V1)
        if (!safe) {
          _iocAdd(sessionId, urlStr, 'url', 'network_traffic', false, hostname);
        }
      }
    } catch (e) {}
  }

  function _iocExtractFromEntry(sessionId, entry) {
    // Extract from request URL
    var url = '';
    if (entry.request && entry.request.url) url = entry.request.url;
    else if (entry.url) url = entry.url;
    if (url) _iocExtractFromURL(sessionId, url);

    // Extract server IP if present
    if (entry.serverIPAddress) {
      var ip = entry.serverIPAddress.trim();
      if (ip && isValidIPv4(ip) && !isPrivateIP(ip)) {
        _iocAdd(sessionId, ip, 'ip', 'server_address', false, '');
      }
    }
  }

  function _iocGetResults(sessionId) {
    var store = _iocStore[sessionId];
    if (!store) return [];
    var results = [];
    var keys = Object.keys(store);
    for (var i = 0; i < keys.length; i++) {
      results.push(store[keys[i]]);
    }
    return results;
  }

  // ── Client-side session management ──────────────────────────────────
  // V2 doesn't have a server-side InvestigationSession concept yet.
  // Sessions are tracked in JS and the content browser is created on navigate.
  var _sessions = [];
  var _nextSessionId = 1;

  function generateSessionId() {
    return 'sess-' + Date.now().toString(36) + '-' + (_nextSessionId++).toString(36);
  }

  // ── Active session helper ────────────────────────────────────────────
  // V2 has a single content browser — inject the active session ID into
  // events so the renderer's per-session filtering works.
  function activeSessionId(data) {
    if (data && data.sessionId) return data.sessionId;
    var s = _sessions.length > 0 ? _sessions[_sessions.length - 1] : null;
    return s ? s.id : '';
  }

  // ── File object normalizer ────────────────────────────────────────────
  // V1 renderer expects certain array/object fields on file analysis results.
  // C++ handlers may omit them (undefined → crash on for...of / .length).
  function normalizeFile(f) {
    if (!f || typeof f !== 'object') return f;
    if (!Array.isArray(f.sandboxResults)) f.sandboxResults = [];
    if (!f.staticAnalysis) f.staticAnalysis = { findings: [] };
    if (!Array.isArray(f.staticAnalysis.findings)) f.staticAnalysis.findings = [];
    // Phase 0 crash fix: ensure all numeric/string fields the renderer expects
    if (typeof f.staticAnalysis.entropy !== 'number') f.staticAnalysis.entropy = 0;
    if (typeof f.staticAnalysis.fileType !== 'string') f.staticAnalysis.fileType = '';
    if (typeof f.staticAnalysis.mimeType !== 'string') f.staticAnalysis.mimeType = '';
    if (!f.staticAnalysis.metadata) f.staticAnalysis.metadata = {};
    if (!f.yaraMatches) f.yaraMatches = [];
    if (!f.enrichment) f.enrichment = {};
    if (!f.hashes) f.hashes = null;
    if (typeof f.fileSize !== 'number') f.fileSize = f.size || 0;
    if (!f.originalName) f.originalName = f.filename || '';
    if (!f.status) f.status = 'pending';
    if (!f.riskLevel) f.riskLevel = 'info';
    if (!f.id && f.sha256) f.id = f.sha256;
    return f;
  }

  // ── Build window.shieldtier ───────────────────────────────────────────

  window.shieldtier = {
    // ── Auth ──
    auth: {
      login: function (email, password) {
        return invoke('auth_login', { email: email, password: password });
      },
      register: function (email, password, analystName) {
        return invoke('auth_register', { email: email, password: password, analystName: analystName });
      },
      logout: function () { return invoke('auth_logout'); },
      getUser: function () { return invoke('auth_get_user'); },
      restoreSession: function () { return invoke('auth_restore_session'); },
      changePassword: function (currentPassword, newPassword) {
        return invoke('auth_change_password', { currentPassword: currentPassword, newPassword: newPassword });
      },
      resendVerification: function () { return invoke('auth_resend_verification'); },
      refreshProfile: function () { return invoke('auth_refresh_profile'); },
      updateProfile: function (updates) { return invoke('auth_update_profile', updates); },
      syncCases: function (cases) { return invoke('auth_sync_cases', { cases: cases }); },
      getCases: function () {
        return invoke('auth_get_cases').then(function (v) {
          return Array.isArray(v) ? v : (v && v.cases ? v.cases : []);
        });
      },
      setSyncKey: function (syncKey) { return invoke('auth_set_sync_key', { syncKey: syncKey }); },
      onSessionExpired: function (callback) {
        return on('auth_session_expired', callback);
      },
    },

    // ── Session ──
    session: {
      create: function (config) {
        var caseName = (config && config.caseName) || 'Untitled';
        var url = (config && config.url) || '';
        var proxyConfig = (config && config.proxyConfig) || null;

        // Delegate to C++ SessionManager — session state survives renderer crashes
        return invoke('session_create', {
          caseName: caseName,
          url: url,
          proxyConfig: proxyConfig
        }).then(function (session) {
          // Keep a local reference for activeSessionId() lookups
          _sessions.push(session);
          return session;
        });
      },
      destroy: function (sessionId) {
        _sessions = _sessions.filter(function (s) { return s.id !== sessionId; });
        // Clear IOC store for this session (match V1's session cleanup)
        delete _iocStore[sessionId];
        return invoke('session_destroy', { sessionId: sessionId }).catch(function () {
          return { success: true };
        });
      },
      list: function () {
        // Fetch authoritative session list from C++ SessionManager
        return invoke('session_list', {}).then(function (sessions) {
          if (Array.isArray(sessions)) {
            _sessions = sessions;
            return sessions;
          }
          return _sessions;
        }).catch(function () {
          return _sessions;
        });
      },
    },

    // ── Proxy ──
    proxy: {
      configure: function (config) {
        return invoke('set_config', { key: 'proxy', value: config });
      },
      getConfig: function () {
        return invoke('get_config', { key: 'proxy' });
      },
      test: function (config) {
        return invoke('test_proxy', config || {});
      },
    },

    // ── View (BrowserView / Content Browser) ──
    view: {
      create: function (sessionId) { return invoke('navigate', { sessionId: sessionId }); },
      navigate: function (sessionId, url) {
        return invoke('navigate', { sessionId: sessionId, url: url });
      },
      goBack: function (sessionId) { return invoke('nav_back', {}); },
      goForward: function (sessionId) { return invoke('nav_forward', {}); },
      reload: function (sessionId) { return invoke('nav_reload', {}); },
      stop: function (sessionId) { return invoke('nav_stop', {}); },
      setBounds: function (sessionId, bounds) {
        return invoke('set_content_bounds', bounds);
      },
      hide: function (sessionId) { return invoke('hide_content_browser', {}); },
      hideView: function (sessionId) { return invoke('hide_content_browser', {}); },
      getNavState: function (sessionId) {
        return invoke('get_nav_state', { sessionId: sessionId });
      },
      setZoom: function (sessionId, factor) {
        return invoke('set_zoom', { factor: factor });
      },
      getZoom: function (sessionId) { return invoke('get_zoom', {}); },
      analyzeNow: function (sessionId) {
        return invoke('analyze_now', { sessionId: sessionId });
      },

      onNavStateChanged: function (callback) {
        return on('navigation_state', function (data) {
          // Remap C++ field names to V1 renderer expected shape
          var state = {
            url: data.url || '',
            title: data.title || '',
            isLoading: !!data.loading,
            canGoBack: !!data.can_back,
            canGoForward: !!data.can_forward,
          };
          // Also update the active session's navState
          var sid = activeSessionId(data);
          for (var i = 0; i < _sessions.length; i++) {
            if (_sessions[i].id === sid) {
              _sessions[i].navState = state;
              if (state.url) _sessions[i].url = state.url;
              break;
            }
          }
          // Auto-extract IOCs from navigated URLs
          if (state.url) _iocExtractFromURL(sid, state.url);
          callback(sid, state);
        });
      },
      onLoadError: function (callback) {
        return on('load_error', function (data) {
          callback(activeSessionId(data), data);
        });
      },
      onSandboxResult: function (callback) {
        return on('sandbox_result', function (data) {
          callback(activeSessionId(data), data);
        });
      },
    },

    // ── Capture ──
    capture: {
      enable: function (sessionId) { return invoke('start_capture', { sessionId: sessionId }); },
      disable: function (sessionId) { return invoke('stop_capture', { sessionId: sessionId }); },
      getHAR: function (sessionId) { return invoke('get_capture', { sessionId: sessionId }); },
      takeScreenshot: function (sessionId) { return invoke('take_screenshot', { sessionId: sessionId }); },
      takeDOMSnapshot: function (sessionId) { return invoke('take_dom_snapshot', { sessionId: sessionId }); },
      getStatus: function (sessionId) {
        return invoke('get_capture_status', { sessionId: sessionId });
      },
      getScreenshots: function (sessionId) {
        return invoke('get_screenshots', { sessionId: sessionId }).then(function (v) {
          if (Array.isArray(v)) return v;
          if (v && v.screenshots) return v.screenshots;
          return [];
        });
      },
      getDOMSnapshots: function (sessionId) {
        return invoke('get_dom_snapshots', { sessionId: sessionId }).then(function (v) {
          if (Array.isArray(v)) return v;
          if (v && v.snapshots) return v.snapshots;
          return [];
        });
      },
      onNetworkEvent: function (callback) {
        return on('capture_update', function (data) {
          // Auto-extract IOCs from every network event
          var sid = activeSessionId(data);
          _iocExtractFromEntry(sid, data);
          callback(sid, data);
        });
      },
    },

    // ── Enrichment ──
    enrichment: {
      query: function (sessionId, ioc) {
        var trimmed = (ioc || '').trim();
        var iocType = detectIOCType(trimmed);
        if (!iocType) return Promise.resolve(null);

        // Register as manual IOC if not already tracked
        var norm = trimmed.toLowerCase();
        if (!_iocStore[sessionId]) _iocStore[sessionId] = {};
        var store = _iocStore[sessionId];
        if (!store[norm]) {
          store[norm] = {
            value: trimmed,
            type: iocType,
            source: 'manual',
            firstSeen: Date.now(),
            results: [],
            status: 'enriching',
            safe: false,
            domain: iocType === 'domain' ? trimmed : ''
          };
        } else {
          store[norm].status = 'enriching';
          store[norm].results = [];
        }
        _iocEmit(sessionId, store[norm]);

        // Call real C++ EnrichmentManager via IPC
        return invoke('enrichment_query', {
          sessionId: sessionId,
          ioc: trimmed,
          iocType: iocType
        }).then(function (data) {
          if (store[norm]) {
            store[norm].status = data.status || 'done';
            store[norm].results = data.results || [];
            if (data.verdict) store[norm].verdict = data.verdict;
            _iocEmit(sessionId, store[norm]);
          }
          return store[norm] || null;
        }).catch(function (err) {
          if (store[norm]) {
            store[norm].status = 'error';
            store[norm].results = [{
              provider: 'error',
              ioc: trimmed,
              iocType: iocType,
              verdict: 'unknown',
              confidence: 0,
              summary: err.message || 'Enrichment failed',
              details: {},
              timestamp: Date.now()
            }];
            _iocEmit(sessionId, store[norm]);
          }
          return store[norm] || null;
        });
      },
      getResults: function (sessionId) {
        return Promise.resolve(_iocGetResults(sessionId));
      },
      getSummary: function (sessionId) {
        var entries = _iocGetResults(sessionId);
        var summary = { total: entries.length, malicious: 0, suspicious: 0, clean: 0, pending: 0, error: 0, byType: { ip: 0, domain: 0, url: 0, hash: 0 } };
        for (var i = 0; i < entries.length; i++) {
          var e = entries[i];
          summary.byType[e.type] = (summary.byType[e.type] || 0) + 1;
          if (e.status === 'skipped') continue;
          if (e.status === 'pending' || e.status === 'enriching') { summary.pending++; continue; }
          if (e.status === 'error') { summary.error++; continue; }
          summary.clean++;
        }
        return Promise.resolve(summary);
      },
      setAPIKeys: function (keys) {
        return invoke('set_config', { key: 'apiKeys', value: keys });
      },
      getAPIKeys: function () {
        return invoke('get_config', { key: 'apiKeys' }).then(function (v) {
          return v || {};
        });
      },
      onResult: function (callback) {
        return on('enrichment_result', function (data) {
          callback(activeSessionId(data), data);
        });
      },
    },

    // ── File Analysis ──
    fileanalysis: {
      getFiles: function (sessionId) {
        return invoke('get_analysis_result', { sessionId: sessionId }).catch(function () { return []; }).then(function (v) {
          var arr = Array.isArray(v) ? v : [];
          return arr.map(normalizeFile);
        });
      },
      getFile: function (sessionId, fileId) {
        return invoke('get_analysis_result', { sha256: fileId }).catch(function () { return null; }).then(function (v) {
          return v ? normalizeFile(v) : null;
        });
      },
      resubmit: function (sessionId, fileId) {
        return invoke('analyze_download', { sha256: fileId });
      },
      analyzeBehavior: function (sessionId, fileId) {
        return invoke('analyze_download', { sha256: fileId });
      },
      getFilePreview: function (fileId) {
        return invoke('get_file_preview', { sha256: fileId });
      },
      analyzeInVM: function (sessionId, fileId, config) {
        return invoke('submit_sample_to_vm', { sessionId: sessionId, fileId: fileId, config: config });
      },
      deleteFile: function (sessionId, fileId) {
        return invoke('delete_file', { sessionId: sessionId, fileId: fileId });
      },
      setSandboxKeys: function (keys) {
        return invoke('set_config', { key: 'sandboxKeys', value: keys });
      },
      getSandboxKeys: function () {
        return invoke('get_config', { key: 'sandboxKeys' });
      },
      submitArchivePassword: function (sessionId, fileId, password) {
        return invoke('submit_archive_password', { sha256: fileId, password: password });
      },
      skipArchivePassword: function (sessionId, fileId) {
        return invoke('skip_archive_password', { sha256: fileId });
      },
      uploadFiles: function (sessionId) {
        return invoke('upload_files', { sessionId: sessionId });
      },
      onFileUpdate: function (callback) {
        return on('analysis_complete', function (data) {
          // C++ emits {sha256, result: {status, verdict}}
          // Flatten into a single object the renderer expects
          var file = {};
          if (data && data.result && typeof data.result === 'object') {
            file = JSON.parse(JSON.stringify(data.result));
          } else if (data) {
            file = JSON.parse(JSON.stringify(data));
          }
          // Ensure sha256/id are at the top level
          if (data && data.sha256) {
            file.sha256 = data.sha256;
            if (!file.id) file.id = data.sha256;
          }
          // Auto-register file hashes as IOCs
          var sid = activeSessionId(data);
          if (file.sha256) {
            _iocAdd(sid, file.sha256, 'hash', 'file_download', false, '');
          }
          if (file.md5) {
            _iocAdd(sid, file.md5, 'hash', 'file_download', false, '');
          }
          callback(sid, normalizeFile(file));
        });
      },
    },

    // ── Config ──
    config: {
      get: function (key) { return invoke('get_config', { key: key }); },
      set: function (key, value) { return invoke('set_config', { key: key, value: value }); },
      getWhitelist: function () {
        return invoke('get_config', { key: 'whitelist' }).then(function (v) {
          return v || { domains: [], patterns: [], ips: [], hashes: [], useBuiltIn: false };
        });
      },
      setWhitelist: function (value) {
        return invoke('set_config', { key: 'whitelist', value: value });
      },
      getProxyConfig: function () {
        return invoke('get_config', { key: 'proxy' }).then(function (v) {
          return v || { type: 'direct', host: 'localhost', port: 0 };
        });
      },
      isDomainWhitelisted: function (domain) {
        return invoke('check_whitelist', { domain: domain });
      },
      getAnalystProfile: function () {
        return invoke('get_config', { key: 'analystProfile' }).then(function (v) {
          return v || { name: '', organization: '', role: '' };
        });
      },
      setAnalystProfile: function (value) {
        return invoke('set_config', { key: 'analystProfile', value: value });
      },
      peekNextCaseId: function () {
        return invoke('get_config', { key: 'nextCaseId' }).then(function (raw) {
          // Unwrap: raw might be {success:true, value:N} or a number or null
          var val;
          if (typeof raw === 'number') {
            val = raw;
          } else if (raw && typeof raw === 'object') {
            if (typeof raw.value === 'number') val = raw.value;
            else if (typeof raw.data === 'number') val = raw.data;
          }
          if (typeof val === 'number' && val > 0) {
            return 'CASE-' + String(val).padStart(6, '0');
          }
          return 'CASE-000001';
        }).catch(function () {
          return 'CASE-000001';
        });
      },
    },

    // ── Report ──
    report: {
      generate: function (config) { return invoke('export_report', config); },
      preview: function (config) {
        return invoke('preview_report', config || {});
      },
      onProgress: function (callback) {
        return on('report_progress', callback);
      },
      saveFile: function (content, defaultName, extension) {
        return invoke('save_report', { content: content, defaultName: defaultName, extension: extension });
      },
    },

    // ── Email ──
    email: {
      parseRaw: function (sessionId, rawSource) {
        return invoke('analyze_email', { sessionId: sessionId, rawSource: rawSource }).then(normalizeEmail);
      },
      getEmails: function (sessionId) {
        return invoke('get_emails', { sessionId: sessionId }).then(function (v) {
          var list = Array.isArray(v) ? v : (v && v.emails ? v.emails : []);
          return list.map(normalizeEmail);
        });
      },
      getEmail: function (sessionId, emailId) {
        return invoke('get_email', { sessionId: sessionId, emailId: emailId }).then(normalizeEmail);
      },
      openFile: function (sessionId) {
        return invoke('open_email_file', { sessionId: sessionId }).then(normalizeEmail);
      },
      onEmailParsed: function (callback) {
        return on('email_parsed', function (data) {
          var email = data && data.email ? normalizeEmail(data.email) : normalizeEmail(data);
          var sid = (data && data.sessionId) || activeSessionId(data);
          callback(sid, email);
        });
      },
    },

    // ── Content Analysis ──
    contentanalysis: {
      getFindings: function (sessionId) {
        return invoke('get_content_findings', { sessionId: sessionId }).then(function (v) {
          return Array.isArray(v) ? v : [];
        });
      },
      onFinding: function (callback) {
        return on('content_finding', function (data) {
          callback(activeSessionId(data), data);
        });
      },
    },

    // ── YARA ──
    yara: {
      getRules: function () {
        return invoke('yara_get_rules', {}).then(function (v) {
          return Array.isArray(v) ? v : [];
        });
      },
      getRule: function (id) {
        return invoke('yara_get_rule', { id: id });
      },
      addRule: function (rule) {
        return invoke('yara_add_rule', rule);
      },
      updateRule: function (id, rule) {
        return invoke('yara_update_rule', { id: id, rule: rule });
      },
      deleteRule: function (id) {
        return invoke('yara_delete_rule', { id: id });
      },
      importRules: function (data) {
        return invoke('yara_import_rules', { data: data });
      },
      exportRules: function () {
        return invoke('yara_export_rules', {});
      },
      getBuiltinPacks: function () {
        return invoke('yara_get_packs', {});
      },
      togglePack: function (pack, enabled) {
        return invoke('yara_toggle_pack', { pack: pack, enabled: enabled });
      },
      scanFile: function (sha256) {
        return invoke('yara_scan_file', { sha256: sha256 });
      },
      scanContent: function (content) {
        return invoke('yara_scan_content', { content: content });
      },
      getScanResults: function (sha256) {
        return invoke('yara_get_results', { sha256: sha256 }).then(function (v) {
          return Array.isArray(v) ? v : [];
        });
      },
      onScanResult: function (callback) {
        return on('yara_scan_result', function (data) {
          callback(activeSessionId(data), data);
        });
      },
    },

    // ── Chat ──
    chat: {
      getIdentity: function () {
        return invoke('chat_get_identity', {}).then(function (v) {
          if (!v) return null;
          return {
            sessionId: v.sessionId || v.session_id || '',
            mnemonic: v.mnemonic || v.public_key || '',
          };
        });
      },
      getContacts: function () {
        return invoke('chat_get_contacts', {}).then(function (v) {
          return Array.isArray(v) ? v : (v && v.contacts ? v.contacts : []);
        });
      },
      addContact: function (sessionId, displayName) {
        return invoke('chat_add_contact', { sessionId: sessionId, displayName: displayName });
      },
      removeContact: function (contactId) {
        return invoke('chat_remove_contact', { contactId: contactId });
      },
      updateContactName: function (contactId, name) {
        return invoke('chat_update_contact', { contactId: contactId, name: name });
      },
      getConversations: function () {
        return invoke('chat_get_conversations', {}).then(function (v) {
          return Array.isArray(v) ? v : (v && v.conversations ? v.conversations : []);
        });
      },
      getMessages: function (conversationId, limit, before) {
        return invoke('chat_get_messages', { conversationId: conversationId, limit: limit, before: before }).then(function (v) {
          return Array.isArray(v) ? v : (v && v.messages ? v.messages : []);
        });
      },
      sendMessage: function (recipientSessionId, body) {
        return invoke('chat_send_message', { recipientSessionId: recipientSessionId, body: body });
      },
      markAsRead: function (conversationId) {
        return invoke('chat_mark_read', { conversationId: conversationId });
      },
      getConnectionStatus: function () { return invoke('chat_get_status', {}).then(function (v) { return (v && v.status) ? v.status : 'disconnected'; }); },
      setPresence: function (status) {
        return invoke('chat_set_presence', { status: status });
      },
      acknowledgeOnboarding: function () {
        return invoke('chat_ack_onboarding', {});
      },
      getMessageRequests: function () {
        return invoke('chat_get_requests', {}).then(function (v) {
          return Array.isArray(v) ? v : (v && v.requests ? v.requests : []);
        });
      },
      approveContact: function (sessionId) {
        return invoke('chat_approve_contact', { sessionId: sessionId });
      },
      rejectContact: function (sessionId) {
        return invoke('chat_reject_contact', { sessionId: sessionId });
      },
      lookupUser: function (sessionId) {
        return invoke('chat_lookup_user', { query: sessionId });
      },

      onMessageReceived: function (callback) { return on('chat_message_received', callback); },
      onMessageSent: function (callback) { return on('chat_message_sent', callback); },
      onMessageFailed: function (callback) { return on('chat_message_failed', callback); },
      onIdentityCreated: function (callback) { return on('chat_identity_created', callback); },
      onConnectionStatus: function (callback) { return on('chat_connection_status', callback); },
      onPresenceUpdate: function (callback) { return on('chat_presence_update', callback); },
      onMessageRequest: function (callback) { return on('chat_message_request', callback); },
    },

    // ── Threat Feed ──
    threatfeed: {
      listFeeds: function () {
        return invoke('get_threat_feeds', {}).then(function (v) {
          return Array.isArray(v) ? v : (v && v.feeds ? v.feeds : []);
        });
      },
      addFeed: function (feed) {
        return invoke('threatfeed_add', feed);
      },
      updateFeed: function (feedId, updates) {
        return invoke('threatfeed_update', { feedId: feedId, updates: updates });
      },
      deleteFeed: function (feedId) {
        return invoke('threatfeed_delete', { feedId: feedId });
      },
      toggleFeed: function (feedId, enabled) {
        return invoke('threatfeed_toggle', { feedId: feedId, enabled: enabled });
      },
      discover: function (serverUrl, auth) {
        return invoke('threatfeed_discover', { serverUrl: serverUrl, auth: auth });
      },
      getCollections: function (feedId) {
        return invoke('threatfeed_collections', { feedId: feedId }).then(function (v) {
          return Array.isArray(v) ? v : (v && v.collections ? v.collections : []);
        });
      },
      syncFeed: function (feedId) {
        return invoke('threatfeed_sync', { feedId: feedId });
      },
      syncAll: function () {
        return invoke('threatfeed_sync_all', {});
      },
      getMatches: function (sessionId) {
        return invoke('threatfeed_matches', { sessionId: sessionId }).then(function (v) {
          return Array.isArray(v) ? v : (v && v.matches ? v.matches : []);
        });
      },
      importCSV: function (data) {
        return invoke('threatfeed_import_csv', { data: data });
      },
      importSTIX: function (data) {
        return invoke('threatfeed_import_stix', { data: data });
      },
      getStats: function () {
        return invoke('threatfeed_stats', {});
      },
      onMatch: function (callback) { return on('threatfeed_match', callback); },
      onSyncStatus: function (callback) { return on('threatfeed_sync_status', callback); },
    },

    // ── Clipboard ──
    clipboard: {
      writeText: function (text) {
        return navigator.clipboard.writeText(text).then(function () {
          return { success: true };
        });
      },
      readText: function () {
        return navigator.clipboard.readText();
      },
    },

    // ── VM Sandbox ──
    vm: {
      getQEMUStatus: function () {
        return invoke('vm_get_status', {});
      },
      installQEMU: function () {
        return invoke('vm_install', {});
      },
      listImages: function () {
        return invoke('vm_list_images', {}).then(function (v) {
          return Array.isArray(v) ? v : (v && v.images ? v.images : []);
        });
      },
      downloadImage: function (imageId) {
        return invoke('vm_download_image', { imageId: imageId });
      },
      spawnVM: function (sessionId, fileId, config) {
        return invoke('start_vm', { sessionId: sessionId, fileId: fileId, config: config });
      },
      killVM: function (instanceId) {
        return invoke('stop_vm', { instanceId: instanceId });
      },
      getInstances: function () {
        return invoke('vm_get_instances', {}).then(function (v) {
          return Array.isArray(v) ? v : (v && v.instances ? v.instances : []);
        });
      },
      getResult: function (instanceId) {
        return invoke('vm_get_result', { instanceId: instanceId });
      },
      hasSnapshot: function (imageId) {
        return invoke('vm_has_snapshot', { imageId: imageId });
      },
      prepareSnapshot: function (imageId) {
        return invoke('vm_prepare_snapshot', { imageId: imageId });
      },
      getCACertPEM: function () {
        return invoke('vm_get_ca_cert', {});
      },
      buildAgent: function (platform) {
        return invoke('vm_build_agent', { platform: platform });
      },
      getAgentStatus: function () {
        return invoke('vm_get_agent_status', {});
      },

      focusSandboxWindow: function () {
        return invoke('wsb_focus_window', {});
      },

      onStatus: function (callback) { return on('vm_status', callback); },
      onWsbRunning: function (callback) { return on('wsb_running', callback); },
      onInstallProgress: function (callback) { return on('vm_install_progress', callback); },
      onImageDownloadProgress: function (callback) { return on('vm_image_download_progress', callback); },
      onSnapshotProgress: function (callback) { return on('vm_snapshot_progress', callback); },
      onScreenshot: function (callback) { return on('vm_screenshot', callback); },
    },

    // ── Log Analysis ──
    loganalysis: {
      analyzeFile: function (sessionId, filePath, opts) {
        return invoke('analyze_logs', { sessionId: sessionId, filePath: filePath, opts: opts });
      },
      getResults: function (sessionId) {
        return invoke('get_log_results', { sessionId: sessionId }).then(function (v) {
          return Array.isArray(v) ? v : [];
        });
      },
      getResult: function (sessionId, resultId) {
        return invoke('get_log_result', { sessionId: sessionId, resultId: resultId });
      },
      deleteResult: function (sessionId, resultId) {
        return invoke('delete_log_result', { sessionId: sessionId, resultId: resultId });
      },
      getFormats: function () {
        return invoke('get_log_formats', {}).then(function (v) {
          return Array.isArray(v) ? v : (v && v.formats ? v.formats : []);
        });
      },
      openFile: function (sessionId) {
        return invoke('open_log_file', { sessionId: sessionId });
      },
      onComplete: function (callback) {
        return on('log_complete', function (data) {
          // C++ emits {id, result: LogAnalysisResult} — unwrap
          var result = (data && data.result && typeof data.result === 'object') ? data.result : data;
          callback(activeSessionId(data), result);
        });
      },
      onProgress: function (callback) {
        return on('log_progress', function (data) {
          callback(activeSessionId(data), data);
        });
      },
    },

    // ── URL Chain Investigation ──
    urlchain: {
      investigate: function (sessionId, url) {
        return invoke('investigate_url', { sessionId: sessionId, url: url });
      },
      getChains: function () {
        return invoke('get_url_chains', {}).then(function (v) {
          return Array.isArray(v) ? v : [];
        });
      },
      onUpdate: function (callback) {
        return on('url_chain_update', function (data) {
          callback(activeSessionId(data), data);
        });
      },
    },

    // ── App Info ──
    getAppInfo: function () {
      return invoke('get_app_info', {});
    },

    // ── Feedback ──
    submitFeedback: function (type, message, email, rating) {
      return invoke('submit_feedback', { type: type, message: message, email: email, rating: rating });
    },

    // ── Auto-updater ──
    update: {
      check: function () {
        return invoke('check_update', {}).then(function (v) {
          return v || { status: 'not-available', currentVersion: '2.0.0' };
        });
      },
      download: function () { return Promise.resolve({ success: true }); },
      install: function () { return Promise.resolve({ success: true }); },
      getState: function () {
        return invoke('check_update', {}).catch(function () {
          return { status: 'idle', currentVersion: '2.0.0', availableVersion: null, downloadProgress: 0, error: null };
        });
      },
      onStatus: function () { return function () {}; },
    },

    // ── Platform ──
    platform: (function () {
      var ua = navigator.userAgent.toLowerCase();
      if (ua.indexOf('mac') !== -1) return 'darwin';
      if (ua.indexOf('win') !== -1) return 'win32';
      return 'linux';
    })(),
  };

  // ── C++ enrichment_result → _iocStore sync ──────────────────────────
  // When C++ pushes enrichment_result events (PDF URIs, email URLs, etc.),
  // also register them in the shim's _iocStore so getResults() returns them.
  on('enrichment_result', function (data) {
    if (!data || !data.value) return;
    var sid = activeSessionId(data);
    if (!sid) return;
    var norm = data.value.toLowerCase();
    if (!_iocStore[sid]) _iocStore[sid] = {};
    var store = _iocStore[sid];
    if (store[norm]) return; // Already registered
    _iocSeenGlobal[norm] = true;
    store[norm] = {
      value: data.value,
      type: data.type || detectIOCType(data.value) || 'url',
      source: data.source || 'analysis',
      firstSeen: data.firstSeen || Date.now(),
      results: data.results || [],
      status: data.status || 'pending',
      safe: !!data.safe,
      domain: data.domain || ''
    };
  });

  // ── Server IP auto-registration ──────────────────────────────────────
  // C++ pushes 'server_ip' events from CDP Network.responseReceived
  on('server_ip', function (data) {
    if (!data || !data.ip) return;
    var sid = activeSessionId(data);
    var ip = data.ip.trim();
    if (!ip) return;
    // IPv6 parked — only register IPv4 addresses
    if (!isValidIPv4(ip)) return;
    var priv = isPrivateIP(ip);
    _iocAdd(sid, ip, 'ip', 'server_address', priv, '');
  });

  console.log('[ShieldTier] Preload shim initialized (CEF bridge)');
})();
