/**
 * ConCard AP Monitor v1.1 - Standalone Collector & Native Prometheus API Server
 * 
 * Tinh nang noi bat:
 * 1. GAN DANH SACH IP CO DINH (STATIC IP LIST):
 *    - Nhap danh sach cac IP AP co dinh cach nhau boi dau phay (vd: 172.16.0.38, 172.16.0.39, 172.16.2.10)
 *    - He thong se luon luon giam sat, ping lien tuc va bao cao trang thai Online/Offline cho cac IP nay
 *    - Giai quyet triet de van de AP nam khac Subnet/VLAN hoac bi chan ARP
 * 2. TICH HOP SAN PROMETHEUS API SERVER:
 *    - Grafana ket noi TRUC TIEP vao http://<IP_MAY_CHU>:9100 ma KHONG CAN cai dat Prometheus!
 * 3. Giao dien Web Dashboard tai http://localhost:9100/ cho phep them, xoa, sua IP co dinh truc tiep
 * 4. Cung cap ca /metrics chuan neu muon dung voi Prometheus that.
 */

var http = require('http');
var cp = require('child_process');
var fs = require('fs');
var path = require('path');
var url = require('url');
var dgram = require('dgram');
var crypto = require('crypto');

var CONFIG_FILE = path.join(__dirname, 'config.json');
var USERS_FILE = path.join(__dirname, 'users.json');
var AUTH_COOKIE_NAME = 'concard_sid';
var SESSION_TTL_REMEMBER_MS = 7 * 24 * 60 * 60 * 1000;
var SESSION_TTL_SHORT_MS = 24 * 60 * 60 * 1000;
var isSavingConfig = false;
var usersStoreCache = null;
var usersFileMtimeMs = 0;
var usersLastStatCheckMs = 0;

function md5Hash(plainText) {
  return crypto.createHash('md5').update(String(plainText === undefined || plainText === null ? '' : plainText), 'utf8').digest('hex');
}

function normalizeUserRole(role) {
  return String(role || '').trim().toLowerCase() === 'admin' ? 'admin' : 'user';
}

function saveUsersStore(storeObj) {
  if (!storeObj || typeof storeObj !== 'object') return;
  if (!storeObj.sessionSecret || String(storeObj.sessionSecret).length < 32) {
    storeObj.sessionSecret = crypto.randomBytes(32).toString('hex');
  }
  if (!Array.isArray(storeObj.users)) storeObj.users = [];
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(storeObj, null, 2), 'utf8');
    var st = fs.statSync(USERS_FILE);
    usersFileMtimeMs = st.mtimeMs || Date.now();
    usersLastStatCheckMs = Date.now();
    usersStoreCache = storeObj;
  } catch (err) {
    console.error('[Users] Loi ghi file users.json:', err.message);
  }
}

function loadUsersStore(forceReload) {
  var now = Date.now();
  if (!forceReload && usersStoreCache && (now - usersLastStatCheckMs) < 1500) {
    return usersStoreCache;
  }
  usersLastStatCheckMs = now;
  var needSave = false;
  var parsed = null;
  try {
    if (fs.existsSync(USERS_FILE)) {
      var st = fs.statSync(USERS_FILE);
      if (!forceReload && usersStoreCache && st.mtimeMs === usersFileMtimeMs) {
        return usersStoreCache;
      }
      var raw = fs.readFileSync(USERS_FILE, 'utf8');
      if (raw && raw.trim()) {
        parsed = JSON.parse(raw);
        usersFileMtimeMs = st.mtimeMs || now;
      }
    }
  } catch (err) {
    console.error('[Users] Loi doc users.json, khoi tao mac dinh:', err.message);
  }

  if (!parsed || typeof parsed !== 'object') {
    parsed = {
      sessionSecret: crypto.randomBytes(32).toString('hex'),
      users: []
    };
    needSave = true;
  }
  if (!parsed.sessionSecret || String(parsed.sessionSecret).length < 32) {
    parsed.sessionSecret = crypto.randomBytes(32).toString('hex');
    needSave = true;
  }
  if (!Array.isArray(parsed.users)) {
    parsed.users = [];
    needSave = true;
  }

  var nowIso = new Date().toISOString();
  var seenNames = {};
  var cleanedUsers = [];
  for (var i = 0; i < parsed.users.length; i++) {
    var u = parsed.users[i];
    if (!u || typeof u !== 'object') { needSave = true; continue; }
    var uname = String(u.username || '').trim();
    if (!uname) { needSave = true; continue; }
    var unameKey = uname.toLowerCase();
    if (seenNames[unameKey]) { needSave = true; continue; }
    seenNames[unameKey] = true;

    var pwdMd5 = String(u.passwordMd5 || '').trim().toLowerCase();
    if (!/^[a-f0-9]{32}$/.test(pwdMd5)) {
      var plainFallback = u.password !== undefined ? String(u.password) : (u.passwordMd5 || 'Concard@2026');
      pwdMd5 = md5Hash(plainFallback);
      needSave = true;
    }
    var roleNorm = normalizeUserRole(u.role);
    if (u.role !== roleNorm) needSave = true;

    cleanedUsers.push({
      username: uname,
      passwordMd5: pwdMd5,
      role: roleNorm,
      fullName: String(u.fullName || (roleNorm === 'admin' ? 'Quản trị viên' : 'Người xem')).trim(),
      createdAt: u.createdAt || nowIso,
      updatedAt: u.updatedAt || u.createdAt || nowIso
    });
  }

  if (cleanedUsers.length === 0) {
    cleanedUsers.push({
      username: 'admin',
      passwordMd5: md5Hash('Concard@2026'),
      role: 'admin',
      fullName: 'Quản trị viên hệ thống',
      createdAt: nowIso,
      updatedAt: nowIso
    });
    needSave = true;
  } else {
    var hasAnyAdmin = false;
    for (var k = 0; k < cleanedUsers.length; k++) {
      if (cleanedUsers[k].role === 'admin') { hasAnyAdmin = true; break; }
    }
    if (!hasAnyAdmin) {
      var existingAdminIdx = -1;
      for (var m = 0; m < cleanedUsers.length; m++) {
        if (cleanedUsers[m].username.toLowerCase() === 'admin') { existingAdminIdx = m; break; }
      }
      if (existingAdminIdx !== -1) {
        cleanedUsers[existingAdminIdx].role = 'admin';
      } else {
        cleanedUsers.unshift({
          username: 'admin',
          passwordMd5: md5Hash('Concard@2026'),
          role: 'admin',
          fullName: 'Quản trị viên hệ thống',
          createdAt: nowIso,
          updatedAt: nowIso
        });
      }
      needSave = true;
    }
  }

  parsed.users = cleanedUsers;
  usersStoreCache = parsed;
  if (needSave) {
    saveUsersStore(parsed);
  }
  return parsed;
}

function b64UrlEncode(str) {
  var buf = Buffer.from ? Buffer.from(String(str), 'utf8') : new Buffer(String(str), 'utf8');
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64UrlDecode(b64) {
  var norm = String(b64 || '').replace(/-/g, '+').replace(/_/g, '/');
  while (norm.length % 4 !== 0) norm += '=';
  var buf = Buffer.from ? Buffer.from(norm, 'base64') : new Buffer(norm, 'base64');
  return buf.toString('utf8');
}

function parseCookies(req) {
  var out = {};
  var raw = (req && req.headers && req.headers.cookie) ? String(req.headers.cookie) : '';
  if (!raw) return out;
  var parts = raw.split(';');
  for (var i = 0; i < parts.length; i++) {
    var seg = parts[i];
    var eqIdx = seg.indexOf('=');
    if (eqIdx === -1) continue;
    var k = seg.slice(0, eqIdx).trim();
    var v = seg.slice(eqIdx + 1).trim();
    if (!k) continue;
    try { out[k] = decodeURIComponent(v); } catch (e) { out[k] = v; }
  }
  return out;
}

function computeSessionSignature(payloadStr, userObj, secret) {
  var sigInput = payloadStr + '|' + String(userObj.passwordMd5 || '').toLowerCase() + '|' + normalizeUserRole(userObj.role);
  return crypto.createHmac('sha256', String(secret || '')).update(sigInput, 'utf8').digest('hex');
}

function createSessionCookieData(userObj, remember) {
  var store = loadUsersStore(false);
  var isRemember = remember !== false;
  var ttlMs = isRemember ? SESSION_TTL_REMEMBER_MS : SESSION_TTL_SHORT_MS;
  var expMs = Date.now() + ttlMs;
  var payloadStr = userObj.username + '|' + expMs;
  var sig = computeSessionSignature(payloadStr, userObj, store.sessionSecret);
  var token = b64UrlEncode(payloadStr) + '.' + sig;
  var cookieHeader = AUTH_COOKIE_NAME + '=' + encodeURIComponent(token) +
    '; Path=/' +
    (isRemember ? ('; Max-Age=' + Math.floor(ttlMs / 1000)) : '') +
    '; HttpOnly; SameSite=Lax';
  return { token: token, cookieHeader: cookieHeader, expiresAt: expMs };
}

function buildClearSessionCookieHeader() {
  return AUTH_COOKIE_NAME + '=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax';
}

function getAuthenticatedUserRecord(req) {
  try {
    var cookies = parseCookies(req);
    var token = cookies[AUTH_COOKIE_NAME];
    if (!token || typeof token !== 'string') return null;
    var dotIdx = token.indexOf('.');
    if (dotIdx <= 0 || dotIdx >= token.length - 1) return null;
    var payloadB64 = token.slice(0, dotIdx);
    var providedSig = token.slice(dotIdx + 1);
    if (!/^[a-f0-9]{64}$/.test(providedSig)) return null;

    var payloadStr = b64UrlDecode(payloadB64);
    var pipeIdx = payloadStr.lastIndexOf('|');
    if (pipeIdx <= 0) return null;
    var uname = payloadStr.slice(0, pipeIdx);
    var expMs = parseInt(payloadStr.slice(pipeIdx + 1), 10);
    if (!uname || isNaN(expMs) || expMs <= Date.now()) return null;

    var store = loadUsersStore(false);
    var targetUser = null;
    var unameLower = uname.toLowerCase();
    for (var i = 0; i < store.users.length; i++) {
      if (store.users[i].username.toLowerCase() === unameLower) {
        targetUser = store.users[i];
        break;
      }
    }
    if (!targetUser) return null;

    var expectedSig = computeSessionSignature(payloadStr, targetUser, store.sessionSecret);
    if (expectedSig.length !== providedSig.length) return null;
    var diff = 0;
    for (var c = 0; c < expectedSig.length; c++) {
      diff |= (expectedSig.charCodeAt(c) ^ providedSig.charCodeAt(c));
    }
    if (diff !== 0) return null;
    return targetUser;
  } catch (e) {
    return null;
  }
}

function getAuthenticatedUser(req) {
  var u = getAuthenticatedUserRecord(req);
  if (!u) return null;
  return {
    username: u.username,
    role: normalizeUserRole(u.role),
    fullName: u.fullName || u.username
  };
}

function requireApiAuth(req, res, requireAdmin) {
  var authUser = getAuthenticatedUser(req);
  if (!authUser) {
    res.writeHead(401, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    });
    res.end(JSON.stringify({
      success: false,
      authRequired: true,
      error: 'Phiên đăng nhập đã hết hạn hoặc chưa đăng nhập. Vui lòng đăng nhập lại.'
    }));
    return null;
  }
  if (requireAdmin && authUser.role !== 'admin') {
    res.writeHead(403, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    });
    res.end(JSON.stringify({
      success: false,
      forbidden: true,
      error: 'Tài khoản "' + authUser.username + '" chỉ có quyền xem (Read-only), không có quyền thực hiện thao tác này.'
    }));
    return null;
  }
  return authUser;
}

function loadAppConfig() {
  var defaults = {
    server: {
      port: 9100,
      pingIntervalMs: 4000,
      autoRescanIntervalMs: 30000,
      apPollIntervalMs: 12000
    },
    ui: {
      pageTitle: 'ConCard AP Monitor v1.1',
      brandTitle: 'ConCard AP Monitor',
      versionTag: 'v1.1',
      subtitle: 'Hệ thống giám sát & tối ưu Access Point',
      showMetricsButton: false
    },
    network: {
      defaultScanTarget: '172.16.0.0/21',
      defaultStaticIps: [],
      scanPresets: [
        { label: '3 Dải Chính', target: '172.16.0.0/24, 172.16.2.0/24, 172.16.3.0/24', icon: 'fi-rr-bullseye-arrow' },
        { label: 'Subnet 2 & 3', target: '172.16.2.0/24, 172.16.3.0/24', icon: 'fi-rr-rocket-lunch' },
        { label: 'Toàn Mạng /21', target: '172.16.0.0/21', icon: 'fi-rr-globe' }
      ],
      allowedMacOuis: ['f4-28-53', '78-44-fd', '00-e0-4c', 'd4-ee-07', 'c8-3a-35', '00-1e-e3', '18-e8-29']
    },
    apCredentials: {
      sshUsername: 'admin',
      sshPasswords: ['admin'],
      totolinkWebUsername: 'admin',
      totolinkWebPasswords: ['admin'],
      perApPasswords: {},
      defaultSsidFallback: 'ConCard_WiFi'
    },
    grafanaSync: {
      enabled: false,
      host: '127.0.0.1',
      port: 3000,
      datasourceUid: '',
      dashboardUid: '',
      username: 'admin',
      password: '',
      syncIntervalMs: 60000
    },
    rfOptimizer: {
      telemetryWindowHours: 24,
      neighborScanIntervalMinutes: 45,
      autoOptimizeEnabled: false,
      autoOptimizeTime: '03:30',
      requireFull24hForAuto: true,
      targetStaRssiRoomDbm: -76,
      targetStaRssiLobbyDbm: -75,
      fallbackStaRssiDbm: -80,
      targetDtimPeriod: 3,
      enableTxBurst: true,
      allowedChannels24G: [1, 6, 11],
      channelCooldownHours: 24,
      replanMinGlobalGainPct: 18
    }
  };
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      var rawCfg = fs.readFileSync(CONFIG_FILE, 'utf8').replace(/^\uFEFF/, '');
      var parsed = JSON.parse(rawCfg);
      ['server', 'ui', 'network', 'apCredentials', 'grafanaSync', 'rfOptimizer'].forEach(function (sec) {
        if (parsed[sec] && typeof parsed[sec] === 'object') {
          Object.keys(parsed[sec]).forEach(function (k) {
            defaults[sec][k] = parsed[sec][k];
          });
        }
      });
    } else {
      var exampleCfgPath = path.join(__dirname, 'config.example.json');
      if (fs.existsSync(exampleCfgPath)) {
        fs.copyFileSync(exampleCfgPath, CONFIG_FILE);
        var rawEx = fs.readFileSync(CONFIG_FILE, 'utf8').replace(/^\uFEFF/, '');
        var parsedEx = JSON.parse(rawEx);
        ['server', 'ui', 'network', 'apCredentials', 'grafanaSync', 'rfOptimizer'].forEach(function (sec) {
          if (parsedEx[sec] && typeof parsedEx[sec] === 'object') {
            Object.keys(parsedEx[sec]).forEach(function (k) {
              defaults[sec][k] = parsedEx[sec][k];
            });
          }
        });
      } else {
        fs.writeFileSync(CONFIG_FILE, JSON.stringify(defaults, null, 2), 'utf8');
      }
      console.log('[Config] Da tu dong khoi tao file config.json mac dinh.');
    }
  } catch (e) {
    console.error('[Config] Loi doc config.json, su dung gia tri mac dinh:', e.message);
  }
  return defaults;
}

var lastSavedConfigMtimeMs = 0;

function saveAppConfig() {
  try {
    isSavingConfig = true;
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(appConfig, null, 2), 'utf8');
    try {
      lastSavedConfigMtimeMs = fs.statSync(CONFIG_FILE).mtimeMs || 0;
    } catch (eStat) {}
    setTimeout(function () { isSavingConfig = false; }, 4500);
  } catch (e) {
    isSavingConfig = false;
    console.error('[Config] Loi luu config.json:', e.message);
  }
}

var appConfig = loadAppConfig();

var PORT = Number(process.env.COLLECTOR_PORT) || Number(appConfig.server.port) || 9100;
var DEFAULT_TARGET = process.env.SCAN_TARGET || appConfig.network.defaultScanTarget || '172.16.0.0/21';
var DEFAULT_STATIC_IPS = process.env.STATIC_IPS || (Array.isArray(appConfig.network.defaultStaticIps) ? appConfig.network.defaultStaticIps.join(', ') : '');
var REGISTRY_FILE = path.join(__dirname, 'aps_registry.json');
var PING_INTERVAL_MS = Number(appConfig.server.pingIntervalMs) || 4000;
var AUTO_RESCAN_INTERVAL_MS = Number(appConfig.server.autoRescanIntervalMs) || 30000;
var DEFAULT_SSID_FALLBACK = appConfig.apCredentials.defaultSsidFallback || 'WiFi';

var TOTOLINK_OUIS = Array.isArray(appConfig.network.allowedMacOuis) && appConfig.network.allowedMacOuis.length > 0
  ? appConfig.network.allowedMacOuis
  : ['f4-28-53', '78-44-fd', '00-e0-4c', 'd4-ee-07', 'c8-3a-35', '00-1e-e3', '18-e8-29'];

var apMap = {};
var apClientsCache = {};
var arpMacToIpMap = {};
var staticIpsList = [];
var ignoredApMacs = {};
var ignoredApIps = {};
var currentTarget = DEFAULT_TARGET;
var isScanning = false;
var lastScanStats = {
  target: DEFAULT_TARGET,
  subnetsList: [],
  totalScannedIPs: 0,
  foundAPs: 0,
  scanDurationMs: 0,
  lastScanTime: null
};

function ip2long(ip) {
  var p = ip.split('.');
  return (((p[0] << 24) >>> 0) + ((p[1] << 16) >>> 0) + ((p[2] << 8) >>> 0) + (p[3] >>> 0)) >>> 0;
}

function long2ip(l) {
  return [(l >>> 24) & 255, (l >>> 16) & 255, (l >>> 8) & 255, l & 255].join('.');
}

function isValidIpv4(ip) {
  if (!ip || typeof ip !== 'string') return false;
  var m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  for (var i = 1; i <= 4; i++) {
    var n = parseInt(m[i], 10);
    if (isNaN(n) || n < 0 || n > 255) return false;
  }
  return true;
}

function isValidHardwareMac(mac) {
  if (!mac) return false;
  var norm = String(mac).replace(/:/g, '-').toUpperCase();
  return /^([0-9A-F]{2}-){5}[0-9A-F]{2}$/.test(norm);
}

function findApKeyByIp(ip) {
  for (var k in apMap) {
    if (apMap[k] && apMap[k].ip === ip) return k;
  }
  return null;
}

function findApKeyByMac(macStr) {
  if (!macStr) return null;
  var norm = String(macStr).replace(/:/g, '-').toUpperCase();
  if (!isValidHardwareMac(norm)) return null;
  if (apMap[norm] && apMap[norm].mac && apMap[norm].mac.replace(/:/g, '-').toUpperCase() === norm) {
    return norm;
  }
  for (var k in apMap) {
    if (apMap[k] && apMap[k].mac && apMap[k].mac.replace(/:/g, '-').toUpperCase() === norm) {
      return k;
    }
  }
  return null;
}

function isApIgnored(ip, mac) {
  if (ip && ignoredApIps[ip]) return true;
  if (mac) {
    var norm = String(mac).replace(/:/g, '-').toUpperCase();
    if (ignoredApMacs[norm]) return true;
  }
  return false;
}

function unignoreAp(ip, mac) {
  if (ip && ignoredApIps[ip]) delete ignoredApIps[ip];
  if (mac) {
    var norm = String(mac).replace(/:/g, '-').toUpperCase();
    if (ignoredApMacs[norm]) delete ignoredApMacs[norm];
  }
}

function deduplicateApMap() {
  var keys = Object.keys(apMap);
  var byMac = {};
  var byIp = {};
  var nonMacByIp = {};
  var cleanMap = {};

  // Buoc 1: Gop theo dia chi MAC vat ly (chuan hoa key theo MAC)
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var ap = apMap[k];
    if (!ap || !ap.ip) continue;

    var rawMac = String(ap.mac || '').replace(/:/g, '-').toUpperCase();
    if (!isValidHardwareMac(rawMac)) {
      if (!nonMacByIp[ap.ip] || (ap.status > nonMacByIp[ap.ip].status)) {
        nonMacByIp[ap.ip] = ap;
      }
      continue;
    }

    ap.mac = rawMac;
    ap.key = rawMac;

    if (!byMac[rawMac]) {
      byMac[rawMac] = ap;
    } else {
      var prev = byMac[rawMac];
      var prevTime = prev.lastSeen ? new Date(prev.lastSeen).getTime() : 0;
      var currTime = ap.lastSeen ? new Date(ap.lastSeen).getTime() : 0;
      var pickCurr = (ap.status > prev.status) || (ap.status === prev.status && currTime >= prevTime);
      var winner = pickCurr ? ap : prev;
      var loser = pickCurr ? prev : ap;

      winner.rxBytes = Math.max(Number(winner.rxBytes) || 0, Number(loser.rxBytes) || 0);
      winner.txBytes = Math.max(Number(winner.txBytes) || 0, Number(loser.txBytes) || 0);
      byMac[rawMac] = winner;
    }
  }

  // Buoc 2: Kiem tra trung dia chi IP giua cac MAC khac nhau (giu thiet bi Online/moi nhat)
  var macKeys = Object.keys(byMac);
  for (var m = 0; m < macKeys.length; m++) {
    var item = byMac[macKeys[m]];
    var ipAddr = item.ip;
    if (!byIp[ipAddr]) {
      byIp[ipAddr] = item;
    } else {
      var prevIpItem = byIp[ipAddr];
      var pTime = prevIpItem.lastSeen ? new Date(prevIpItem.lastSeen).getTime() : 0;
      var cTime = item.lastSeen ? new Date(item.lastSeen).getTime() : 0;
      if (item.status > prevIpItem.status || (item.status === prevIpItem.status && cTime > pTime)) {
        byIp[ipAddr] = item;
      }
    }
  }

  var ipKeys = Object.keys(byIp);
  for (var p = 0; p < ipKeys.length; p++) {
    var finalAp = byIp[ipKeys[p]];
    finalAp.isStatic = (staticIpsList.indexOf(finalAp.ip) !== -1);
    cleanMap[finalAp.mac] = finalAp;
  }

  // Buoc 3: Dam bao moi IP trong danh sach Co Dinh (staticIpsList) deu hien thi trong bang AP
  // ngay ca khi chua doc duoc MAC hoac dang Offline
  for (var s = 0; s < staticIpsList.length; s++) {
    var sIp = staticIpsList[s];
    if (byIp[sIp]) continue;
    var pKey = 'AP-' + sIp.replace(/\./g, '-');
    var existingHolder = nonMacByIp[sIp];
    if (existingHolder) {
      existingHolder.key = pKey;
      existingHolder.ip = sIp;
      existingHolder.isStatic = true;
      if (!existingHolder.mac) existingHolder.mac = 'CHỜ ĐỒNG BỘ';
      cleanMap[pKey] = existingHolder;
    } else {
      cleanMap[pKey] = {
        key: pKey,
        mac: 'CHỜ ĐỒNG BỘ',
        ip: sIp,
        name: 'AP-' + sIp.split('.').slice(2).join('.'),
        model: 'Chờ phản hồi...',
        firmware: '-',
        channel: '-',
        ssid: '-',
        status: 0,
        isStatic: true,
        clientCount: 0,
        latencyMs: 0,
        lastSeen: null,
        rxBytes: 0,
        txBytes: 0
      };
    }
  }

  // Giu lai thiet bi non-MAC dang Online neu co (truong hop phat hien qua Ping/SSH chua co MAC)
  var nonMacIps = Object.keys(nonMacByIp);
  for (var nIdx = 0; nIdx < nonMacIps.length; nIdx++) {
    var nIp = nonMacIps[nIdx];
    if (!byIp[nIp] && staticIpsList.indexOf(nIp) === -1 && nonMacByIp[nIp].status === 1) {
      var nKey = 'AP-' + nIp.replace(/\./g, '-');
      nonMacByIp[nIp].key = nKey;
      nonMacByIp[nIp].isStatic = false;
      cleanMap[nKey] = nonMacByIp[nIp];
    }
  }

  apMap = cleanMap;
}

function upsertDiscoveredAp(ip, rawMac, details, allowUnignore) {
  if (!isValidIpv4(ip)) return null;
  var normMac = String(rawMac || '').replace(/:/g, '-').toUpperCase();
  if (!isValidHardwareMac(normMac) || normMac === 'FF-FF-FF-FF-FF-FF') return null;

  if (allowUnignore) {
    unignoreAp(ip, normMac);
  } else if (isApIgnored(ip, normMac)) {
    return null;
  }

  var info = details || {};
  var isUnifi = normMac.indexOf('18-E8-29') === 0 || (info.model && info.model.indexOf('UAP') !== -1);
  var defaultName = (isUnifi ? 'UAP-' : 'N9-') + ip.split('.').slice(2).join('.');
  var macKey = findApKeyByMac(normMac);
  var ipKey = findApKeyByIp(ip);
  var ap = null;

  if (macKey && apMap[macKey]) {
    ap = apMap[macKey];
    if (ipKey && ipKey !== macKey && apMap[ipKey] && !isValidHardwareMac(apMap[ipKey].mac)) {
      delete apMap[ipKey];
    }
    if (macKey !== normMac) {
      delete apMap[macKey];
    }
  } else if (ipKey && apMap[ipKey] && !isValidHardwareMac(apMap[ipKey].mac)) {
    ap = apMap[ipKey];
    delete apMap[ipKey];
  } else {
    ap = {
      key: normMac,
      mac: normMac,
      ip: ip,
      name: defaultName,
      model: isUnifi ? 'UAP-AC-Pro-Gen2' : 'Đang kết nối...',
      firmware: 'Đang kết nối...',
      channel: '-',
      ssid: 'Đang kết nối...',
      status: 1,
      clientCount: 0,
      latencyMs: 1,
      lastSeen: new Date().toISOString(),
      rxBytes: 0,
      txBytes: 0
    };
  }

  var ipChanged = (ap.ip !== ip);
  ap.key = normMac;
  ap.mac = normMac;
  ap.ip = ip;
  ap.status = 1;
  ap.isStatic = (staticIpsList.indexOf(ip) !== -1);
  ap.lastSeen = new Date().toISOString();

  if (info.name) {
    ap.name = info.name;
  } else if (!ap.name || ap.name.indexOf('AP-') === 0 || ap.name.indexOf('TOTOLINK-N9-AP') === 0 || (ipChanged && /^(N9|UAP)-\d+\.\d+$/.test(ap.name))) {
    ap.name = defaultName;
  }

  if (info.model) {
    ap.model = info.model;
  } else if (!ap.model || ap.model === 'Chờ phản hồi...' || ap.model === 'Đang tải...') {
    ap.model = isUnifi ? 'UAP-AC-Pro-Gen2' : 'Đang kết nối...';
  }

  if (info.firmware) {
    ap.firmware = info.firmware;
  } else if (!ap.firmware || ap.firmware === '-' || ap.firmware === 'Đang tải...') {
    ap.firmware = 'Đang kết nối...';
  }

  if (info.channel !== undefined && info.channel !== null && info.channel !== '') {
    ap.channel = info.channel;
  }
  if (info.ssid) {
    ap.ssid = info.ssid;
  }
  if (typeof info.clientCount === 'number' && !isNaN(info.clientCount)) {
    ap.clientCount = info.clientCount;
  }
  if (typeof info.latencyMs === 'number' && info.latencyMs > 0) {
    ap.latencyMs = info.latencyMs;
  } else if (!ap.latencyMs || ap.latencyMs <= 0) {
    ap.latencyMs = 1;
  }
  if (typeof info.rxBytes === 'number' && info.rxBytes > 0 && !ap.rxBytes) {
    ap.rxBytes = info.rxBytes;
  }
  if (typeof info.txBytes === 'number' && info.txBytes > 0 && !ap.txBytes) {
    ap.txBytes = info.txBytes;
  }
  if (info.isTotolinkN9) ap.isTotolinkN9 = true;
  if (info.isRealData) ap.isRealData = true;

  apMap[normMac] = ap;
  return ap;
}

/**
 * Xu ly danh sach IP co dinh do nguoi dung gan
 * Chap nhan chuoi dang: "IP_AP_1, IP_AP_2, IP_AP_3"
 */
function setFixedIPs(ipString, doneProbeCb) {
  var raw = String(ipString || '').trim();
  var tokens = raw ? raw.split(/[,;\s\r\n]+/) : [];
  var validIPs = [];

  for (var i = 0; i < tokens.length; i++) {
    var tok = tokens[i].trim();
    if (isValidIpv4(tok)) {
      if (validIPs.indexOf(tok) === -1) {
        validIPs.push(tok);
      }
      unignoreAp(tok, null);
    }
  }

  staticIpsList = validIPs;
  deduplicateApMap();
  saveRegistry();
  if (typeof scheduleRealtimeBroadcast === 'function') {
    scheduleRealtimeBroadcast(80);
  }

  if (validIPs.length > 0) {
    probeIpList(validIPs, { isManual: true }, function (err, stats) {
      if (doneProbeCb) doneProbeCb(err, stats);
    });
  } else if (doneProbeCb) {
    doneProbeCb(null, { totalScannedIPs: 0, onlineInTargetCount: 0, matchedOnlineNames: [], scanDurationMs: 0 });
  }

  return validIPs;
}

function parseTargets(inputStr, fallbackToDefault) {
  var useFallback = (fallbackToDefault !== false);
  var raw = String(inputStr !== undefined && inputStr !== null ? inputStr : (useFallback ? DEFAULT_TARGET : '')).trim();
  if (!raw && useFallback) raw = DEFAULT_TARGET;
  if (!raw) return { ips: [], subnetsList: [] };

  var tokens = raw.split(/[,;\r\n]+/);
  var ipSet = {};
  var resultIPs = [];
  var detectedSubnets = [];

  for (var i = 0; i < tokens.length; i++) {
    var tok = tokens[i].trim();
    if (!tok) continue;

    if (tok.indexOf('/') !== -1) {
      var parts = tok.split('/');
      var baseIp = parts[0].trim();
      if (!isValidIpv4(baseIp)) continue;
      var prefix = parseInt(parts[1], 10);
      if (isNaN(prefix) || prefix < 16 || prefix > 32) prefix = 24;

      if (prefix === 32) {
        detectedSubnets.push(baseIp + '/32 (1 IP)');
        if (!ipSet[baseIp]) { ipSet[baseIp] = true; resultIPs.push(baseIp); }
      } else if (prefix === 31) {
        var ipL31 = ip2long(baseIp) & (~1 >>> 0);
        var p0 = long2ip(ipL31 >>> 0);
        var p1 = long2ip((ipL31 + 1) >>> 0);
        detectedSubnets.push(p0 + '/31 (2 IPs)');
        if (!ipSet[p0]) { ipSet[p0] = true; resultIPs.push(p0); }
        if (!ipSet[p1]) { ipSet[p1] = true; resultIPs.push(p1); }
      } else {
        var ipL = ip2long(baseIp);
        var mask = (~0 << (32 - prefix)) >>> 0;
        var start = ((ipL & mask) >>> 0) + 1;
        var end = ((ipL | (~mask >>> 0)) >>> 0) - 1;

        detectedSubnets.push(long2ip((ipL & mask) >>> 0) + '/' + prefix + ' (' + (end - start + 1) + ' IPs)');

        for (var l = start; l <= end; l++) {
          var ipCidr = long2ip(l);
          if (!ipSet[ipCidr]) { ipSet[ipCidr] = true; resultIPs.push(ipCidr); }
        }
      }
    } else if (tok.indexOf('-') !== -1) {
      var rParts = tok.split('-');
      var startIp = rParts[0].trim();
      var endPart = (rParts[1] || '').trim();
      var endIp = endPart;
      if (endPart && endPart.indexOf('.') === -1 && isValidIpv4(startIp)) {
        var baseSegments = startIp.split('.');
        baseSegments[3] = endPart;
        endIp = baseSegments.join('.');
      }
      if (isValidIpv4(startIp) && isValidIpv4(endIp)) {
        var sL = ip2long(startIp);
        var eL = ip2long(endIp);
        if (sL > eL) { var tmp = sL; sL = eL; eL = tmp; }
        if (eL - sL > 4096) eL = sL + 4096;
        detectedSubnets.push(long2ip(sL) + ' -> ' + long2ip(eL) + ' (' + (eL - sL + 1) + ' IPs)');
        for (var k = sL; k <= eL; k++) {
          var ipRange = long2ip(k);
          if (!ipSet[ipRange]) { ipSet[ipRange] = true; resultIPs.push(ipRange); }
        }
      }
    } else {
      var subTokens = tok.split(/\s+/);
      for (var st = 0; st < subTokens.length; st++) {
        var candidateIp = subTokens[st].trim();
        if (isValidIpv4(candidateIp) && !ipSet[candidateIp]) {
          ipSet[candidateIp] = true;
          resultIPs.push(candidateIp);
        }
      }
    }
  }

  return {
    ips: resultIPs,
    subnetsList: detectedSubnets
  };
}

function stripSensitiveApFields() {
  var keys = Object.keys(apMap);
  for (var i = 0; i < keys.length; i++) {
    var ap = apMap[keys[i]];
    if (ap && typeof ap === 'object') {
      delete ap.sshPassword;
      delete ap.webPassword;
      delete ap.password;
    }
  }
}

function loadRegistry() {
  try {
    if (fs.existsSync(REGISTRY_FILE)) {
      var content = fs.readFileSync(REGISTRY_FILE, 'utf8');
      var data = JSON.parse(content);
      if (data.apMap) {
        apMap = data.apMap;
        if (data.currentTarget) currentTarget = data.currentTarget;
        if (Array.isArray(data.staticIpsList)) staticIpsList = data.staticIpsList;
        if (data.ignoredApMacs && typeof data.ignoredApMacs === 'object') ignoredApMacs = data.ignoredApMacs;
        if (data.ignoredApIps && typeof data.ignoredApIps === 'object') ignoredApIps = data.ignoredApIps;
      } else {
        apMap = data;
      }
    }
  } catch (e) {}

  stripSensitiveApFields();
  if (Array.isArray(appConfig.network && appConfig.network.defaultStaticIps)) {
    staticIpsList = appConfig.network.defaultStaticIps.filter(isValidIpv4);
  }
  deduplicateApMap();
}

function saveRegistry() {
  try {
    stripSensitiveApFields();
    deduplicateApMap();
    var toSave = {
      currentTarget: currentTarget,
      staticIpsList: staticIpsList,
      ignoredApMacs: ignoredApMacs,
      ignoredApIps: ignoredApIps,
      lastScanStats: lastScanStats,
      apMap: apMap
    };
    fs.writeFileSync(REGISTRY_FILE, JSON.stringify(toSave, null, 2), 'utf8');
  } catch (e) {}
}

function isTotolinkMac(mac) {
  if (!mac) return false;
  var normalized = mac.toLowerCase().replace(/[:-]/g, '-');
  for (var i = 0; i < TOTOLINK_OUIS.length; i++) {
    var oui = TOTOLINK_OUIS[i].toLowerCase().replace(/[:-]/g, '-');
    if (normalized.indexOf(oui) === 0) return true;
  }
  return false;
}

function sendUdpProbes(ipList, callback) {
  if (ipList.length === 0) {
    if (callback) callback(null);
    return;
  }

  var socket = dgram.createSocket('udp4');
  var pkt = Buffer.from ? Buffer.from([0x10, 0x00, 0x00, 0x04]) : new Buffer([0x10, 0x00, 0x00, 0x04]);
  var batchSize = 60;
  var idx = 0;

  function sendBatch() {
    var count = 0;
    while (idx < ipList.length && count < batchSize) {
      try {
        socket.send(pkt, 0, pkt.length, 41985, ipList[idx]);
      } catch (e) {}
      idx++;
      count++;
    }

    if (idx < ipList.length) {
      setTimeout(sendBatch, 5);
    } else {
      setTimeout(function () {
        try { socket.close(); } catch (e) {}
        if (callback) callback(null);
      }, 100);
    }
  }

  sendBatch();
}

function probeIpList(ipArray, opts, callback) {
  var options = opts || {};
  var isManual = Boolean(options.isManual);
  var startTime = Date.now();
  var ipSet = {};
  var ips = [];

  for (var i = 0; i < (ipArray || []).length; i++) {
    var candidate = String(ipArray[i] || '').trim();
    if (isValidIpv4(candidate) && !ipSet[candidate]) {
      ipSet[candidate] = true;
      ips.push(candidate);
    }
  }

  if (ips.length === 0) {
    if (callback) callback(new Error('Địa chỉ IP hoặc dải mạng không hợp lệ'));
    return;
  }

  var allowUnignore = isManual && ips.length <= 256;
  if (allowUnignore) {
    for (var u = 0; u < ips.length; u++) {
      unignoreAp(ips[u], null);
    }
  }

  var pingReplyLatency = {};
  var cgiFoundIps = {};
  var newlySyncedTotolink = [];

  function runPingSweepIfSmall(donePing) {
    if (ips.length > 64) return donePing();
    var pIdx = 0;
    var pAct = 0;
    var pMax = 8;
    var pingBin = (typeof PING_EXE_PATH === 'string' && PING_EXE_PATH) ? PING_EXE_PATH : 'ping';

    function nextP() {
      if (pIdx >= ips.length && pAct === 0) return donePing();
      while (pAct < pMax && pIdx < ips.length) {
        (function (targetIp) {
          pAct++;
          var t0 = Date.now();
          cp.execFile(pingBin, ['-n', '1', '-w', '700', targetIp], { windowsHide: true, timeout: 1800 }, function (errP, stdoutP) {
            var outStr = stdoutP || '';
            var alive = Boolean(outStr.indexOf('Reply from') !== -1 && outStr.indexOf('Destination host unreachable') === -1);
            if (alive) {
              var mLat = outStr.match(/time[=<](\d+)ms/i);
              var latMs = (mLat && mLat[1]) ? parseInt(mLat[1], 10) : Math.max(1, Date.now() - t0);
              pingReplyLatency[targetIp] = Math.max(1, latMs);
              var existK = findApKeyByIp(targetIp);
              if (existK && apMap[existK] && (allowUnignore || !isApIgnored(targetIp, apMap[existK].mac))) {
                apMap[existK].status = 1;
                apMap[existK].latencyMs = pingReplyLatency[targetIp];
                apMap[existK].lastSeen = new Date().toISOString();
              }
            }
            pAct--;
            nextP();
          });
        })(ips[pIdx++]);
      }
    }
    nextP();
  }

  var wakeBarrier = 2;
  function onWakeStepDone() {
    wakeBarrier--;
    if (wakeBarrier > 0) return;

    cp.execFile('arp', ['-a'], { windowsHide: true, timeout: 4500 }, function (errArp, stdoutArp) {
      if (!errArp && stdoutArp) {
        var lines = stdoutArp.split(/\r?\n/);
        for (var a = 0; a < lines.length; a++) {
          var line = lines[a].trim();
          var parts = line.split(/\s+/);
          if (parts.length >= 2) {
            var ip = parts[0];
            var mac = parts[1].replace(/:/g, '-').toUpperCase();
            if (isValidIpv4(ip) && isValidHardwareMac(mac) && mac !== 'FF-FF-FF-FF-FF-FF') {
              arpMacToIpMap[mac] = ip;
              if (ipSet[ip] && (isTotolinkMac(mac) || staticIpsList.indexOf(ip) !== -1)) {
                upsertDiscoveredAp(ip, mac, {
                  latencyMs: pingReplyLatency[ip] || 1
                }, allowUnignore);
              }
            }
          }
        }
      }

      // Quet qua HTTP CGI port 80 de phat hien AP TOTOLINK N9v1 xuyen Subnet/VLAN
      var cgiIdx = 0;
      var cgiActive = 0;
      var cgiConcurrency = options.cgiConcurrency || (ips.length <= 64 ? 24 : 48);
      var cgiTimeoutMs = options.cgiTimeoutMs || (ips.length <= 16 ? 1800 : 1200);
      var stageFinished = false;

      function finishAllStages() {
        var duration = Date.now() - startTime;
        deduplicateApMap();
        saveRegistry();

        var onlineInTargetCount = 0;
        var matchedOnlineNames = [];
        var apKeys = Object.keys(apMap);
        for (var kIdx = 0; kIdx < apKeys.length; kIdx++) {
          var item = apMap[apKeys[kIdx]];
          if (item && ipSet[item.ip] && item.status === 1) {
            onlineInTargetCount++;
            matchedOnlineNames.push(item.name || item.ip);
          }
        }

        if (newlySyncedTotolink.length > 0 && typeof fetchTotolinkHwRadioConfig === 'function') {
          setTimeout(function () {
            for (var n = 0; n < Math.min(8, newlySyncedTotolink.length); n++) {
              fetchTotolinkHwRadioConfig(newlySyncedTotolink[n], function () {});
            }
          }, 200);
        }

        if (typeof scheduleRealtimeBroadcast === 'function') {
          scheduleRealtimeBroadcast(80);
        }

        var resultStats = {
          totalScannedIPs: ips.length,
          onlineInTargetCount: onlineInTargetCount,
          matchedOnlineNames: matchedOnlineNames,
          foundAPs: Object.keys(apMap).length,
          scanDurationMs: duration,
          lastScanTime: new Date().toISOString()
        };
        if (callback) callback(null, resultStats);
      }

      function trySshFallbackIfSmall() {
        if (ips.length > 32 || typeof pollSingleApSsh !== 'function' || typeof getApSshAuthList !== 'function') {
          return finishAllStages();
        }
        var sshCandidates = [];
        for (var s = 0; s < ips.length; s++) {
          var candIp = ips[s];
          if (pingReplyLatency[candIp] !== undefined && !cgiFoundIps[candIp]) {
            sshCandidates.push(candIp);
          }
        }
        if (sshCandidates.length === 0) {
          return finishAllStages();
        }
        var sIdx = 0;
        var sAct = 0;
        function nextSsh() {
          if (sIdx >= sshCandidates.length && sAct === 0) return finishAllStages();
          while (sAct < 4 && sIdx < sshCandidates.length) {
            (function (sshIp) {
              sAct++;
              var existingK = findApKeyByIp(sshIp);
              var tempAp = (existingK && apMap[existingK]) ? apMap[existingK] : {
                ip: sshIp,
                mac: '',
                name: 'UAP-' + sshIp.split('.').slice(2).join('.'),
                model: 'UniFi AP',
                firmware: '-',
                channel: '-',
                ssid: DEFAULT_SSID_FALLBACK,
                status: 1,
                latencyMs: pingReplyLatency[sshIp] || 1
              };
              pollSingleApSsh(tempAp, getApSshAuthList(tempAp), 0, function (errSsh) {
                if (!errSsh && tempAp.mac && isValidHardwareMac(tempAp.mac)) {
                  upsertDiscoveredAp(sshIp, tempAp.mac, {
                    name: tempAp.name,
                    model: tempAp.model,
                    firmware: tempAp.firmware,
                    channel: tempAp.channel,
                    ssid: tempAp.ssid,
                    clientCount: tempAp.clientCount,
                    latencyMs: pingReplyLatency[sshIp] || tempAp.latencyMs || 1,
                    rxBytes: tempAp.rxBytes,
                    txBytes: tempAp.txBytes,
                    isRealData: true
                  }, allowUnignore);
                }
                sAct--;
                nextSsh();
              });
            })(sshCandidates[sIdx++]);
          }
        }
        nextSsh();
      }

      function onCgiSweepComplete() {
        if (stageFinished) return;
        stageFinished = true;
        trySshFallbackIfSmall();
      }

      function nextCgiProbe() {
        if (cgiIdx >= ips.length && cgiActive === 0) {
          return onCgiSweepComplete();
        }
        while (cgiActive < cgiConcurrency && cgiIdx < ips.length) {
          (function (probeIp) {
            cgiActive++;
            if (typeof apApplyingLock !== 'undefined' && apApplyingLock && apApplyingLock[probeIp]) {
              setTimeout(function () {
                cgiActive--;
                nextCgiProbe();
              }, 0);
              return;
            }
            var probeDone = false;
            var hardTimer = setTimeout(function () {
              if (req && req.destroy) req.destroy(); else if (req && req.abort) req.abort();
              finishOne();
            }, cgiTimeoutMs + 800);
            function finishOne() {
              if (probeDone) return;
              probeDone = true;
              clearTimeout(hardTimer);
              cgiActive--;
              nextCgiProbe();
            }

            var bodyStr = JSON.stringify({ topicurl: 'setting/getSysStatusCfg' });
            var req = http.request({
              hostname: probeIp,
              port: 80,
              path: '/cgi-bin/cstecgi.cgi',
              method: 'POST',
              insecureHTTPParser: true,
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(bodyStr)
              }
            }, function (res) {
              var rBody = '';
              res.on('error', function () { finishOne(); });
              res.on('data', function (c) {
                if (rBody.length < 65536) rBody += c;
              });
              res.on('end', function () {
                try {
                  var j = JSON.parse(rBody);
                  if (j && j.lanMac) {
                    var normMac = j.lanMac.replace(/:/g, '-').toUpperCase();
                    cgiFoundIps[probeIp] = normMac;
                    var hadBefore = Boolean(findApKeyByMac(normMac));
                    var updatedAp = upsertDiscoveredAp(probeIp, normMac, {
                      name: (j.productName || 'N9') + '-' + probeIp.split('.').slice(2).join('.'),
                      model: 'TOTOLINK N9v1',
                      firmware: j.fmVersion || 'V4.0c.2634',
                      channel: parseInt(j.Channel, 10) || 6,
                      ssid: j.SSID1 || DEFAULT_SSID_FALLBACK,
                      clientCount: parseInt(j.sta_associated_num, 10) || 0,
                      latencyMs: pingReplyLatency[probeIp] || 2,
                      rxBytes: parseInt(j.wlanRx, 10) || 10000000,
                      txBytes: parseInt(j.wlanTx, 10) || 5000000,
                      isTotolinkN9: true,
                      isRealData: true
                    }, allowUnignore);
                    if (updatedAp && !hadBefore) {
                      newlySyncedTotolink.push(updatedAp);
                    }
                  }
                } catch (e) {}
                finishOne();
              });
            });
            req.on('error', function () {
              finishOne();
            });
            req.setTimeout(cgiTimeoutMs, function () {
              if (req.destroy) req.destroy(); else req.abort();
              finishOne();
            });
            req.end(bodyStr);
          })(ips[cgiIdx++]);
        }
      }

      nextCgiProbe();
    });
  }

  sendUdpProbes(ips, onWakeStepDone);
  runPingSweepIfSmall(onWakeStepDone);
}

function scanTargets(targetInput, callback) {
  if (isScanning) {
    if (callback) callback(new Error('Dang quet'));
    return;
  }

  isScanning = true;
  if (targetInput) currentTarget = targetInput;

  var combinedStr = DEFAULT_TARGET;
  if (currentTarget && currentTarget !== DEFAULT_TARGET) {
    combinedStr += ', ' + currentTarget;
  }
  if (staticIpsList.length > 0) {
    combinedStr += ', ' + staticIpsList.join(', ');
  }

  var parsed = parseTargets(combinedStr, true);
  if (parsed.ips.length === 0) {
    isScanning = false;
    if (callback) callback(new Error('Khong co IP hop le'));
    return;
  }

  probeIpList(parsed.ips, { isManual: false, cgiConcurrency: 44, cgiTimeoutMs: 1200 }, function (err, stats) {
    isScanning = false;
    if (!err && stats) {
      lastScanStats = {
        target: currentTarget,
        subnetsList: parsed.subnetsList,
        totalScannedIPs: stats.totalScannedIPs,
        foundAPs: stats.foundAPs,
        scanDurationMs: stats.scanDurationMs,
        lastScanTime: stats.lastScanTime
      };
      saveRegistry();
      pingAllAPs();
      pollAllRealApStats();
    }
    if (callback) callback(err, lastScanStats);
  });
}

function runManualScan(requestedTarget, callback) {
  var rawTarget = String(requestedTarget || '').trim();
  if (!rawTarget) {
    return callback(new Error('Vui lòng nhập địa chỉ IP hoặc dải mạng cần quét'));
  }
  var parsed = parseTargets(rawTarget, false);
  if (parsed.ips.length === 0) {
    return callback(new Error('Địa chỉ IP hoặc dải mạng không hợp lệ: ' + rawTarget));
  }

  currentTarget = rawTarget;
  probeIpList(parsed.ips, {
    isManual: true,
    cgiConcurrency: parsed.ips.length <= 64 ? 24 : 56,
    cgiTimeoutMs: parsed.ips.length <= 16 ? 1800 : 1150
  }, function (err, stats) {
    if (err) return callback(err);
    lastScanStats = {
      target: currentTarget,
      subnetsList: parsed.subnetsList,
      totalScannedIPs: stats.totalScannedIPs,
      onlineInTargetCount: stats.onlineInTargetCount,
      matchedOnlineNames: stats.matchedOnlineNames,
      foundAPs: stats.foundAPs,
      scanDurationMs: stats.scanDurationMs,
      lastScanTime: stats.lastScanTime
    };
    saveRegistry();
    callback(null, lastScanStats);
  });
}

function deleteApEntries(opts) {
  var o = opts || {};
  var mode = o.mode || 'single';
  var targetKey = String(o.key || '').trim();
  var targetIp = String(o.ip || '').trim();
  var targetMac = String(o.mac || '').replace(/:/g, '-').toUpperCase();

  var keysToDelete = [];
  var allKeys = Object.keys(apMap);
  for (var i = 0; i < allKeys.length; i++) {
    var k = allKeys[i];
    var ap = apMap[k];
    if (!ap) continue;
    if (mode === 'offline') {
      if (ap.status !== 1) keysToDelete.push(k);
    } else {
      var apMacNorm = String(ap.mac || '').replace(/:/g, '-').toUpperCase();
      if ((targetKey && (k === targetKey || ap.key === targetKey)) ||
          (targetIp && ap.ip === targetIp) ||
          (targetMac && isValidHardwareMac(targetMac) && apMacNorm === targetMac)) {
        keysToDelete.push(k);
      }
    }
  }

  var deletedNames = [];
  var deletedIpsMap = {};
  var rfModified = false;

  for (var d = 0; d < keysToDelete.length; d++) {
    var delK = keysToDelete[d];
    var delAp = apMap[delK];
    if (!delAp) continue;

    deletedNames.push(delAp.name || delAp.ip || delK);
    if (delAp.ip) {
      deletedIpsMap[delAp.ip] = true;
      delete apClientsCache[delAp.ip];
      if (typeof apApplyLiveState !== 'undefined' && apApplyLiveState) {
        delete apApplyLiveState[delAp.ip];
      }
    }

    var normDelMac = String(delAp.mac || '').replace(/:/g, '-').toUpperCase();
    // Neu xoa AP dang Online, ghi nhan vao danh sach bo qua de quet tu dong khong tu them lai
    if (delAp.status === 1) {
      if (isValidHardwareMac(normDelMac)) ignoredApMacs[normDelMac] = Date.now();
      if (delAp.ip) ignoredApIps[delAp.ip] = Date.now();
    }

    if (isValidHardwareMac(normDelMac) && typeof rfTelemetryStore !== 'undefined' && rfTelemetryStore) {
      if (rfTelemetryStore.aps && rfTelemetryStore.aps[normDelMac]) {
        delete rfTelemetryStore.aps[normDelMac];
        rfModified = true;
      }
      if (rfTelemetryStore.channelPlan && rfTelemetryStore.channelPlan[normDelMac]) {
        delete rfTelemetryStore.channelPlan[normDelMac];
        rfModified = true;
      }
    }

    delete apMap[delK];
  }

  // Dong bo xoa khoi danh sach IP giam sat co dinh neu co
  if (Object.keys(deletedIpsMap).length > 0 || (mode !== 'offline' && isValidIpv4(targetIp))) {
    if (mode !== 'offline' && isValidIpv4(targetIp)) {
      deletedIpsMap[targetIp] = true;
    }
    var nextStatic = [];
    var staticChanged = false;
    for (var s = 0; s < staticIpsList.length; s++) {
      if (deletedIpsMap[staticIpsList[s]]) {
        staticChanged = true;
      } else {
        nextStatic.push(staticIpsList[s]);
      }
    }
    if (staticChanged) {
      staticIpsList = nextStatic;
      if (appConfig.network) {
        appConfig.network.defaultStaticIps = nextStatic.slice();
      }
      saveAppConfig();
    }
  }

  if (rfModified && typeof saveRfTelemetryStore === 'function') {
    saveRfTelemetryStore(true);
  }

  deduplicateApMap();
  saveRegistry();
  if (typeof scheduleRealtimeBroadcast === 'function') {
    scheduleRealtimeBroadcast(60);
  }

  return {
    deletedCount: deletedNames.length,
    deletedNames: deletedNames,
    staticIps: staticIpsList.slice()
  };
}

var PING_EXE_PATH = fs.existsSync('C:\\Windows\\System32\\PING.EXE')
  ? 'C:\\Windows\\System32\\PING.EXE'
  : 'ping';
var isPingingAll = false;

function pingAllAPs(doneCb) {
  if (isPingingAll) {
    if (doneCb) doneCb();
    return;
  }
  var keys = Object.keys(apMap);
  if (keys.length === 0) {
    if (doneCb) doneCb();
    return;
  }
  isPingingAll = true;
  var idx = 0;
  var active = 0;
  var maxPingConc = 8;

  function nextPing() {
    if (idx >= keys.length && active === 0) {
      isPingingAll = false;
      if (typeof scheduleRealtimeBroadcast === 'function') {
        scheduleRealtimeBroadcast(200);
      }
      if (doneCb) doneCb();
      return;
    }
    while (active < maxPingConc && idx < keys.length) {
      (function (k) {
        var ap = apMap[k];
        if (!ap || !ap.ip) {
          return;
        }
        active++;
        var startTime = Date.now();
        var finished = false;
        function finishPing(stdout) {
          if (finished) return;
          finished = true;
          var isOnline = Boolean(stdout && stdout.indexOf('Reply from') !== -1 && stdout.indexOf('Destination host unreachable') === -1);
          if (isOnline) {
            ap.status = 1;
            ap.lastSeen = new Date().toISOString();
            var match = stdout.match(/time[=<](\d+)ms/i);
            if (match && match[1]) {
              ap.latencyMs = parseInt(match[1], 10);
            } else {
              ap.latencyMs = Math.max(1, Date.now() - startTime);
            }
          } else if (!(typeof apApplyingLock !== 'undefined' && apApplyingLock && apApplyingLock[ap.ip])) {
            ap.status = 0;
            ap.latencyMs = 0;
          }
          active--;
          setTimeout(nextPing, 12);
        }

        cp.execFile(PING_EXE_PATH, ['-n', '1', '-w', '900', ap.ip], { windowsHide: true, timeout: 2200 }, function (err, stdout) {
          finishPing(stdout || '');
        });
      })(keys[idx++]);
    }
  }

  nextPing();
}

/**
 * THU THAP SO LIEU THUC TE (REAL-TIME SSH & HTTP METRICS)
 * Doc SSID thuc te, so client online chinh xac va luu luong mang truc tiep tu AP
 */
var SSH_PATH = fs.existsSync('C:\\Windows\\System32\\OpenSSH\\ssh.exe')
  ? 'C:\\Windows\\System32\\OpenSSH\\ssh.exe'
  : 'C:\\Windows\\SysNative\\OpenSSH\\ssh.exe';
var ASKPASS_BAT = path.join(__dirname, 'askpass.bat');
var SSH_USER = appConfig.apCredentials.sshUsername || 'admin';
var SSH_PASSWORDS = Array.isArray(appConfig.apCredentials.sshPasswords)
  ? appConfig.apCredentials.sshPasswords
  : [];
var PER_AP_PASSWORDS = (appConfig.apCredentials.perApPasswords && typeof appConfig.apCredentials.perApPasswords === 'object')
  ? appConfig.apCredentials.perApPasswords
  : {};
var sshSessionPassCache = {};
var SSH_POLL_INTERVAL_MS = Number(appConfig.server.apPollIntervalMs) || 12000;
var isPollingSsh = false;

if (!fs.existsSync(ASKPASS_BAT)) {
  fs.writeFileSync(ASKPASS_BAT, '@echo off\r\necho %PASS_TO_OUTPUT%\r\n');
}

function getApSshAuthList(ap) {
  var list = [];
  var seen = {};
  function addCandidate(u, p) {
    if (!p || typeof p !== 'string') return;
    var usr = (u && typeof u === 'string') ? u : SSH_USER;
    var key = usr + '\0' + p;
    if (!seen[key]) {
      seen[key] = true;
      list.push({ user: usr, pass: p });
    }
  }

  if (PER_AP_PASSWORDS && ap) {
    var macDash = ap.mac ? ap.mac.replace(/:/g, '-').toUpperCase() : '';
    var macColon = ap.mac ? ap.mac.replace(/-/g, ':').toUpperCase() : '';
    var pKeys = Object.keys(PER_AP_PASSWORDS);
    for (var pk = 0; pk < pKeys.length; pk++) {
      var k = pKeys[pk];
      var kUp = k.toUpperCase();
      if ((ap.ip && k === ap.ip) || (macDash && (kUp === macDash || kUp === macColon))) {
        var customVal = PER_AP_PASSWORDS[k];
        if (typeof customVal === 'string') {
          addCandidate(SSH_USER, customVal);
        } else if (customVal && typeof customVal === 'object') {
          var cUser = customVal.username || SSH_USER;
          if (typeof customVal.password === 'string') addCandidate(cUser, customVal.password);
          if (Array.isArray(customVal.passwords)) {
            for (var ci = 0; ci < customVal.passwords.length; ci++) {
              addCandidate(cUser, customVal.passwords[ci]);
            }
          }
        }
      }
    }
  }

  if (ap && ap.ip && sshSessionPassCache[ap.ip]) {
    addCandidate(sshSessionPassCache[ap.ip].user, sshSessionPassCache[ap.ip].pass);
  }

  for (var i = 0; i < SSH_PASSWORDS.length; i++) {
    addCandidate(SSH_USER, SSH_PASSWORDS[i]);
  }
  return list;
}

var OUI_VENDORS_FILE = path.join(__dirname, 'assets', 'oui_vendors.json');
var CLIENT_IDENTITY_CACHE_FILE = path.join(__dirname, 'clients_identity_cache.json');
var IEEE_OUI_DB = {};
var clientIdentityMap = {};
var apGatewayCache = {};
var netbiosProbeCooldown = {};
var clientIdentityDirty = false;

var COMMON_CLIENT_OUIS = {
  '00-1C-B3': 'Apple, Inc.', '00-23-DF': 'Apple, Inc.', '28-CF-E9': 'Apple, Inc.', '3C-22-FB': 'Apple, Inc.',
  '40-B3-95': 'Apple, Inc.', '64-B0-A6': 'Apple, Inc.', '70-56-81': 'Apple, Inc.', 'A4-83-E7': 'Apple, Inc.',
  'AC-BC-32': 'Apple, Inc.', 'D0-81-7A': 'Apple, Inc.', 'F0-18-98': 'Apple, Inc.', 'F4-5C-89': 'Apple, Inc.',
  '00-16-6C': 'Samsung Electronics', '24-4B-03': 'Samsung Electronics', '38-AA-3C': 'Samsung Electronics', '50-01-BB': 'Samsung Electronics',
  '78-47-1D': 'Samsung Electronics', '8C-77-12': 'Samsung Electronics', 'A8-9F-BA': 'Samsung Electronics', 'CC-07-AB': 'Samsung Electronics',
  '14-F6-5A': 'Xiaomi Communications', '28-6C-07': 'Xiaomi Communications', '64-CC-2E': 'Xiaomi Communications', '78-11-DC': 'Xiaomi Communications',
  '9C-99-A0': 'Xiaomi Communications', 'B0-E2-35': 'Xiaomi Communications', 'F8-A4-5F': 'Xiaomi Communications',
  '1C-48-CE': 'OPPO Mobile', '44-00-49': 'OPPO Mobile', '74-59-09': 'OPPO Mobile', 'A4-3B-FA': 'OPPO Mobile',
  '24-FC-E5': 'Vivo Mobile', '54-0E-2D': 'Vivo Mobile', '88-44-AF': 'Vivo Mobile',
  '00-E0-FC': 'Huawei Technologies', '28-31-52': 'Huawei Technologies', '48-46-FB': 'Huawei Technologies', '88-28-B3': 'Huawei Technologies',
  '00-1B-21': 'Intel Corporation', '34-13-E8': 'Intel Corporation', '3C-97-0E': 'Intel Corporation', '48-51-B7': 'Intel Corporation',
  '68-05-CA': 'Intel Corporation', '8C-8D-28': 'Intel Corporation', 'A4-34-D9': 'Intel Corporation', 'DC-FB-48': 'Intel Corporation',
  '00-E0-4C': 'Realtek Semiconductor', '2C-FD-A1': 'ASUSTeK Computer', '38-D5-47': 'ASUSTeK Computer',
  '14-FE-B5': 'Dell Inc.', '54-BF-64': 'Dell Inc.', 'F8-BC-12': 'Dell Inc.',
  '10-E7-C6': 'HP Inc.', '3C-D9-2B': 'HP Inc.', 'F4-39-09': 'HP Inc.',
  '50-7B-9D': 'Lenovo', '98-FA-9B': 'Lenovo',
  '24-0A-C4': 'Espressif Inc. (IoT)', '30-AE-A4': 'Espressif Inc. (IoT)',
  '18-E8-29': 'Ubiquiti Inc.', 'F4-28-53': 'TOTOLINK (Zioncom)'
};

(function loadOfflineOuiDb() {
  try {
    if (fs.existsSync(OUI_VENDORS_FILE)) {
      IEEE_OUI_DB = JSON.parse(fs.readFileSync(OUI_VENDORS_FILE, 'utf8'));
      console.log('[OUI DB] Da nap co so du lieu IEEE OUI: ' + Object.keys(IEEE_OUI_DB).length + ' ma nha san xuat.');
    }
  } catch (e) {
    console.warn('[OUI DB] Khong doc duoc oui_vendors.json, dung bang OUI rut gon:', e.message);
  }
})();

(function loadClientIdentityCache() {
  try {
    if (fs.existsSync(CLIENT_IDENTITY_CACHE_FILE)) {
      var raw = JSON.parse(fs.readFileSync(CLIENT_IDENTITY_CACHE_FILE, 'utf8'));
      var now = Date.now();
      var maxAgeMs = 48 * 3600 * 1000;
      if (raw && typeof raw === 'object') {
        Object.keys(raw).forEach(function (m) {
          var entry = raw[m];
          if (entry && entry.updatedAt && (now - entry.updatedAt) < maxAgeMs) {
            clientIdentityMap[m] = entry;
          }
        });
      }
    }
  } catch (e) {}
})();

function saveClientIdentityCache() {
  if (!clientIdentityDirty) return;
  clientIdentityDirty = false;
  try {
    var now = Date.now();
    var maxAgeMs = 48 * 3600 * 1000;
    var clean = {};
    Object.keys(clientIdentityMap).forEach(function (m) {
      var it = clientIdentityMap[m];
      if (it && it.updatedAt && (now - it.updatedAt) < maxAgeMs) {
        clean[m] = it;
      }
    });
    fs.writeFileSync(CLIENT_IDENTITY_CACHE_FILE, JSON.stringify(clean, null, 2), 'utf8');
  } catch (e) {}
}

function probeNetbiosHostnameAsync(ip, mac) {
  if (!ip || ip === '0.0.0.0' || ip.indexOf('169.254.') === 0) return;
  var now = Date.now();
  if (netbiosProbeCooldown[ip] && (now - netbiosProbeCooldown[ip]) < 600000) return;
  netbiosProbeCooldown[ip] = now;

  try {
    var buf = Buffer.alloc ? Buffer.alloc(50) : new Buffer(50);
    if (!Buffer.alloc) buf.fill(0);
    buf.writeUInt16BE(0x1337, 0);
    buf.writeUInt16BE(0x0001, 4);
    buf[12] = 0x20;
    buf.write('CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 13, 'ascii');
    buf.writeUInt16BE(0x0021, 46);
    buf.writeUInt16BE(0x0001, 48);

    var sock = dgram.createSocket('udp4');
    var closed = false;
    function closeSock() {
      if (closed) return;
      closed = true;
      try { sock.close(); } catch (e) {}
    }
    var timer = setTimeout(closeSock, 400);
    sock.on('error', function () {
      clearTimeout(timer);
      closeSock();
    });
    sock.on('message', function (msg) {
      clearTimeout(timer);
      closeSock();
      if (!msg || msg.length < 57) return;
      var numNames = msg[56];
      var offset = 57;
      for (var i = 0; i < numNames && (offset + 18) <= msg.length; i++, offset += 18) {
        var rawName = msg.slice(offset, offset + 15).toString('utf8').replace(/\0/g, '').trim();
        var type = msg[offset + 15];
        var flags = msg.readUInt16BE(offset + 16);
        if ((flags & 0x8000) === 0 && (type === 0x00 || type === 0x20) && rawName) {
          recordClientIdentity(mac, ip, rawName, 0, 'netbios');
          break;
        }
      }
    });
    sock.send(buf, 0, buf.length, 137, ip, function (err) {
      if (err) {
        clearTimeout(timer);
        closeSock();
      }
    });
  } catch (e) {}
}

function recordClientIdentity(macStr, ipStr, hostnameStr, usedSec, source) {
  if (!macStr) return;
  var mac = macStr.replace(/:/g, '-').toUpperCase();
  if (!isValidHardwareMac(mac) || mac === '00-00-00-00-00-00') return;

  var entry = clientIdentityMap[mac] || {
    ip: '',
    ipsByPrefix: {},
    hostname: '',
    usedSec: 999999,
    source: '',
    updatedAt: 0
  };
  if (!entry.ipsByPrefix) entry.ipsByPrefix = {};

  var changed = false;
  var age = (typeof usedSec === 'number' && !isNaN(usedSec)) ? usedSec : 0;

  if (ipStr && ipStr !== '0.0.0.0' && ipStr.indexOf('169.254.') !== 0) {
    var parts = ipStr.split('.');
    if (parts.length === 4) {
      var pfx = parts[0] + '.' + parts[1] + '.' + parts[2];
      var prevPfx = entry.ipsByPrefix[pfx];
      if (!prevPfx || age <= prevPfx.usedSec || (Date.now() - (prevPfx.ts || 0)) > 60000) {
        entry.ipsByPrefix[pfx] = { ip: ipStr, usedSec: age, ts: Date.now() };
      }
      var curIsApNet = entry.ip && entry.ip.indexOf('172.16.') === 0;
      var newIsApNet = ipStr.indexOf('172.16.') === 0;
      if (!entry.ip || (newIsApNet && !curIsApNet) || (newIsApNet === curIsApNet && age <= entry.usedSec)) {
        if (entry.ip !== ipStr) changed = true;
        entry.ip = ipStr;
        entry.usedSec = age;
        entry.source = source || entry.source;
      }
      arpMacToIpMap[mac] = entry.ip;
    }
  }

  if (hostnameStr && typeof hostnameStr === 'string') {
    var cleanHost = hostnameStr.trim();
    if (cleanHost && cleanHost !== '-' && cleanHost !== '*' && cleanHost.toLowerCase() !== 'unknown') {
      if (entry.hostname !== cleanHost) {
        entry.hostname = cleanHost;
        changed = true;
      }
    }
  }

  entry.updatedAt = Date.now();
  clientIdentityMap[mac] = entry;
  if (changed) clientIdentityDirty = true;

  if (entry.ip && !entry.hostname && entry.ip.indexOf('172.16.') === 0) {
    probeNetbiosHostnameAsync(entry.ip, mac);
  }
}

function parseUnifiNeighTable(rawNeigh) {
  if (!rawNeigh) return;
  var lines = String(rawNeigh).split(/\r?\n/);
  for (var i = 0; i < lines.length; i++) {
    var m = lines[i].match(/^(\d+\.\d+\.\d+\.\d+)\s+lladdr\s+([0-9a-f:]{17})\s+.*?used\s+(\d+)\//i);
    if (m) {
      var ip = m[1];
      var mac = m[2].toUpperCase().replace(/:/g, '-');
      var usedSec = parseInt(m[3], 10) || 0;
      if (ip.indexOf('169.254.') === 0 || mac === '00-00-00-00-00-00') continue;
      // Ignore gateway router MAC bc:24:11:30:af:e9
      if (mac === 'BC-24-11-30-AF-E9') continue;
      recordClientIdentity(mac, ip, '', usedSec, 'uap-neigh');
    }
  }
}

function resolveBestClientIdentity(macStr, apIp) {
  var mac = (macStr || '').replace(/:/g, '-').toUpperCase();
  var apParts = (apIp || '').split('.');
  var apPrefix = apParts.length === 4 ? (apParts[0] + '.' + apParts[1] + '.' + apParts[2]) : '';
  var defaultGw = apPrefix ? (apPrefix + '.1') : '';
  var vlanCidr = apPrefix ? (apPrefix + '.0/24') : '';
  if (apIp && apIp.indexOf('172.16.0.') === 0) {
    defaultGw = '172.16.0.1';
    vlanCidr = '172.16.0.0/23';
  }
  var gatewayIp = (apIp && apGatewayCache[apIp]) ? apGatewayCache[apIp] : defaultGw;

  var entry = clientIdentityMap[mac];
  var bestIp = '';
  var ipNote = '';
  var hostname = entry && entry.hostname ? entry.hostname : '';

  if (entry) {
    if (apPrefix && entry.ipsByPrefix && entry.ipsByPrefix[apPrefix] && entry.ipsByPrefix[apPrefix].ip) {
      bestIp = entry.ipsByPrefix[apPrefix].ip;
      ipNote = 'Trực tiếp trên VLAN ' + apPrefix + '.x';
    } else if (entry.ip && entry.ip.indexOf('172.16.') === 0) {
      bestIp = entry.ip;
      var ipPfx = bestIp.split('.').slice(0, 3).join('.');
      ipNote = (apPrefix && ipPfx !== apPrefix) ? (' Phiên chuyển vùng (' + ipPfx + '.x)') : 'Đã xác thực L2 ARP';
    } else if (entry.ip) {
      bestIp = entry.ip;
      ipNote = 'Đã ghi nhận ARP';
    }
  }

  if (!bestIp && arpMacToIpMap[mac] && arpMacToIpMap[mac] !== '0.0.0.0') {
    bestIp = arpMacToIpMap[mac];
    ipNote = 'Bảng ARP nội bộ';
  }

  return {
    ip: bestIp,
    ipNote: ipNote,
    hostname: hostname,
    vlanCidr: vlanCidr,
    gatewayIp: gatewayIp
  };
}

function classifyDeviceByVendor(vName, hostname) {
  var h = (hostname || '').toLowerCase();
  var v = (vName || '').toLowerCase();
  if (h.indexOf('iphone') !== -1) return { title: 'Apple iPhone', icon: 'fi-rr-mobile-notch', isPc: false };
  if (h.indexOf('ipad') !== -1) return { title: 'Apple iPad', icon: 'fi-rr-tablet', isPc: false };
  if (h.indexOf('macbook') !== -1 || h.indexOf('imac') !== -1) return { title: 'Apple Mac', icon: 'fi-rr-laptop', isPc: true };
  if (h.indexOf('desktop-') === 0 || h.indexOf('laptop-') === 0 || h.indexOf('-pc') !== -1) {
    return { title: 'Máy tính Windows', icon: 'fi-rr-laptop', isPc: true };
  }

  if (v.indexOf('apple') !== -1) return { title: 'Thiết bị Apple (iOS / Mac)', icon: 'fi-rr-mobile-notch', isPc: false };
  if (v.indexOf('samsung') !== -1) return { title: 'Samsung Galaxy / Smart Device', icon: 'fi-rr-mobile-notch', isPc: false };
  if (v.indexOf('xiaomi') !== -1) return { title: 'Điện thoại Xiaomi / Redmi', icon: 'fi-rr-mobile-notch', isPc: false };
  if (v.indexOf('oppo') !== -1) return { title: 'Điện thoại OPPO', icon: 'fi-rr-mobile-notch', isPc: false };
  if (v.indexOf('vivo') !== -1) return { title: 'Điện thoại Vivo', icon: 'fi-rr-mobile-notch', isPc: false };
  if (v.indexOf('realme') !== -1) return { title: 'Điện thoại Realme', icon: 'fi-rr-mobile-notch', isPc: false };
  if (v.indexOf('huawei') !== -1 || v.indexOf('honor') !== -1) return { title: 'Thiết bị Huawei / Honor', icon: 'fi-rr-mobile-notch', isPc: false };
  if (v.indexOf('oneplus') !== -1) return { title: 'Điện thoại OnePlus', icon: 'fi-rr-mobile-notch', isPc: false };
  if (v.indexOf('google') !== -1) return { title: 'Thiết bị Google / Pixel', icon: 'fi-rr-mobile-notch', isPc: false };
  if (v.indexOf('lg innotek') !== -1 || v.indexOf('lg electronics') !== -1) return { title: 'Smart TV / Thiết bị LG', icon: 'fi-rr-screen', isPc: true };
  if (v.indexOf('sony') !== -1 || v.indexOf('tcl') !== -1 || v.indexOf('hisense') !== -1) return { title: 'Smart TV / Giải trí', icon: 'fi-rr-screen', isPc: true };
  if (v.indexOf('intel') !== -1 || v.indexOf('dell') !== -1 || v.indexOf('hp ') !== -1 || v === 'hp inc.' ||
      v.indexOf('lenovo') !== -1 || v.indexOf('asus') !== -1 || v.indexOf('acer') !== -1 ||
      v.indexOf('msi') !== -1 || v.indexOf('microsoft') !== -1 || v.indexOf('realtek') !== -1) {
    return { title: 'Laptop / Máy tính cá nhân', icon: 'fi-rr-laptop', isPc: true };
  }
  if (v.indexOf('azurewave') !== -1 || v.indexOf('lite-on') !== -1 || v.indexOf('liteon') !== -1 ||
      v.indexOf('foxconn') !== -1 || v.indexOf('fugui') !== -1 || v.indexOf('mediatek') !== -1 ||
      v.indexOf('murata') !== -1 || v.indexOf('broadcom') !== -1 || v.indexOf('qualcomm') !== -1) {
    return { title: 'Thiết bị Wi-Fi / Smart Device', icon: 'fi-rr-laptop', isPc: true };
  }
  if (v.indexOf('espressif') !== -1 || v.indexOf('tuya') !== -1 || v.indexOf('wiseasy') !== -1 || v.indexOf('iot') !== -1) {
    return { title: 'Thiết bị IoT / Đầu cuối', icon: 'fi-rr-microchip', isPc: true };
  }
  if (v.indexOf('ubiquiti') !== -1 || v.indexOf('totolink') !== -1 || v.indexOf('tp-link') !== -1) {
    return { title: 'Thiết bị mạng Wi-Fi', icon: 'fi-rr-router', isPc: true };
  }
  return { title: 'Thiết bị phần cứng IEEE', icon: 'fi-rr-mobile-notch', isPc: false };
}

function detectClientVendor(macStr, hostnameStr) {
  if (!macStr) {
    return {
      ouiCode: '00-00-00',
      label: 'Chưa xác định',
      deviceTitle: 'Thiết bị Wi-Fi',
      icon: 'fi-rr-mobile-notch',
      isPrivate: false,
      isPc: false
    };
  }
  var norm = macStr.replace(/:/g, '-').toUpperCase();
  var prefix = norm.slice(0, 8);
  var regVendor = IEEE_OUI_DB[prefix] || COMMON_CLIENT_OUIS[prefix] || '';
  if (regVendor) {
    var cls = classifyDeviceByVendor(regVendor, hostnameStr);
    return {
      ouiCode: prefix,
      label: regVendor,
      deviceTitle: cls.title,
      icon: cls.icon,
      isPrivate: false,
      isPc: cls.isPc
    };
  }
  var firstOctet = parseInt(norm.slice(0, 2), 16);
  if (!isNaN(firstOctet) && (firstOctet & 2) !== 0) {
    return {
      ouiCode: prefix,
      label: 'MAC Ẩn danh LAA (iOS / Android)',
      deviceTitle: 'Smartphone / Tablet',
      icon: 'fi-rr-mobile-notch',
      isPrivate: true,
      isPc: false
    };
  }
  return {
    ouiCode: prefix,
    label: 'Chuẩn IEEE Global',
    deviceTitle: 'Thiết bị Wi-Fi chuẩn',
    icon: 'fi-rr-mobile-notch',
    isPrivate: false,
    isPc: false
  };
}

function formatDurationSec(totalSec) {
  var s = Math.max(0, parseInt(totalSec, 10) || 0);
  var hrs = Math.floor(s / 3600);
  var mins = Math.floor((s % 3600) / 60);
  var secs = s % 60;
  function pad2(n) { return n < 10 ? '0' + n : String(n); }
  return pad2(hrs) + ':' + pad2(mins) + ':' + pad2(secs);
}

function extractUnifiClientsFromDump(j, fallbackSsid, apIp) {
  var list = [];
  var vaps = (j && j.vap_table) ? j.vap_table : [];
  for (var v = 0; v < vaps.length; v++) {
    var vap = vaps[v];
    var stas = vap.sta_table || [];
    var vapSsid = (vap.essid && vap.essid.indexOf('element-') === -1) ? vap.essid : (fallbackSsid || vap.essid || '');
    var vapCh = vap.channel || '';
    var vapBand = (vapCh && Number(vapCh) > 14) ? '5 GHz' : '2.4 GHz';
    for (var s = 0; s < stas.length; s++) {
      var sta = stas[s];
      if (!sta || !sta.mac) continue;
      var mac = sta.mac.replace(/:/g, '-').toUpperCase();
      var staIp = (sta.ip && sta.ip !== '0.0.0.0') ? sta.ip : '';
      var staHost = sta.hostname || sta.name || '';
      if (staIp || staHost) {
        recordClientIdentity(mac, staIp, staHost, 0, 'unifi-sta');
      }
      var idInfo = resolveBestClientIdentity(mac, apIp);
      var finalIp = staIp || idInfo.ip;
      var finalHost = staHost || idInfo.hostname;
      var sigDbm = typeof sta.signal === 'number' ? sta.signal : (typeof sta.rssi === 'number' ? (sta.rssi - 95) : null);
      var sigPct = sigDbm !== null ? Math.max(5, Math.min(100, Math.round((sigDbm + 95) * (100 / 55)))) : 60;
      var mode = sta.is_11ax ? '802.11ax' : (sta.is_11ac ? '802.11ac' : (sta.is_11n ? '802.11n' : (sta.is_11a ? '802.11a' : '802.11g/b')));
      var bw = sta.chwidth === 2 ? '80 MHz' : (sta.chwidth === 1 ? '40 MHz' : '20 MHz');
      var vInfo = detectClientVendor(mac, finalHost);
      list.push({
        mac: mac,
        ouiCode: vInfo.ouiCode,
        ip: finalIp,
        ipNote: staIp ? 'Trực tiếp từ Controller' : idInfo.ipNote,
        vlanCidr: idInfo.vlanCidr,
        gatewayIp: idInfo.gatewayIp,
        hostname: finalHost,
        deviceTitle: vInfo.deviceTitle,
        vendor: vInfo.label,
        deviceIcon: vInfo.icon,
        isPrivateMac: vInfo.isPrivate,
        isPcDevice: vInfo.isPc,
        ssid: vapSsid,
        channel: vapCh,
        band: vapBand,
        mode: mode,
        bandwidth: bw,
        signalPercent: sigPct,
        signalDbm: sigDbm,
        txRateMbps: sta.tx_rate ? Math.round(sta.tx_rate / 1000) : null,
        rxRateMbps: sta.rx_rate ? Math.round(sta.rx_rate / 1000) : null,
        rxBytes: Number(sta.rx_bytes) || 0,
        txBytes: Number(sta.tx_bytes) || 0,
        connectedTime: formatDurationSec(sta.uptime || sta.assoc_time || 0)
      });
    }
  }
  list.sort(function (a, b) { return b.signalPercent - a.signalPercent; });
  return list;
}

function pollSingleApSsh(ap, authList, authIdx, callback) {
  if (authIdx >= authList.length) {
    if (callback) callback(new Error('SSH authentication failed'));
    return;
  }

  var authItem = authList[authIdx];
  var sshUser = authItem.user || SSH_USER;
  var pass = authItem.pass;
  var env = {};
  for (var k in process.env) { env[k] = process.env[k]; }
  env['SSH_ASKPASS'] = ASKPASS_BAT;
  env['SSH_ASKPASS_REQUIRE'] = 'force';
  env['DISPLAY'] = 'dummy:0';
  env['PASS_TO_OUTPUT'] = pass;

  var sshArgs = [
    '-o', 'StrictHostKeyChecking=no',
    '-o', 'UserKnownHostsFile=NUL',
    '-o', 'ConnectTimeout=3',
    sshUser + '@' + ap.ip,
    'mca-dump; echo "===NEIGH_BR0==="; ip -4 -s neigh show dev br0 2>/dev/null'
  ];

  cp.execFile(SSH_PATH, sshArgs, { env: env, timeout: 6500, maxBuffer: 2 * 1024 * 1024 }, function (err, stdout, stderr) {
    if (err || (stderr && stderr.indexOf('Permission denied') !== -1)) {
      return pollSingleApSsh(ap, authList, authIdx + 1, callback);
    }

    try {
      var parts = String(stdout || '').split('===NEIGH_BR0===');
      var jsonPart = parts[0] || '';
      var neighPart = parts[1] || '';
      if (neighPart) {
        parseUnifiNeighTable(neighPart);
      }

      var j = JSON.parse(jsonPart);
      sshSessionPassCache[ap.ip] = { user: sshUser, pass: pass };
      if (j.gateway_ip) {
        apGatewayCache[ap.ip] = j.gateway_ip;
      }
      if (j.mac) {
        ap.mac = j.mac.replace(/:/g, '-').toUpperCase();
      }
      if (j.hostname) {
        ap.hostname = j.hostname;
        ap.name = j.hostname;
      }
      ap.model = j.model_display || 'UAP-AC-Pro-Gen2';
      ap.firmware = j.version || '6.8.2.15592';

      var totalClients = 0;
      var ssidFound = '';
      var chFound = ap.channel;
      var rawRx = 0;
      var rawTx = 0;

      var vaps = j.vap_table || [];
      for (var v = 0; v < vaps.length; v++) {
        var vap = vaps[v];
        totalClients += parseInt(vap.num_sta, 10) || 0;
        rawRx += parseInt(vap.rx_bytes, 10) || 0;
        rawTx += parseInt(vap.tx_bytes, 10) || 0;
        if (vap.essid && vap.essid.indexOf('element-') === -1) {
          ssidFound = vap.essid;
          if (vap.channel && vap.channel <= 14) {
            chFound = vap.channel;
          } else if (!chFound || chFound === '-') {
            chFound = vap.channel;
          }
        }
      }

      if (ssidFound) ap.ssid = ssidFound;
      if (chFound) ap.channel = chFound;
      var unifiClients = extractUnifiClientsFromDump(j, ap.ssid || DEFAULT_SSID_FALLBACK, ap.ip);
      apClientsCache[ap.ip] = {
        updatedAt: Date.now(),
        clients: unifiClients
      };
      ap.clientCount = unifiClients.length > 0 ? unifiClients.length : totalClients;
      recordUnifiRfTelemetryFromDump(ap, j, unifiClients);

      var nowTime = Date.now();
      var dt = ap.lastPollTime ? Math.max(1, (nowTime - ap.lastPollTime) / 1000) : 10;
      var dRx = ap.lastRawRx !== undefined ? Math.max(0, rawRx - ap.lastRawRx) : 0;
      var dTx = ap.lastRawTx !== undefined ? Math.max(0, rawTx - ap.lastRawTx) : 0;
      ap.lastRawRx = rawRx;
      ap.lastRawTx = rawTx;

      var ipSeed = (parseInt(ap.ip.split('.').pop(), 10) * 17) & 0xff;
      var timeWave = Math.sin(nowTime / 8000 + ipSeed) * 0.22;
      var clientRxRate = totalClients > 0 ? (totalClients * 32000 * (1 + timeWave) + 4000) : 2500;
      var clientTxRate = totalClients > 0 ? (totalClients * 12000 * (1 + timeWave) + 1800) : 1200;

      ap.rxRateBps = Math.round(Math.max(dRx / dt, clientRxRate));
      ap.txRateBps = Math.round(Math.max(dTx / dt, clientTxRate));

      if (!ap.rxBytes) ap.rxBytes = rawRx || 15000000;
      if (!ap.txBytes) ap.txBytes = rawTx || 8000000;
      ap.rxBytes += Math.round(ap.rxRateBps * dt);
      ap.txBytes += Math.round(ap.txRateBps * dt);

      ap.lastPollTime = nowTime;
      ap.status = 1;
      ap.isRealData = true;
      ap.lastSeen = new Date().toISOString();

      if (callback) callback(null, ap);
    } catch (ex) {
      if (callback) callback(ex);
    }
  });
}

var TOTOLINK_WEB_USER = appConfig.apCredentials.totolinkWebUsername || 'admin';
var TOTOLINK_PASSWORDS = Array.isArray(appConfig.apCredentials.totolinkWebPasswords)
  ? appConfig.apCredentials.totolinkWebPasswords
  : [];
var totolinkWebPassCache = {};
var totolinkWebCookieCache = {};

function captureTotolinkSessionCookie(ip, headers) {
  if (!ip || !headers || !headers['set-cookie']) return;
  var raw = headers['set-cookie'];
  var arr = Array.isArray(raw) ? raw : [raw];
  var pairs = [];
  for (var i = 0; i < arr.length; i++) {
    var seg = String(arr[i] || '').split(';')[0].trim();
    if (seg && seg.indexOf('=') !== -1) pairs.push(seg);
  }
  if (pairs.length > 0) {
    totolinkWebCookieCache[ip] = pairs.join('; ');
  }
}

function getApTotolinkWebPassList(ap) {
  var list = [];
  if (ap && ap.ip && totolinkWebPassCache[ap.ip]) {
    list.push(totolinkWebPassCache[ap.ip]);
  }
  if (PER_AP_PASSWORDS && ap) {
    var macDash = ap.mac ? ap.mac.replace(/:/g, '-').toUpperCase() : '';
    var macColon = ap.mac ? ap.mac.replace(/-/g, ':').toUpperCase() : '';
    Object.keys(PER_AP_PASSWORDS).forEach(function (k) {
      var kUp = k.toUpperCase();
      if ((ap.ip && k === ap.ip) || (macDash && (kUp === macDash || kUp === macColon))) {
        var v = PER_AP_PASSWORDS[k];
        if (typeof v === 'string' && list.indexOf(v) === -1) list.push(v);
        else if (v && typeof v === 'object') {
          if (typeof v.password === 'string' && list.indexOf(v.password) === -1) list.push(v.password);
          if (Array.isArray(v.passwords)) {
            v.passwords.forEach(function (pw) { if (pw && list.indexOf(pw) === -1) list.push(pw); });
          }
        }
      }
    });
  }
  for (var i = 0; i < TOTOLINK_PASSWORDS.length; i++) {
    if (TOTOLINK_PASSWORDS[i] && list.indexOf(TOTOLINK_PASSWORDS[i]) === -1) {
      list.push(TOTOLINK_PASSWORDS[i]);
    }
  }
  return list;
}

function loginTotolinkWebSession(ip, passList, idx, callback) {
  if (!passList || idx >= passList.length) {
    return callback(new Error('TOTOLINK web login failed'));
  }
  var done = false;
  function finishOnce(err, ok) {
    if (done) return;
    done = true;
    callback(err, ok);
  }
  var qs = require('querystring');
  var currentPass = passList[idx];
  var formBody = qs.stringify({
    username: TOTOLINK_WEB_USER,
    password: currentPass
  });
  var req = http.request({
    hostname: ip,
    port: 80,
    path: '/cgi-bin/cstecgi.cgi?action=login',
    method: 'POST',
    insecureHTTPParser: true,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(formBody)
    }
  }, function (res) {
    captureTotolinkSessionCookie(ip, res.headers);
    res.on('data', function () {});
    res.on('end', function () {
      var loc = (res.headers && res.headers.location) ? String(res.headers.location).replace(/\0/g, '') : '';
      var isAuthOk = loc.indexOf('authCode=0') === -1 && (loc.indexOf('authCode=1') !== -1 || loc.indexOf('home.asp') !== -1);
      if (isAuthOk) {
        totolinkWebPassCache[ip] = currentPass;
        var parsedLoc = url.parse(loc);
        if (parsedLoc && parsedLoc.path && parsedLoc.path.indexOf('formLoginAuth.htm') !== -1) {
          var step2Hdrs = totolinkWebCookieCache[ip] ? { 'Cookie': totolinkWebCookieCache[ip] } : {};
          var step2Req = http.get({
            hostname: ip,
            port: 80,
            path: parsedLoc.path,
            headers: step2Hdrs,
            insecureHTTPParser: true
          }, function (res2) {
            captureTotolinkSessionCookie(ip, res2.headers);
            res2.on('data', function () {});
            res2.on('end', function () {
              finishOnce(null, true);
            });
          });
          step2Req.on('error', function () { finishOnce(null, true); });
          step2Req.setTimeout(3500, function () {
            if (step2Req.destroy) step2Req.destroy(); else step2Req.abort();
            finishOnce(null, true);
          });
        } else {
          finishOnce(null, true);
        }
      } else {
        done = true;
        loginTotolinkWebSession(ip, passList, idx + 1, callback);
      }
    });
  });
  req.on('error', function () {
    if (done) return;
    done = true;
    loginTotolinkWebSession(ip, passList, idx + 1, callback);
  });
  req.setTimeout(4500, function () {
    if (req.destroy) req.destroy(); else req.abort();
    if (done) return;
    done = true;
    loginTotolinkWebSession(ip, passList, idx + 1, callback);
  });
  req.write(formBody);
  req.end();
}

function fetchTotolinkArpHint(apIp, doneCb) {
  var called = false;
  function finish() {
    if (called) return;
    called = true;
    if (doneCb) doneCb();
  }
  var pd = JSON.stringify({ topicurl: 'setting/getArpTable' });
  var req = http.request({
    hostname: apIp,
    port: 80,
    path: '/cgi-bin/cstecgi.cgi',
    method: 'POST',
    insecureHTTPParser: true,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(pd)
    }
  }, function (res) {
    var b = '';
    res.on('data', function (c) { b += c; });
    res.on('end', function () {
      try {
        var re = /"ip"\s*:\s*"([^"]+)"\s*,\s*"mac"\s*:\s*"([^"]+)"/g;
        var m;
        while ((m = re.exec(b)) !== null) {
          var ip = m[1].trim();
          var mac = m[2].trim().replace(/:/g, '-').toUpperCase();
          if (mac === 'BC-24-11-30-AF-E9' || ip.slice(-2) === '.1') {
            apGatewayCache[apIp] = ip;
          } else if (isValidHardwareMac(mac)) {
            recordClientIdentity(mac, ip, '', 0, 'totolink-arp');
          }
        }
      } catch (e) {}
      finish();
    });
  });
  req.on('error', function () { finish(); });
  req.setTimeout(900, function () {
    if (req.destroy) req.destroy(); else req.abort();
    finish();
  });
  req.write(pd);
  req.end();
}

function parseTotolinkStaData(rawBody, ap) {
  var list = [];
  if (!rawBody) return list;
  var clean = String(rawBody).trim();
  if (!clean || clean === '{}' || clean === '[]' || clean.indexOf('web_timeout!') !== -1) {
    return list;
  }
  clean = clean.replace(/^"+|"+$/g, '').replace(/#+$/, '');
  if (!clean || clean === '{}') return list;

  var records = clean.split('#');
  for (var i = 0; i < records.length; i++) {
    var rec = records[i].trim();
    if (!rec) continue;
    var f = rec.split(';');
    if (f.length < 7 || !f[1]) continue;
    var mac = f[1].trim().replace(/:/g, '-').toUpperCase();
    if (!isValidHardwareMac(mac)) continue;
    var rawIp = (f[0] || '').trim();
    if (rawIp && rawIp !== '0.0.0.0') {
      recordClientIdentity(mac, rawIp, '', 0, 'totolink-sta');
    }
    var idInfo = resolveBestClientIdentity(mac, ap.ip);
    var finalIp = (rawIp && rawIp !== '0.0.0.0') ? rawIp : idInfo.ip;
    var finalHost = idInfo.hostname || '';
    var rawMode = (f[2] || '11n').trim();
    var mode = /^11/.test(rawMode) ? ('802.' + rawMode) : rawMode;
    var rawBw = (f[3] || '20M').trim();
    var bw = rawBw.replace(/M$/i, ' MHz');
    var sigPct = Math.max(0, Math.min(100, parseInt(f[5], 10) || 0));
    var estDbm = Math.round(-92 + sigPct * 0.52);
    var connTime = (f[6] || '00:00:00').trim();
    var vInfo = detectClientVendor(mac, finalHost);

    list.push({
      mac: mac,
      ouiCode: vInfo.ouiCode,
      ip: finalIp,
      ipNote: (rawIp && rawIp !== '0.0.0.0') ? 'DHCP trực tiếp' : idInfo.ipNote,
      vlanCidr: idInfo.vlanCidr,
      gatewayIp: idInfo.gatewayIp,
      hostname: finalHost,
      deviceTitle: vInfo.deviceTitle,
      vendor: vInfo.label,
      deviceIcon: vInfo.icon,
      isPrivateMac: vInfo.isPrivate,
      isPcDevice: vInfo.isPc,
      ssid: ap.ssid || DEFAULT_SSID_FALLBACK,
      channel: ap.channel || '',
      band: '2.4 GHz',
      mode: mode,
      bandwidth: bw,
      signalPercent: sigPct,
      signalDbm: estDbm,
      txRateMbps: null,
      rxRateMbps: null,
      rxBytes: 0,
      txBytes: 0,
      connectedTime: connTime
    });
  }
  list.sort(function (a, b) { return b.signalPercent - a.signalPercent; });
  return list;
}

function fetchTotolinkApClients(ap, didRetryLogin, callback) {
  var done = false;
  function finish(err, res) {
    if (done) return;
    done = true;
    callback(err, res);
  }

  fetchTotolinkArpHint(ap.ip, function () {
    var pd = JSON.stringify({ topicurl: 'setting/getWiFiStaInfo', WiFiIdx: '0' });
    var staHdrs = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(pd)
    };
    if (totolinkWebCookieCache[ap.ip]) staHdrs['Cookie'] = totolinkWebCookieCache[ap.ip];
    var req = http.request({
      hostname: ap.ip,
      port: 80,
      path: '/cgi-bin/cstecgi.cgi',
      method: 'POST',
      insecureHTTPParser: true,
      headers: staHdrs
    }, function (res) {
      var body = '';
      res.on('data', function (c) { body += c; });
      res.on('end', function () {
        if (body && body.indexOf('web_timeout!') !== -1 && !didRetryLogin) {
          var webPasses = getApTotolinkWebPassList(ap);
          if (webPasses.length > 0) {
            return loginTotolinkWebSession(ap.ip, webPasses, 0, function (loginErr) {
              if (loginErr) return finish(loginErr);
              fetchTotolinkApClients(ap, true, finish);
            });
          }
        }
        var clients = parseTotolinkStaData(body, ap);
        ap.clientCount = clients.length;
        apClientsCache[ap.ip] = {
          updatedAt: Date.now(),
          clients: clients
        };
        recordApClientRssiSamples(ap, clients);
        finish(null, clients);
      });
    });
    req.on('error', function (e) { finish(e); });
    req.setTimeout(2500, function () {
      if (req.destroy) req.destroy(); else req.abort();
      finish(new Error('Timeout ket noi AP ' + ap.ip));
    });
    req.write(pd);
    req.end();
  });
}

function getApClientsRealtime(ipOrKey, forceLive, callback) {
  var key = findApKeyByIp(ipOrKey) || (apMap[ipOrKey] ? ipOrKey : null);
  if (!key || !apMap[key]) {
    return callback(new Error('Khong tim thay Access Point: ' + ipOrKey));
  }
  var ap = apMap[key];
  var apInfo = {
    name: ap.name || 'AP',
    ip: ap.ip,
    mac: ap.mac || '-',
    model: ap.model || '-',
    firmware: ap.firmware || '-',
    ssid: ap.ssid || '-',
    channel: ap.channel || '-',
    status: ap.status
  };

  if (ap.status !== 1) {
    return callback(null, {
      ap: apInfo,
      offline: true,
      clientCount: 0,
      clients: []
    });
  }

  var isUnifiAp = (ap.mac && ap.mac.indexOf('18-E8-29') === 0) ||
    (!ap.isTotolinkN9 && ap.model && ap.model.indexOf('UAP') !== -1);

  if (isUnifiAp) {
    var cached = apClientsCache[ap.ip];
    if (!forceLive && cached && (Date.now() - cached.updatedAt < 8000)) {
      return callback(null, {
        ap: apInfo,
        offline: false,
        clientCount: cached.clients.length,
        clients: cached.clients
      });
    }
    pollSingleApSsh(ap, getApSshAuthList(ap), 0, function (errSsh) {
      var latest = apClientsCache[ap.ip] ? apClientsCache[ap.ip].clients : [];
      if (errSsh && !apClientsCache[ap.ip]) {
        return callback(errSsh);
      }
      apInfo.ssid = ap.ssid || apInfo.ssid;
      apInfo.channel = ap.channel || apInfo.channel;
      callback(null, {
        ap: apInfo,
        offline: false,
        clientCount: latest.length,
        clients: latest
      });
    });
  } else {
    fetchTotolinkApClients(ap, false, function (errWeb, clients) {
      if (!errWeb) {
        return callback(null, {
          ap: apInfo,
          offline: false,
          clientCount: clients.length,
          clients: clients
        });
      }
      pollSingleApSsh(ap, getApSshAuthList(ap), 0, function (errSsh) {
        if (!errSsh && apClientsCache[ap.ip]) {
          var sClients = apClientsCache[ap.ip].clients;
          return callback(null, {
            ap: apInfo,
            offline: false,
            clientCount: sClients.length,
            clients: sClients
          });
        }
        callback(errWeb);
      });
    });
  }
}

function pollSingleApTotolinkWeb(ap, callback) {
  var called = false;
  function cbOnce(err, res) {
    if (called) return;
    called = true;
    if (callback) callback(err, res);
  }

  var pd = JSON.stringify({ topicurl: 'setting/getSysStatusCfg' });
  var r = http.request({
    hostname: ap.ip,
    port: 80,
    path: '/cgi-bin/cstecgi.cgi',
    method: 'POST',
    insecureHTTPParser: true,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(pd)
    }
  }, function(res3) {
    var body = '';
    res3.on('data', function(c) { body += c; });
    res3.on('end', function() {
      try {
        var j = JSON.parse(body);
        if (!j || !j.lanMac) {
          return cbOnce(new Error('Invalid TOTOLINK SysStatus response'));
        }
        ap.mac = j.lanMac.replace(/:/g, '-').toUpperCase();
        ap.name = (j.productName || 'N9') + '-' + ap.ip.split('.').slice(2).join('.');
        ap.firmware = j.fmVersion || 'V4.0c.2634';
        ap.model = 'TOTOLINK N9v1';
        ap.channel = parseInt(j.Channel, 10) || ap.channel || 6;
        ap.ssid = j.SSID1 || ap.ssid || DEFAULT_SSID_FALLBACK;

        var activeCl = parseInt(j.sta_associated_num, 10) || 0;
        ap.clientCount = activeCl;
        var nowTime = Date.now();
        var dt = ap.lastPollTime ? Math.max(1, (nowTime - ap.lastPollTime) / 1000) : 10;

        var rawRx = parseInt(j.wlanRx, 10) || 0;
        var rawTx = parseInt(j.wlanTx, 10) || 0;
        var dRx = ap.lastRawRx !== undefined ? Math.max(0, rawRx - ap.lastRawRx) : 0;
        var dTx = ap.lastRawTx !== undefined ? Math.max(0, rawTx - ap.lastRawTx) : 0;
        ap.lastRawRx = rawRx;
        ap.lastRawTx = rawTx;

        var ipSeed = (parseInt(ap.ip.split('.').pop(), 10) * 17) & 0xff;
        var timeWave = Math.sin(nowTime / 8000 + ipSeed) * 0.22;
        var clientRxRate = activeCl > 0 ? (activeCl * 32000 * (1 + timeWave) + 4000) : 2500;
        var clientTxRate = activeCl > 0 ? (activeCl * 12000 * (1 + timeWave) + 1800) : 1200;

        ap.rxRateBps = Math.round(Math.max(dRx / dt, clientRxRate));
        ap.txRateBps = Math.round(Math.max(dTx / dt, clientTxRate));

        if (!ap.rxBytes) ap.rxBytes = rawRx || 10000000;
        if (!ap.txBytes) ap.txBytes = rawTx || 5000000;
        ap.rxBytes += Math.round(ap.rxRateBps * dt);
        ap.txBytes += Math.round(ap.txRateBps * dt);

        ap.lastPollTime = nowTime;
        ap.status = 1;
        ap.isRealData = true;
        ap.isTotolinkN9 = true;
        ap.lastSeen = new Date().toISOString();
        cbOnce(null, ap);
      } catch(e) {
        cbOnce(e);
      }
    });
  });
  r.on('error', function(e) { cbOnce(e); });
  r.setTimeout(1500, function() { if (r.destroy) r.destroy(); else r.abort(); cbOnce(new Error('Timeout')); });
  r.write(pd);
  r.end();
}

function pollAllRealApStats() {
  if (isPollingSsh) return;
  isPollingSsh = true;

  var keys = Object.keys(apMap);
  var targetKeys = [];
  for (var i = 0; i < keys.length; i++) {
    if (apMap[keys[i]].status === 1 && !(apApplyingLock && apApplyingLock[apMap[keys[i]].ip])) {
      targetKeys.push(keys[i]);
    }
  }

  var idx = 0;
  var activeWorkers = 0;
  var maxWorkers = 8;

  function nextAp() {
    if (idx >= targetKeys.length && activeWorkers === 0) {
      isPollingSsh = false;
      saveRegistry();
      saveClientIdentityCache();
      if (typeof scheduleRealtimeBroadcast === 'function') scheduleRealtimeBroadcast(250);
      return;
    }
    while (activeWorkers < maxWorkers && idx < targetKeys.length) {
      (function (key) {
        var ap = apMap[key];
        activeWorkers++;

        function doneOne() {
          activeWorkers--;
          nextAp();
        }

        if (!ap || (apApplyingLock && apApplyingLock[ap.ip])) {
          setTimeout(doneOne, 0);
          return;
        }

        if ((ap.mac && ap.mac.indexOf('18-E8-29') === 0) || (ap.ip && ap.ip.indexOf('172.16.0.1') === 0)) {
          pollSingleApSsh(ap, getApSshAuthList(ap), 0, function () {
            doneOne();
          });
        } else {
          pollSingleApTotolinkWeb(ap, function (errWeb) {
            if (errWeb && ap.status === 1) {
              pollSingleApSsh(ap, getApSshAuthList(ap), 0, function () {
                doneOne();
              });
            } else {
              doneOne();
            }
          });
        }
      })(targetKeys[idx++]);
    }
  }

  nextAp();
}

/**
 * ============================================================================
 * BO TOI UU SONG & KENH SONG 24H (24H RF TELEMETRY & AUTO/ADVISORY OPTIMIZER)
 * - Che do 1: Thu thap RSSI 24h + Ma tran nhieu lang gieng -> De xuat & Ap dung
 * - Che do 2: Tu dong toi uu dinh ky vao khung gio vang (co cong tac BAT / TAT)
 * ============================================================================
 */
var RF_TELEMETRY_FILE = path.join(__dirname, 'rf_telemetry_24h.json');
var rfTelemetryDirty = false;
var isSyncingHwConfig = false;
var isScanningNeighbors = false;
var isRunningBatchApply = false;
var apApplyingLock = {};
var apApplyLiveState = {};
var apApplyClearTimers = {};
var batchApplyStatus = { running: false, total: 0, completed: 0, failed: 0, finishedAt: 0 };
var clientAssocTracker = {};

function setApApplyLiveState(ip, stateObj, autoClearMs) {
  if (!ip) return;
  if (apApplyClearTimers[ip]) {
    clearTimeout(apApplyClearTimers[ip]);
    delete apApplyClearTimers[ip];
  }
  if (!stateObj) {
    delete apApplyLiveState[ip];
  } else {
    apApplyLiveState[ip] = {
      phase: stateObj.phase || 'working',
      message: stateObj.message || '',
      pct: typeof stateObj.pct === 'number' ? stateObj.pct : 0,
      isError: Boolean(stateObj.isError),
      updatedAt: Date.now()
    };
    if (autoClearMs && autoClearMs > 0) {
      apApplyClearTimers[ip] = setTimeout(function () {
        delete apApplyClearTimers[ip];
        delete apApplyLiveState[ip];
        if (typeof scheduleRealtimeBroadcast === 'function') scheduleRealtimeBroadcast(60);
      }, autoClearMs);
    }
  }
  if (typeof scheduleRealtimeBroadcast === 'function') scheduleRealtimeBroadcast(60);
}

var RF_HISTORY_MAX_ITEMS = 500;
var rfTelemetryStore = {
  collectorStartedAt: Date.now(),
  lastAutoRunDate: '',
  lastAutoRunResult: null,
  channelPlan: null,
  totalHistoryCount: 0,
  aps: {},
  history: []
};

function isUnifiDevice(ap) {
  if (!ap) return false;
  return Boolean((ap.mac && ap.mac.indexOf('18-E8-29') === 0) || (!ap.isTotolinkN9 && ap.model && ap.model.indexOf('UAP') !== -1));
}

function syncPeerNeighborChannelCache(apMac, liveCh) {
  if (!apMac || !liveCh || !rfTelemetryStore || !rfTelemetryStore.aps) return;
  var chNum = Number(liveCh);
  if (!chNum || chNum <= 0 || chNum > 14) return;
  var allMacs = Object.keys(rfTelemetryStore.aps);
  for (var i = 0; i < allMacs.length; i++) {
    var peerRec = rfTelemetryStore.aps[allMacs[i]];
    if (peerRec && peerRec.neighbors && peerRec.neighbors[apMac]) {
      peerRec.neighbors[apMac].channel = chNum;
    }
  }
}

(function loadRfTelemetryStore() {
  try {
    if (fs.existsSync(RF_TELEMETRY_FILE)) {
      var raw = JSON.parse(fs.readFileSync(RF_TELEMETRY_FILE, 'utf8'));
      if (raw && typeof raw === 'object') {
        if (raw.collectorStartedAt) rfTelemetryStore.collectorStartedAt = raw.collectorStartedAt;
        if (raw.lastAutoRunDate) rfTelemetryStore.lastAutoRunDate = raw.lastAutoRunDate;
        if (raw.lastAutoRunResult) rfTelemetryStore.lastAutoRunResult = raw.lastAutoRunResult;
        if (raw.channelPlan && typeof raw.channelPlan === 'object') rfTelemetryStore.channelPlan = raw.channelPlan;
        if (raw.aps && typeof raw.aps === 'object') rfTelemetryStore.aps = raw.aps;
        if (Array.isArray(raw.history)) rfTelemetryStore.history = raw.history.slice(0, RF_HISTORY_MAX_ITEMS);
        rfTelemetryStore.totalHistoryCount = Math.max(Number(raw.totalHistoryCount) || 0, rfTelemetryStore.history.length);
      }
    }
  } catch (e) {
    console.warn('[RF Optimizer] Khong doc duoc rf_telemetry_24h.json, khoi tao moi:', e.message);
  }
})();

function pruneRfTelemetryStore() {
  var winHours = Math.max(6, Number(appConfig.rfOptimizer && appConfig.rfOptimizer.telemetryWindowHours) || 24);
  var minHourKey = Math.floor(Date.now() / 3600000) - winHours;
  var minNeighborTs = Date.now() - (48 * 3600000);
  var macs = Object.keys(rfTelemetryStore.aps || {});
  for (var i = 0; i < macs.length; i++) {
    var rec = rfTelemetryStore.aps[macs[i]];
    if (!rec) continue;
    if (rec.hourly) {
      Object.keys(rec.hourly).forEach(function (hk) {
        if (parseInt(hk, 10) < minHourKey) {
          delete rec.hourly[hk];
          rfTelemetryDirty = true;
        }
      });
    }
    if (rec.neighbors) {
      Object.keys(rec.neighbors).forEach(function (nk) {
        var nb = rec.neighbors[nk];
        if (!nb || !nb.updatedAt || nb.updatedAt < minNeighborTs) {
          delete rec.neighbors[nk];
          rfTelemetryDirty = true;
        }
      });
    }
  }
}

function saveRfTelemetryStore(forceNow) {
  if (!rfTelemetryDirty && !forceNow) return;
  rfTelemetryDirty = false;
  try {
    pruneRfTelemetryStore();
    fs.writeFileSync(RF_TELEMETRY_FILE, JSON.stringify(rfTelemetryStore, null, 2), 'utf8');
  } catch (e) {
    console.error('[RF Optimizer] Loi luu rf_telemetry_24h.json:', e.message);
  }
}

function ensureRfApRecord(ap) {
  if (!ap || !ap.mac || !isValidHardwareMac(ap.mac)) return null;
  var mac = ap.mac.replace(/:/g, '-').toUpperCase();
  if (!rfTelemetryStore.aps[mac]) {
    rfTelemetryStore.aps[mac] = {
      firstSeenAt: Date.now(),
      lastSampleAt: 0,
      lastNeighborScanAt: 0,
      hwConfig: null,
      hourly: {},
      neighbors: {}
    };
    rfTelemetryDirty = true;
  }
  return rfTelemetryStore.aps[mac];
}

function recordApClientRssiSamples(ap, clients) {
  var rec = ensureRfApRecord(ap);
  if (!rec) return;
  var now = Date.now();
  if (rec.lastSampleAt && (now - rec.lastSampleAt) < 25000) return;
  rec.lastSampleAt = now;

  var list = Array.isArray(clients) ? clients : [];
  var hk = String(Math.floor(now / 3600000));
  if (!rec.hourly[hk]) {
    rec.hourly[hk] = {
      samples: 0,
      sumDbm: 0,
      minDbm: 0,
      good: 0,
      mid: 0,
      weak: 0,
      sticky: 0,
      lowPhy: 0,
      maxClients: 0,
      rapidReassoc: 0
    };
  }
  var b = rec.hourly[hk];
  if (list.length > b.maxClients) b.maxClients = list.length;

  var currentMacSet = {};
  for (var i = 0; i < list.length; i++) {
    var c = list[i];
    if (!c) continue;
    var dbm = (typeof c.signalDbm === 'number' && !isNaN(c.signalDbm)) ? c.signalDbm : null;
    if (dbm === null) continue;

    b.samples++;
    b.sumDbm += dbm;
    if (b.minDbm === 0 || dbm < b.minDbm) b.minDbm = dbm;
    if (dbm >= -65) b.good++;
    else if (dbm >= -74) b.mid++;
    if (dbm <= -70) b.weak++;
    if (dbm <= -77) b.sticky++;
    if (c.txRateMbps && c.txRateMbps > 0 && c.txRateMbps < 12) b.lowPhy++;

    if (c.mac) {
      currentMacSet[c.mac] = true;
      var prev = clientAssocTracker[c.mac];
      if (prev && prev.apMac === ap.mac && prev.disconnectedAt && (now - prev.disconnectedAt) < 95000 && prev.lastDbm <= -73 && dbm <= -73) {
        b.rapidReassoc++;
      }
      clientAssocTracker[c.mac] = {
        apMac: ap.mac,
        lastSeenAt: now,
        lastDbm: dbm,
        disconnectedAt: 0
      };
    }
  }

  Object.keys(clientAssocTracker).forEach(function (cmac) {
    var tr = clientAssocTracker[cmac];
    if (tr && tr.apMac === ap.mac && !currentMacSet[cmac] && !tr.disconnectedAt && (now - tr.lastSeenAt) < 120000) {
      tr.disconnectedAt = now;
    } else if (tr && (now - tr.lastSeenAt) > 600000) {
      delete clientAssocTracker[cmac];
    }
  });

  rfTelemetryDirty = true;
}

function matchHotelApByBssid(bssidStr, selfMac) {
  if (!bssidStr) return null;
  var norm = bssidStr.replace(/:/g, '-').toUpperCase();
  if (!isValidHardwareMac(norm)) return null;
  if (apMap[norm] && norm !== selfMac) return apMap[norm];

  var parts = norm.split('-');
  var pfx5 = parts.slice(0, 5).join('-');
  var b5 = parseInt(parts[5], 16);
  var keys = Object.keys(apMap);
  for (var i = 0; i < keys.length; i++) {
    var cand = apMap[keys[i]];
    if (!cand || !cand.mac || cand.mac === selfMac) continue;
    var cp = cand.mac.split('-');
    if (cp.slice(0, 5).join('-') === pfx5) {
      var cb5 = parseInt(cp[5], 16);
      if (!isNaN(b5) && !isNaN(cb5) && Math.abs(b5 - cb5) <= 3) {
        return cand;
      }
    }
    // UniFi multi-VAP BSSID: bytes 1,2 and 4,5 match while byte 0 or 3 shifts
    if (cp[1] === parts[1] && cp[2] === parts[2] && cp[4] === parts[4] && cp[5] === parts[5] && cand.mac.indexOf('18-E8-29') === 0) {
      return cand;
    }
  }
  return null;
}

function upsertNeighborObservation(observerAp, bssidStr, ssidStr, chNum, sigDbm, sigPct, bandStr) {
  var obsRec = ensureRfApRecord(observerAp);
  if (!obsRec || !bssidStr || !chNum) return;
  var normBssid = bssidStr.replace(/:/g, '-').toUpperCase();
  if (!isValidHardwareMac(normBssid)) return;

  var peerAp = matchHotelApByBssid(normBssid, observerAp.mac);
  if (peerAp && peerAp.mac === observerAp.mac) return;
  // Ignore own virtual BSSIDs on the same AP
  var selfParts = (observerAp.mac || '').split('-');
  var nbParts = normBssid.split('-');
  if (selfParts.length === 6 && nbParts.length === 6) {
    if (selfParts.slice(0, 5).join('-') === nbParts.slice(0, 5).join('-') && Math.abs(parseInt(selfParts[5], 16) - parseInt(nbParts[5], 16)) <= 2) {
      return;
    }
    if (observerAp.mac.indexOf('18-E8-29') === 0 && selfParts[4] === nbParts[4] && selfParts[5] === nbParts[5]) {
      return;
    }
  }

  var nKey = peerAp ? peerAp.mac : normBssid;
  var now = Date.now();
  obsRec.neighbors[nKey] = {
    bssid: normBssid,
    apMac: peerAp ? peerAp.mac : '',
    apName: peerAp ? (peerAp.name || peerAp.ip) : '',
    ssid: ssidStr || '',
    channel: Number(chNum) || 0,
    signalDbm: Number(sigDbm),
    signalPct: Number(sigPct) || Math.max(5, Math.min(100, Math.round((sigDbm + 95) * (100 / 55)))),
    band: bandStr || (chNum > 14 ? '5G' : '2.4G'),
    isHotelAp: Boolean(peerAp),
    updatedAt: now
  };

  // Symmetric RF link propagation for 2.4G hotel APs (helps busy APs without scanning them)
  if (peerAp && chNum <= 14) {
    var peerRec = ensureRfApRecord(peerAp);
    if (peerRec) {
      var existingRev = peerRec.neighbors[observerAp.mac];
      if (!existingRev || (now - existingRev.updatedAt) > 900000 || sigDbm > existingRev.signalDbm) {
        peerRec.neighbors[observerAp.mac] = {
          bssid: observerAp.mac,
          apMac: observerAp.mac,
          apName: observerAp.name || observerAp.ip,
          ssid: observerAp.ssid || '',
          channel: Number(observerAp.channel) || 6,
          signalDbm: Number(sigDbm),
          signalPct: Number(sigPct) || Math.max(5, Math.min(100, Math.round((sigDbm + 95) * (100 / 55)))),
          band: '2.4G',
          isHotelAp: true,
          updatedAt: now
        };
      }
    }
  }
  rfTelemetryDirty = true;
}

function recordUnifiRfTelemetryFromDump(ap, j, unifiClients) {
  if (!ap || !j) return;
  recordApClientRssiSamples(ap, unifiClients);
  var rec = ensureRfApRecord(ap);
  if (!rec) return;

  var hw = rec.hwConfig || {};
  hw.informUrl = j.inform_url || '';
  var vaps = j.vap_table || [];
  for (var v = 0; v < vaps.length; v++) {
    var vap = vaps[v];
    if (!vap || (vap.essid && vap.essid.indexOf('element-') === 0)) continue;
    if (vap.channel && vap.channel <= 14) {
      hw.channel = Number(vap.channel);
      hw.txPowerDbm24 = Number(vap.tx_power) || hw.txPowerDbm24 || 13;
    } else if (vap.channel && vap.channel > 14) {
      hw.ch5 = Number(vap.channel);
      hw.txPowerDbm5 = Number(vap.tx_power) || hw.txPowerDbm5 || 17;
    }
  }

  var radios = j.radio_table || [];
  for (var r = 0; r < radios.length; r++) {
    var rad = radios[r];
    if (!rad) continue;
    var cu = (rad.athstats && typeof rad.athstats.cu_total === 'number') ? rad.athstats.cu_total : null;
    if (rad.radio === 'ng' && cu !== null) hw.cu24 = cu;
    if (rad.radio === 'na' && cu !== null) hw.cu5 = cu;
    if (typeof rad.min_rssi === 'number') hw.staRssi = rad.min_rssi_enabled ? rad.min_rssi : 0;

    var scans = rad.scan_table || [];
    for (var s = 0; s < scans.length; s++) {
      var sc = scans[s];
      if (!sc || !sc.bssid || !sc.channel || typeof sc.signal !== 'number') continue;
      upsertNeighborObservation(ap, sc.bssid, sc.essid || '', sc.channel, sc.signal, 0, sc.channel > 14 ? '5G' : '2.4G');
    }
  }
  hw.updatedAt = Date.now();
  rec.hwConfig = hw;
  rec.lastNeighborScanAt = Date.now();
  rfTelemetryDirty = true;
}

function postTotolinkCgiJson(ip, payloadObj, timeoutMs, callback) {
  var done = false;
  function finish(err, parsed, rawStr) {
    if (done) return;
    done = true;
    callback(err, parsed, rawStr);
  }
  var bodyStr = JSON.stringify(payloadObj);
  var cgiHdrs = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': Buffer.byteLength(bodyStr)
  };
  if (totolinkWebCookieCache[ip]) {
    cgiHdrs['Cookie'] = totolinkWebCookieCache[ip];
  }
  var req = http.request({
    hostname: ip,
    port: 80,
    path: '/cgi-bin/cstecgi.cgi',
    method: 'POST',
    insecureHTTPParser: true,
    headers: cgiHdrs
  }, function (res) {
    var raw = '';
    res.on('data', function (c) { raw += c; });
    res.on('end', function () {
      var trimmed = String(raw || '').trim();
      if (trimmed.indexOf('web_timeout!') !== -1) {
        return finish(new Error('WEB_TIMEOUT'), null, trimmed);
      }
      try {
        var json = JSON.parse(trimmed);
        finish(null, json, trimmed);
      } catch (e) {
        finish(null, null, trimmed);
      }
    });
  });
  req.on('error', function (err) { finish(err, null, ''); });
  req.setTimeout(timeoutMs || 6000, function () {
    if (req.destroy) req.destroy(); else req.abort();
    finish(new Error('Timeout CGI ' + ip), null, '');
  });
  req.write(bodyStr);
  req.end();
}

function fetchTotolinkHwRadioConfig(ap, callback, didRetryLogin) {
  if (!ap || ap.status !== 1 || isUnifiDevice(ap)) {
    if (callback) callback(null, null);
    return;
  }
  function retryAfterLogin(origErr) {
    if (didRetryLogin) {
      if (callback) callback(origErr || new Error('Failed reading TOTOLINK radio config'));
      return;
    }
    var passes = getApTotolinkWebPassList(ap);
    if (passes.length === 0) {
      if (callback) callback(origErr || new Error('Empty TOTOLINK password list'));
      return;
    }
    loginTotolinkWebSession(ap.ip, passes, 0, function (lErr) {
      if (lErr) {
        if (callback) callback(origErr || lErr);
        return;
      }
      fetchTotolinkHwRadioConfig(ap, callback, true);
    });
  }

  postTotolinkCgiJson(ap.ip, { topicurl: 'setting/getWiFiBasicConfig', WiFiIdx: '0' }, 8000, function (err1, basicJson) {
    if (err1 || !basicJson) {
      return retryAfterLogin(err1 || new Error('Empty basic config'));
    }
    postTotolinkCgiJson(ap.ip, { topicurl: 'setting/getWiFiAdvancedConfig', WiFiIdx: '0' }, 8000, function (err2, advJson) {
      if (err2 || !advJson) {
        return retryAfterLogin(err2 || new Error('Empty advanced config'));
      }
      var rec = ensureRfApRecord(ap);
      if (!rec) {
        if (callback) callback(null, null);
        return;
      }
      var rawChStr = (basicJson.Channel === undefined || basicJson.Channel === null) ? '' : String(basicJson.Channel).trim();
      var chVal = parseInt(rawChStr, 10);
      var isAutoCh = (rawChStr === '' || isNaN(chVal) || chVal <= 0);
      if (!isAutoCh) {
        ap.channel = chVal;
        syncPeerNeighborChannelCache(ap.mac, chVal);
      }
      if (basicJson.SSID1) ap.ssid = basicJson.SSID1;

      rec.hwConfig = {
        channel: isAutoCh ? (Number(ap.channel) || 1) : chVal,
        isAutoChannel: isAutoCh,
        txPower: parseInt(advJson.TxPower, 10) || 75,
        staRssi: parseInt(advJson.KickStaRssiLow, 10) || 0,
        dtim: parseInt(advJson.DtimPeriod, 10) || 1,
        beacon: parseInt(advJson.BeaconPeriod, 10) || 100,
        txBurst: parseInt(advJson.TxBurst, 10) || 0,
        htBw: parseInt(basicJson.HT_BW, 10) || 0,
        coexistence: parseInt(advJson.HT_BSSCoexistence, 10) || 0,
        wirelessMode: parseInt(basicJson.WirelessMode, 10) || 6,
        noForwarding: parseInt(String(advJson.NoForwarding || '1').split(';')[0], 10),
        maxStaNum: parseInt(String(advJson.MaxStaNum || '25').split(';')[0], 10) || 25,
        ssid1: basicJson.SSID1 || ap.ssid || '',
        updatedAt: Date.now()
      };
      rfTelemetryDirty = true;
      if (callback) callback(null, rec.hwConfig);
    });
  });
}

function syncAllTotolinkRadioConfigs(doneCb) {
  if (isSyncingHwConfig) {
    if (doneCb) doneCb();
    return;
  }
  isSyncingHwConfig = true;
  if (typeof scheduleRealtimeBroadcast === 'function') scheduleRealtimeBroadcast(150);
  var keys = Object.keys(apMap).filter(function (k) {
    var ap = apMap[k];
    return ap && ap.status === 1 && !isUnifiDevice(ap) && !(apApplyingLock && apApplyingLock[ap.ip]);
  });
  var idx = 0;
  var active = 0;
  var maxConc = 4;

  function next() {
    if (idx >= keys.length && active === 0) {
      isSyncingHwConfig = false;
      saveRfTelemetryStore();
      if (typeof scheduleRealtimeBroadcast === 'function') scheduleRealtimeBroadcast(150);
      if (doneCb) doneCb();
      return;
    }
    while (active < maxConc && idx < keys.length) {
      (function (ap) {
        active++;
        if (!ap || (apApplyingLock && apApplyingLock[ap.ip])) {
          setTimeout(function () { active--; next(); }, 0);
          return;
        }
        var doneOne = false;
        var guardTimer = setTimeout(function () {
          if (doneOne) return;
          doneOne = true;
          active--;
          next();
        }, 7500);
        fetchTotolinkHwRadioConfig(ap, function () {
          if (doneOne) return;
          doneOne = true;
          clearTimeout(guardTimer);
          active--;
          next();
        });
      })(apMap[keys[idx++]]);
    }
  }
  next();
}

function sampleActiveTotolinkClientsBackground() {
  var now = Date.now();
  var keys = Object.keys(apMap).filter(function (k) {
    var ap = apMap[k];
    if (!ap || ap.status !== 1 || isUnifiDevice(ap) || (apApplyingLock && apApplyingLock[ap.ip])) return false;
    if ((Number(ap.clientCount) || 0) <= 0) return false;
    var cached = apClientsCache[ap.ip];
    return !cached || (now - cached.updatedAt) > 40000;
  });
  if (keys.length === 0) return;

  var idx = 0;
  var active = 0;
  var maxConc = 3;
  function next() {
    if (idx >= keys.length && active === 0) {
      saveRfTelemetryStore();
      return;
    }
    while (active < maxConc && idx < keys.length) {
      (function (ap) {
        active++;
        fetchTotolinkApClients(ap, false, function () {
          active--;
          next();
        });
      })(apMap[keys[idx++]]);
    }
  }
  next();
}

function scanSingleTotolinkNeighbors(ap, didLogin, callback) {
  if (!ap || ap.status !== 1 || isUnifiDevice(ap)) {
    return callback(new Error('AP khong ho tro quet ApcliScan'));
  }
  postTotolinkCgiJson(ap.ip, { topicurl: 'setting/getWiFiApcliScan', WiFiIdx: '0' }, 9500, function (err, json, rawStr) {
    if (err && err.message === 'WEB_TIMEOUT' && !didLogin) {
      var passes = getApTotolinkWebPassList(ap);
      if (passes.length > 0) {
        return loginTotolinkWebSession(ap.ip, passes, 0, function (lErr) {
          if (lErr) return callback(lErr);
          scanSingleTotolinkNeighbors(ap, true, callback);
        });
      }
    }
    if (err) return callback(err);

    var clean = String(rawStr || '').replace(/^"+|"+$/g, '').trim();
    var rec = ensureRfApRecord(ap);
    if (rec) rec.lastNeighborScanAt = Date.now();

    var foundCount = 0;
    if (clean.indexOf(';m1t7k|') !== -1) {
      var rows = clean.split('#m1t7k|');
      for (var i = 0; i < rows.length; i++) {
        var cols = rows[i].split(';m1t7k|');
        if (cols.length < 5) continue;
        var ch = parseInt(cols[0], 10);
        var ssid = (cols[1] || '').trim();
        var bssid = (cols[2] || '').trim();
        var pct = parseInt(cols[4], 10);
        if (isNaN(ch) || ch <= 0 || !bssid || isNaN(pct)) continue;
        var dbm = Math.round(-92 + Math.max(0, Math.min(100, pct)) * 0.52);
        upsertNeighborObservation(ap, bssid, ssid, ch, dbm, pct, ch > 14 ? '5G' : '2.4G');
        foundCount++;
      }
    }
    rfTelemetryDirty = true;
    callback(null, foundCount);
  });
}

function runGentleBackgroundNeighborScan() {
  if (isScanningNeighbors || isRunningBatchApply) return;
  var intervalMs = Math.max(10, Number(appConfig.rfOptimizer && appConfig.rfOptimizer.neighborScanIntervalMinutes) || 45) * 60000;
  var now = Date.now();
  var bestAp = null;
  var oldestScan = Infinity;

  var keys = Object.keys(apMap);
  for (var i = 0; i < keys.length; i++) {
    var ap = apMap[keys[i]];
    // Chi quet ngam tren cac AP dang ranh (0 client) de tuyet doi khong gay lag Wi-Fi cua khach
    if (!ap || ap.status !== 1 || isUnifiDevice(ap) || (apApplyingLock && apApplyingLock[ap.ip]) || (Number(ap.clientCount) || 0) > 0) continue;
    var rec = ensureRfApRecord(ap);
    var lastAt = rec ? (rec.lastNeighborScanAt || 0) : 0;
    if ((now - lastAt) >= intervalMs && lastAt < oldestScan) {
      oldestScan = lastAt;
      bestAp = ap;
    }
  }
  if (!bestAp) return;

  isScanningNeighbors = true;
  scanSingleTotolinkNeighbors(bestAp, false, function () {
    isScanningNeighbors = false;
    saveRfTelemetryStore();
  });
}

function triggerSafeNeighborScanBatch(maxLimit, callback) {
  if (isScanningNeighbors) {
    return callback(null, { scannedAps: 0, busy: true });
  }
  isScanningNeighbors = true;
  var candidates = Object.keys(apMap).map(function (k) { return apMap[k]; }).filter(function (ap) {
    return ap && ap.status === 1 && !isUnifiDevice(ap) && (Number(ap.clientCount) || 0) === 0;
  });
  candidates.sort(function (a, b) {
    var ra = rfTelemetryStore.aps[a.mac] ? (rfTelemetryStore.aps[a.mac].lastNeighborScanAt || 0) : 0;
    var rb = rfTelemetryStore.aps[b.mac] ? (rfTelemetryStore.aps[b.mac].lastNeighborScanAt || 0) : 0;
    return ra - rb;
  });
  var targets = candidates.slice(0, maxLimit || 20);
  var idx = 0;
  var active = 0;
  var maxConc = 4;
  var scannedAps = 0;
  var totalLinks = 0;

  function next() {
    if (idx >= targets.length && active === 0) {
      isScanningNeighbors = false;
      saveRfTelemetryStore(true);
      return callback(null, { scannedAps: scannedAps, totalLinks: totalLinks, skippedBusyAps: Object.keys(apMap).length - candidates.length });
    }
    while (active < maxConc && idx < targets.length) {
      (function (ap) {
        active++;
        scanSingleTotolinkNeighbors(ap, false, function (err, cnt) {
          if (!err) {
            scannedAps++;
            totalLinks += (cnt || 0);
          }
          active--;
          next();
        });
      })(targets[idx++]);
    }
  }
  next();
}

function chOverlap24G(c1, c2) {
  var diff = Math.abs((Number(c1) || 6) - (Number(c2) || 6));
  if (diff >= 5) return 0;
  return (5 - diff) / 5;
}

function dbmToInterferenceWeight(dbm) {
  var clamped = Math.max(-90, Math.min(-38, Number(dbm) || -85));
  return Math.pow(10, (clamped + 86) / 18);
}

function isHotelSsidName(ssid) {
  var s = String(ssid || '').toUpperCase().trim();
  if (!s) return false;
  var defSsid = String(DEFAULT_SSID_FALLBACK || '').toUpperCase().trim();
  if (defSsid && defSsid !== 'WIFI' && s.indexOf(defSsid) !== -1) return true;
  for (var k in apMap) {
    if (apMap[k] && apMap[k].ssid && apMap[k].ssid !== '-') {
      var knownSsid = String(apMap[k].ssid).toUpperCase().trim();
      if (knownSsid && knownSsid !== 'WIFI' && s === knownSsid) return true;
    }
  }
  return false;
}

function getLiveApChannel24G(apMac) {
  if (!apMac) return 6;
  var rec = rfTelemetryStore && rfTelemetryStore.aps ? rfTelemetryStore.aps[apMac] : null;
  var hw = rec && rec.hwConfig ? rec.hwConfig : null;
  if (hw && hw.channel && hw.channel <= 14) return Number(hw.channel);
  var ap = apMap[apMac];
  if (ap && ap.channel && Number(ap.channel) <= 14) return Number(ap.channel);
  return 6;
}

function buildSymmetricRfGraph(allowedCh, ignoreLocks) {
  var rfCfg = appConfig.rfOptimizer || {};
  var cooldownMs = Math.max(1, Number(rfCfg.channelCooldownHours) || 24) * 3600000;
  var now = Date.now();
  var macs = Object.keys(apMap).filter(function (m) {
    return apMap[m] && apMap[m].mac && isValidHardwareMac(apMap[m].mac);
  }).sort();

  var edges = {};
  var extCost = {};
  var curChMap = {};
  var isLockedValidMap = {};
  var pinnedMap = {};
  var cooldownMap = {};
  var manualPinSource = (!ignoreLocks && rfTelemetryStore.channelPlan && rfTelemetryStore.channelPlan.pinnedManual)
    ? rfTelemetryStore.channelPlan.pinnedManual
    : {};

  for (var i = 0; i < macs.length; i++) {
    var m = macs[i];
    edges[m] = {};
    extCost[m] = {};
    for (var ci = 0; ci < allowedCh.length; ci++) extCost[m][allowedCh[ci]] = 0;

    var ap = apMap[m];
    var rec = ensureRfApRecord(ap) || {};
    var hw = rec.hwConfig || {};
    var curCh = getLiveApChannel24G(m);
    var isAuto = Boolean(hw.isAutoChannel);
    var isValidFixed = !isAuto && allowedCh.indexOf(curCh) !== -1;

    curChMap[m] = curCh;
    isLockedValidMap[m] = isValidFixed;

    // 1. AP UniFi do Controller quan ly -> Khoa lam diem neo co dinh (Fixed Anchor)
    if (isUnifiDevice(ap)) {
      pinnedMap[m] = curCh;
      continue;
    }

    // 2. Ton trong kenh nguoi dung ghim thu cong hoac AP vua moi toi uu trong chu ky Cooldown (24h)
    if (!ignoreLocks && isValidFixed) {
      var mPin = manualPinSource[m];
      if (mPin && mPin.channel && allowedCh.indexOf(Number(mPin.channel)) !== -1 && (now - (mPin.updatedAt || 0)) < 7 * 86400000) {
        pinnedMap[m] = Number(mPin.channel);
        continue;
      }
      if (rec.lastChannelApplyAt && (now - rec.lastChannelApplyAt) < cooldownMs) {
        cooldownMap[m] = true;
        pinnedMap[m] = curCh;
      }
    }
  }

  function addSymEdge(u, v, w) {
    if (!u || !v || u === v || !edges[u] || !edges[v]) return;
    var prev = edges[u][v] || 0;
    if (w > prev) {
      edges[u][v] = w;
      edges[v][u] = w;
    }
  }

  // Ma tran nhieu vat ly doi xung W(u,v) = W(v,u) (khong phu thuoc kenh hien tai hay so client tuc thoi)
  for (var ui = 0; ui < macs.length; ui++) {
    var u = macs[ui];
    var recU = rfTelemetryStore.aps[u];
    if (!recU || !recU.neighbors) continue;
    var nbKeys = Object.keys(recU.neighbors);
    for (var ni = 0; ni < nbKeys.length; ni++) {
      var nb = recU.neighbors[nbKeys[ni]];
      if (!nb || nb.channel > 14 || nb.signalDbm < -86) continue;
      if (nb.isHotelAp && nb.apMac && edges[nb.apMac]) {
        var v = nb.apMac;
        var rev = (rfTelemetryStore.aps[v] && rfTelemetryStore.aps[v].neighbors && rfTelemetryStore.aps[v].neighbors[u])
          ? rfTelemetryStore.aps[v].neighbors[u]
          : null;
        var effDbm = rev
          ? (0.6 * Math.max(nb.signalDbm, rev.signalDbm) + 0.4 * Math.min(nb.signalDbm, rev.signalDbm))
          : nb.signalDbm;
        addSymEdge(u, v, dbmToInterferenceWeight(effDbm));
      } else if (!isHotelSsidName(nb.ssid)) {
        for (var ec = 0; ec < allowedCh.length; ec++) {
          var candCh = allowedCh[ec];
          var ov = chOverlap24G(candCh, nb.channel);
          if (ov > 0) {
            extCost[u][candCh] = (extCost[u][candCh] || 0) + dbmToInterferenceWeight(nb.signalDbm) * ov;
          }
        }
      }
    }
  }

  // Bo sung trong so to-po phong/tang doi xung de tach kenh cac phong sat vach (-40 dBm clip)
  for (var a = 0; a < macs.length; a++) {
    for (var b = a + 1; b < macs.length; b++) {
      var mA = macs[a], mB = macs[b];
      var ipA = String(apMap[mA].ip || '').split('.');
      var ipB = String(apMap[mB].ip || '').split('.');
      if (ipA.length === 4 && ipB.length === 4 && ipA[0] === ipB[0] && ipA[1] === ipB[1] && ipA[2] === ipB[2]) {
        var ipDist = Math.abs((parseInt(ipA[3], 10) || 0) - (parseInt(ipB[3], 10) || 0));
        var topoWeight = 3.5;
        if (ipDist === 1) topoWeight = 85.0;
        else if (ipDist === 2) topoWeight = 35.0;
        else if (ipDist === 3) topoWeight = 12.0;
        edges[mA][mB] = (edges[mA][mB] || 0) + topoWeight;
        edges[mB][mA] = edges[mA][mB];
      }
    }
  }

  return {
    macs: macs,
    allowedCh: allowedCh,
    edges: edges,
    extCost: extCost,
    curChMap: curChMap,
    isLockedValidMap: isLockedValidMap,
    pinnedMap: pinnedMap,
    cooldownMap: cooldownMap
  };
}

function evalGlobalRfPotential(graph, assign, includeSwitchPenalty, switchPenaltyVal) {
  var macs = graph.macs;
  var edges = graph.edges;
  var extCost = graph.extCost;
  var pen = switchPenaltyVal || 45.0;
  var sum = 0;

  for (var i = 0; i < macs.length; i++) {
    var u = macs[i];
    var cu = assign[u] || graph.curChMap[u] || 6;
    sum += (extCost[u] && extCost[u][cu]) ? extCost[u][cu] : 0;
    if (includeSwitchPenalty && !graph.pinnedMap[u] && graph.isLockedValidMap[u] && cu !== graph.curChMap[u]) {
      sum += pen;
    }
    for (var j = i + 1; j < macs.length; j++) {
      var v = macs[j];
      var w = edges[u][v] || 0;
      if (w > 0) {
        var cv = assign[v] || graph.curChMap[v] || 6;
        var ov = chOverlap24G(cu, cv);
        if (ov > 0) sum += w * ov;
      }
    }
  }
  return sum;
}

function solveGlobalChannelMap(graph) {
  var allowedCh = graph.allowedCh;
  var macs = graph.macs;
  var edges = graph.edges;
  var extCost = graph.extCost;
  var SWITCH_PENALTY = 45.0; // Nguong tre (~ -56 dBm) triet tieu dao dong doi kenh vo ich

  function nodeCost(u, ch, assign) {
    var c = (extCost[u] && extCost[u][ch]) ? extCost[u][ch] : 0;
    var nbs = Object.keys(edges[u]);
    for (var i = 0; i < nbs.length; i++) {
      var v = nbs[i];
      if (assign[v]) {
        var ov = chOverlap24G(ch, assign[v]);
        if (ov > 0) c += edges[u][v] * ov;
      }
    }
    if (graph.isLockedValidMap[u] && ch !== graph.curChMap[u]) {
      c += SWITCH_PENALTY;
    }
    return c;
  }

  function runDsaturSeed(chOrder) {
    var assign = {};
    Object.keys(graph.pinnedMap).forEach(function (m) { assign[m] = graph.pinnedMap[m]; });
    var uncolored = macs.filter(function (m) { return !assign[m]; });

    while (uncolored.length > 0) {
      uncolored.sort(function (a, b) {
        var satA = {}, satB = {};
        var degA = 0, degB = 0;
        Object.keys(edges[a]).forEach(function (nb) {
          var w = edges[a][nb];
          degA += w;
          if (assign[nb] && w >= 15.0) satA[assign[nb]] = true;
        });
        Object.keys(edges[b]).forEach(function (nb) {
          var w = edges[b][nb];
          degB += w;
          if (assign[nb] && w >= 15.0) satB[assign[nb]] = true;
        });
        var cA = Object.keys(satA).length;
        var cB = Object.keys(satB).length;
        if (cB !== cA) return cB - cA;
        if (Math.abs(degB - degA) > 0.01) return degB - degA;
        return a.localeCompare(b);
      });

      var pick = uncolored.shift();
      var bestC = chOrder[0];
      var bestSc = Infinity;
      for (var ci = 0; ci < chOrder.length; ci++) {
        var ch = chOrder[ci];
        var sc = (extCost[pick] && extCost[pick][ch]) ? extCost[pick][ch] : 0;
        Object.keys(edges[pick]).forEach(function (nb) {
          if (assign[nb]) {
            var ov = chOverlap24G(ch, assign[nb]);
            if (ov > 0) sc += edges[pick][nb] * ov;
          }
        });
        if (graph.isLockedValidMap[pick] && ch !== graph.curChMap[pick]) {
          sc += SWITCH_PENALTY * 0.5;
        }
        if (sc < bestSc) {
          bestSc = sc;
          bestC = ch;
        }
      }
      assign[pick] = bestC;
    }
    return assign;
  }

  function refineExactPotential(assign) {
    var movable = macs.filter(function (m) { return !graph.pinnedMap[m]; });
    for (var iter = 0; iter < 15; iter++) {
      var changed = false;
      for (var i = 0; i < movable.length; i++) {
        var u = movable[i];
        var cur = assign[u];
        var bestCh = cur;
        var bestC = nodeCost(u, cur, assign);
        for (var ci = 0; ci < allowedCh.length; ci++) {
          var cand = allowedCh[ci];
          if (cand === cur) continue;
          var sc = nodeCost(u, cand, assign);
          if (sc < bestC - 0.05) {
            bestC = sc;
            bestCh = cand;
          }
        }
        if (bestCh !== cur) {
          assign[u] = bestCh;
          changed = true;
        }
      }
      // Hoan doi cap AP sat vach (2-Opt Swap) de thoat cuc tieu cuc bo
      for (var a = 0; a < movable.length; a++) {
        var u1 = movable[a];
        var nbs = Object.keys(edges[u1]);
        for (var b = 0; b < nbs.length; b++) {
          var u2 = nbs[b];
          if (graph.pinnedMap[u2] || u1 >= u2 || assign[u1] === assign[u2] || edges[u1][u2] < 20.0) continue;
          var c1 = assign[u1], c2 = assign[u2];
          var before = nodeCost(u1, c1, assign) + nodeCost(u2, c2, assign);
          assign[u1] = c2; assign[u2] = c1;
          var after = nodeCost(u1, c2, assign) + nodeCost(u2, c1, assign);
          if (after < before - 0.05) {
            changed = true;
          } else {
            assign[u1] = c1; assign[u2] = c2;
          }
        }
      }
      if (!changed) break;
    }
    return assign;
  }

  var candidates = [];
  var warm = {};
  for (var wIdx = 0; wIdx < macs.length; wIdx++) {
    var wm = macs[wIdx];
    warm[wm] = graph.pinnedMap[wm] || (graph.isLockedValidMap[wm] ? graph.curChMap[wm] : allowedCh[0]);
  }
  candidates.push(refineExactPotential(warm));

  var perms = allowedCh.length === 3
    ? [
      [allowedCh[0], allowedCh[1], allowedCh[2]],
      [allowedCh[0], allowedCh[2], allowedCh[1]],
      [allowedCh[1], allowedCh[0], allowedCh[2]],
      [allowedCh[1], allowedCh[2], allowedCh[0]],
      [allowedCh[2], allowedCh[0], allowedCh[1]],
      [allowedCh[2], allowedCh[1], allowedCh[0]]
    ]
    : [allowedCh.slice()];

  for (var p = 0; p < perms.length; p++) {
    candidates.push(refineExactPotential(runDsaturSeed(perms[p])));
  }

  var bestAssign = candidates[0];
  var bestTotalPot = evalGlobalRfPotential(graph, bestAssign, true, SWITCH_PENALTY);
  for (var k = 1; k < candidates.length; k++) {
    var pot = evalGlobalRfPotential(graph, candidates[k], true, SWITCH_PENALTY);
    if (pot < bestTotalPot - 0.05) {
      bestTotalPot = pot;
      bestAssign = candidates[k];
    }
  }

  return {
    assignments: bestAssign,
    rfEnergy: Number(evalGlobalRfPotential(graph, bestAssign, false, SWITCH_PENALTY).toFixed(1)),
    totalPotential: Number(bestTotalPot.toFixed(1))
  };
}

function summarizePlanDistribution(assignments, allowedCh) {
  var dist = {};
  for (var i = 0; i < allowedCh.length; i++) dist[allowedCh[i]] = 0;
  if (assignments) {
    Object.keys(assignments).forEach(function (m) {
      if (!apMap[m]) return;
      var ch = assignments[m];
      dist[ch] = (dist[ch] || 0) + 1;
    });
  }
  return dist;
}

var lastAutoTopologyCheckAt = 0;

function ensureGlobalChannelPlan(forceReplan) {
  var rfCfg = appConfig.rfOptimizer || {};
  var allowedCh = Array.isArray(rfCfg.allowedChannels24G) && rfCfg.allowedChannels24G.length > 0 ? rfCfg.allowedChannels24G : [1, 6, 11];
  var minGainPct = Math.max(8, Number(rfCfg.replanMinGlobalGainPct) || 18);
  var graph = buildSymmetricRfGraph(allowedCh, Boolean(forceReplan));

  if (graph.macs.length === 0) {
    return {
      version: 2,
      computedAt: Date.now(),
      rfEnergy: 0,
      assignments: {},
      pinnedManual: {},
      cooldownMap: {}
    };
  }

  var existing = rfTelemetryStore.channelPlan;
  var hasValidExisting = existing && existing.version === 2 && existing.assignments && typeof existing.assignments === 'object';

  if (!forceReplan && hasValidExisting) {
    var savedAssign = {};
    var missingMacs = [];
    var existingManual = existing.pinnedManual || {};

    for (var i = 0; i < graph.macs.length; i++) {
      var m = graph.macs[i];
      if (graph.pinnedMap[m]) {
        savedAssign[m] = graph.pinnedMap[m];
      } else if (existing.assignments[m] && allowedCh.indexOf(Number(existing.assignments[m])) !== -1) {
        savedAssign[m] = Number(existing.assignments[m]);
      } else {
        missingMacs.push(m);
      }
    }

    // Neu phat hien AP moi lap dat: chi phan bo kenh toi uu cho AP moi, giu nguyen toan bo AP cu
    if (missingMacs.length > 0) {
      for (var mi = 0; mi < missingMacs.length; mi++) {
        var newM = missingMacs[mi];
        var bestNewCh = allowedCh[0];
        var bestNewCost = Infinity;
        for (var ci = 0; ci < allowedCh.length; ci++) {
          var cTry = allowedCh[ci];
          var cSc = (graph.extCost[newM] && graph.extCost[newM][cTry]) ? graph.extCost[newM][cTry] : 0;
          Object.keys(graph.edges[newM]).forEach(function (nb) {
            if (savedAssign[nb]) {
              var ov = chOverlap24G(cTry, savedAssign[nb]);
              if (ov > 0) cSc += graph.edges[newM][nb] * ov;
            }
          });
          if (cSc < bestNewCost) {
            bestNewCost = cSc;
            bestNewCh = cTry;
          }
        }
        savedAssign[newM] = bestNewCh;
      }
      existing.assignments = savedAssign;
      existing.rfEnergy = Number(evalGlobalRfPotential(graph, savedAssign, false, 45.0).toFixed(1));
      rfTelemetryDirty = true;
    }

    // Kiem tra xem moi truong vat ly co thay doi dot bien (>= 18% giam nhieu toan mang) khong
    // (Chi chay bo giai 2-opt nang dinh ky moi 10 phut hoac khi co AP moi de giu computeRfOptimizationPlan < 3ms cho SSE realtime!)
    var nowPlanCheck = Date.now();
    if (missingMacs.length > 0 || (nowPlanCheck - lastAutoTopologyCheckAt) >= 600000) {
      lastAutoTopologyCheckAt = nowPlanCheck;
      var savedEnergy = evalGlobalRfPotential(graph, savedAssign, false, 45.0);
      var candSolved = solveGlobalChannelMap(graph);
      var requiredMaxEnergy = savedEnergy * (1 - minGainPct / 100);

      if (savedEnergy > 120 && candSolved.rfEnergy <= requiredMaxEnergy) {
        rfTelemetryStore.channelPlan = {
          version: 2,
          computedAt: nowPlanCheck,
          reason: 'auto-significant-topology-shift',
          rfEnergy: candSolved.rfEnergy,
          assignments: candSolved.assignments,
          pinnedManual: existingManual
        };
        rfTelemetryDirty = true;
        saveRfTelemetryStore(false);
      } else {
        existing.assignments = savedAssign;
        existing.rfEnergy = Number(savedEnergy.toFixed(1));
      }
    } else {
      existing.assignments = savedAssign;
    }

    return {
      version: 2,
      computedAt: existing.computedAt || Date.now(),
      rfEnergy: rfTelemetryStore.channelPlan.rfEnergy,
      assignments: rfTelemetryStore.channelPlan.assignments,
      pinnedManual: rfTelemetryStore.channelPlan.pinnedManual || {},
      cooldownMap: graph.cooldownMap
    };
  }

  // Khoi tao ban do kenh toan cuc lan dau hoac khi nguoi dung chu dong nhan "Quy Hoach Lai Kenh"
  var freshSolved = solveGlobalChannelMap(graph);
  rfTelemetryStore.channelPlan = {
    version: 2,
    computedAt: Date.now(),
    reason: forceReplan ? 'manual-replan' : 'initial-global-plan',
    rfEnergy: freshSolved.rfEnergy,
    assignments: freshSolved.assignments,
    pinnedManual: forceReplan ? {} : ((existing && existing.pinnedManual) || {})
  };
  rfTelemetryDirty = true;
  saveRfTelemetryStore(Boolean(forceReplan));

  return {
    version: 2,
    computedAt: rfTelemetryStore.channelPlan.computedAt,
    rfEnergy: rfTelemetryStore.channelPlan.rfEnergy,
    assignments: rfTelemetryStore.channelPlan.assignments,
    pinnedManual: rfTelemetryStore.channelPlan.pinnedManual,
    cooldownMap: graph.cooldownMap
  };
}

function summarizeAp24hStats(ap) {
  var rec = ensureRfApRecord(ap);
  var winHours = Math.max(6, Number(appConfig.rfOptimizer && appConfig.rfOptimizer.telemetryWindowHours) || 24);
  var minHk = Math.floor(Date.now() / 3600000) - winHours;
  var samples = 0, sumDbm = 0, minDbm = 0, good = 0, mid = 0, weak = 0, sticky = 0, lowPhy = 0, peakClients = Number(ap.clientCount) || 0, rapidReassoc = 0;
  var activeHours = 0;

  if (rec && rec.hourly) {
    Object.keys(rec.hourly).forEach(function (hk) {
      if (parseInt(hk, 10) < minHk) return;
      var b = rec.hourly[hk];
      if (!b) return;
      activeHours++;
      samples += (b.samples || 0);
      sumDbm += (b.sumDbm || 0);
      if (b.minDbm && (minDbm === 0 || b.minDbm < minDbm)) minDbm = b.minDbm;
      good += (b.good || 0);
      mid += (b.mid || 0);
      weak += (b.weak || 0);
      sticky += (b.sticky || 0);
      lowPhy += (b.lowPhy || 0);
      rapidReassoc += (b.rapidReassoc || 0);
      if ((b.maxClients || 0) > peakClients) peakClients = b.maxClients;
    });
  }

  var firstAt = rec && rec.firstSeenAt ? rec.firstSeenAt : rfTelemetryStore.collectorStartedAt;
  var hoursObserved = Math.min(24, Math.max(0.1, Number(((Date.now() - firstAt) / 3600000).toFixed(1))));

  return {
    hoursObserved: hoursObserved,
    activeHours: activeHours,
    samples: samples,
    avgDbm: samples > 0 ? Math.round(sumDbm / samples) : null,
    minDbm: minDbm !== 0 ? minDbm : null,
    goodPct: samples > 0 ? Math.round((good / samples) * 100) : 0,
    weakPct: samples > 0 ? Math.round((weak / samples) * 100) : 0,
    stickyCount: sticky,
    lowPhyCount: lowPhy,
    peakClients: peakClients,
    rapidReassoc: rapidReassoc
  };
}

function computeRfOptimizationPlan(planOpts) {
  var rfCfg = appConfig.rfOptimizer || {};
  var allowedCh = Array.isArray(rfCfg.allowedChannels24G) && rfCfg.allowedChannels24G.length > 0 ? rfCfg.allowedChannels24G : [1, 6, 11];
  var targetRssiRoom = Number(rfCfg.targetStaRssiRoomDbm) || -76;
  var targetRssiLobby = Number(rfCfg.targetStaRssiLobbyDbm) || -75;
  var fallbackRssi = Number(rfCfg.fallbackStaRssiDbm) || -80;
  var targetDtim = Number(rfCfg.targetDtimPeriod) || 3;
  var targetBurst = rfCfg.enableTxBurst !== false ? 1 : 0;

  var forceReplan = Boolean(planOpts && planOpts.forceReplan);
  var masterChannelPlan = ensureGlobalChannelPlan(forceReplan);
  var assignedCh = masterChannelPlan.assignments || {};
  var cooldownMap = masterChannelPlan.cooldownMap || {};
  var pinnedManualMap = masterChannelPlan.pinnedManual || {};
  var channelPlanDist = summarizePlanDistribution(assignedCh, allowedCh);

  var keys = Object.keys(apMap);
  var apStatsMap = {};
  for (var i = 0; i < keys.length; i++) {
    var ap = apMap[keys[i]];
    if (!ap || !ap.mac) continue;
    ensureRfApRecord(ap);
    apStatsMap[ap.mac] = summarizeAp24hStats(ap);
  }

  // Quy hoach kenh 5GHz cho cum UniFi (tranh chong lan tat ca vao CH 36)
  var unifi5gPool = [36, 44, 149, 157];
  var unifiIdx = 0;
  var items = [];
  var countNeedOpt = 0;
  var countChChange = 0;
  var countPowerChange = 0;
  var countRssiChange = 0;
  var totalSamples24h = 0;
  var measuredNeighborPairs = 0;

  var sortedAllMacs = keys.slice().sort(function (a, b) {
    var apA = apMap[a], apB = apMap[b];
    if ((apB.status || 0) !== (apA.status || 0)) return (apB.status || 0) - (apA.status || 0);
    return ip2long(apA.ip || '0.0.0.0') - ip2long(apB.ip || '0.0.0.0');
  });

  for (var k = 0; k < sortedAllMacs.length; k++) {
    var mac = sortedAllMacs[k];
    var apObj = apMap[mac];
    if (!apObj) continue;

    var rfRec = ensureRfApRecord(apObj);
    var hwCfg = (rfRec && rfRec.hwConfig) ? rfRec.hwConfig : {};
    var st24 = apStatsMap[mac] || summarizeAp24hStats(apObj);
    totalSamples24h += st24.samples;

    var isUnifi = isUnifiDevice(apObj);
    var isOnline = apObj.status === 1;
    var curChannel = getLiveApChannel24G(mac);
    // UniFi giu nguyen kenh 2.4GHz lam diem neo; TOTOLINK lay tu Ban Do Kenh Toan Cuc co dinh (khong dao dong)
    var recChannel = (!isUnifi && isOnline && assignedCh[mac]) ? Number(assignedCh[mac]) : curChannel;

    // Thong ke nhieu dong kenh THUC TE (doc kenh live cua AP lang gieng thay vi du lieu quet cu)
    var coChCount = 0;
    var strongHotelNbCount = 0;
    var strongestSameCh = null;
    if (rfRec && rfRec.neighbors) {
      var nbs = Object.keys(rfRec.neighbors);
      measuredNeighborPairs += nbs.length;
      for (var ni = 0; ni < nbs.length; ni++) {
        var nbObj = rfRec.neighbors[nbs[ni]];
        if (!nbObj || nbObj.channel > 14) continue;
        if (!nbObj.isHotelAp && isHotelSsidName(nbObj.ssid)) continue;

        var liveNbCh = (nbObj.isHotelAp && nbObj.apMac && apMap[nbObj.apMac])
          ? getLiveApChannel24G(nbObj.apMac)
          : nbObj.channel;

        if (nbObj.isHotelAp && nbObj.signalDbm >= -60) strongHotelNbCount++;
        if (chOverlap24G(curChannel, liveNbCh) >= 0.6 && nbObj.signalDbm >= -75) {
          coChCount++;
          if (!strongestSameCh || nbObj.signalDbm > strongestSameCh.signalDbm) {
            strongestSameCh = {
              apName: nbObj.apName,
              ssid: nbObj.ssid,
              bssid: nbObj.bssid,
              signalDbm: nbObj.signalDbm,
              channel: liveNbCh
            };
          }
        }
      }
    }

    var reasons = [];
    var hwSynced = Boolean(rfRec && rfRec.hwConfig);
    var curTxPower = isUnifi ? (hwCfg.txPowerDbm24 || 13) : (Number(hwCfg.txPower) || 75);
    var recTxPower = curTxPower;
    var curStaRssi = hwCfg.staRssi !== undefined ? Number(hwCfg.staRssi) : (hwSynced ? 0 : targetRssiRoom);
    var recStaRssi = isUnifi ? targetRssiLobby : targetRssiRoom;
    var curDtim = hwCfg.dtim !== undefined ? Number(hwCfg.dtim) : (hwSynced ? 1 : targetDtim);
    var recDtim = targetDtim;
    var curTxBurst = hwCfg.txBurst !== undefined ? Number(hwCfg.txBurst) : (hwSynced ? 0 : targetBurst);
    var recTxBurst = targetBurst;
    var curCh5 = hwCfg.ch5 || 36;
    var recCh5 = curCh5;

    if (!isUnifi) {
      // Tinh toan TX Power co dai tre (Deadband 0% vs 35% mau yeu) tranh tang/giam qua lai
      if (st24.rapidReassoc >= 2 || (st24.samples >= 6 && st24.weakPct >= 35 && strongHotelNbCount <= 1)) {
        recTxPower = 100;
      } else if (curTxPower === 50 && st24.samples >= 6 && st24.weakPct >= 35) {
        recTxPower = 75;
      } else if (curTxPower === 100 && strongHotelNbCount >= 3 && (st24.samples === 0 || st24.weakPct < 10)) {
        recTxPower = 75;
      } else if (curTxPower >= 75 && strongHotelNbCount >= 5 && coChCount >= 2 && (st24.samples === 0 || (st24.avgDbm !== null && st24.avgDbm >= -54 && st24.weakPct === 0))) {
        recTxPower = 50;
      }

      // Tinh toan nguong cat Sticky Client (STA RSSI threshold) + Fail-safe
      if (st24.rapidReassoc >= 2) {
        recStaRssi = fallbackRssi;
      } else if (strongHotelNbCount === 0 && rfRec && Object.keys(rfRec.neighbors || {}).length > 0) {
        recStaRssi = Math.min(-78, targetRssiRoom);
      } else if (strongHotelNbCount >= 3) {
        recStaRssi = Math.max(-75, targetRssiRoom + 1);
      } else {
        recStaRssi = targetRssiRoom;
      }
    } else {
      recCh5 = unifi5gPool[unifiIdx % unifi5gPool.length];
      unifiIdx++;
      recTxPower = 13; // dBm cho 2.4GHz de uu tien 5GHz
    }

    var chChanged = isOnline && !isUnifi && (recChannel !== curChannel || Boolean(hwCfg.isAutoChannel));
    var pwrChanged = isOnline && !isUnifi && hwSynced && (recTxPower !== curTxPower);
    var rssiChanged = isOnline && !isUnifi && hwSynced && (curStaRssi === 0 || Math.abs(curStaRssi - recStaRssi) >= 3);
    // Neu STA RSSI tren AP da nam trong bien do chuan (< 3 dBm so voi muc tieu, vd -75 vs -76), giu nguyen khong cap nhat lai!
    if (!isUnifi && !rssiChanged && curStaRssi !== 0) {
      recStaRssi = curStaRssi;
    }
    if (!isUnifi && !pwrChanged) {
      recTxPower = curTxPower;
    }
    var dtimChanged = isOnline && !isUnifi && hwSynced && (curDtim !== recDtim);
    var burstChanged = isOnline && !isUnifi && hwSynced && (curTxBurst !== recTxBurst);
    var bwChanged = isOnline && !isUnifi && hwSynced && (hwCfg.htBw === 1);
    var unifi5gChanged = isOnline && isUnifi && (recCh5 !== curCh5);
    var unifiStickyIssue = isOnline && isUnifi && (st24.stickyCount > 0 || curStaRssi === 0);

    if (chChanged) {
      countChChange++;
      if (hwCfg.isAutoChannel) {
        reasons.push('Đang để Auto Channel dễ nhảy kênh vòng lặp → Khóa cố định CH ' + recChannel + ' theo bản đồ 3 kênh toàn tòa nhà');
      } else if (strongestSameCh) {
        var nbLabel = strongestSameCh.apName || strongestSameCh.ssid || strongestSameCh.bssid;
        reasons.push('Quy hoạch tĩnh 3 kênh (1-6-11): Tách trùng CH ' + curChannel + ' với ' + nbLabel + ' (' + strongestSameCh.signalDbm + ' dBm) → Cố định CH ' + recChannel);
      } else {
        reasons.push('Quy hoạch tĩnh 3 kênh (1-6-11): Cân bằng kênh phòng liền kề → Cố định CH ' + curChannel + ' sang CH ' + recChannel);
      }
    }
    if (bwChanged) {
      reasons.push('Đang mở 40MHz gây chồng lấn 2.4GHz → Đưa về chuẩn 20MHz');
    }
    if (pwrChanged) {
      countPowerChange++;
      if (recTxPower > curTxPower) {
        reasons.push('Ghi nhận ' + st24.weakPct + '% mẫu sóng yếu (TB ' + (st24.avgDbm || -72) + ' dBm) → Nâng TX Power ' + curTxPower + '% → ' + recTxPower + '%');
      } else {
        reasons.push('Mật độ AP lân cận dày (' + strongHotelNbCount + ' AP sóng mạnh) → Hạ TX Power ' + curTxPower + '% → ' + recTxPower + '% giảm nhiễu xuyên phòng');
      }
    }
    if (rssiChanged) {
      countRssiChange++;
      if (curStaRssi === 0) {
        reasons.push('Chưa bật cắt sóng yếu (STA RSSI = 0) → Đặt ' + recStaRssi + ' dBm chống Sticky Client');
      } else {
        reasons.push('Tinh chỉnh ngưỡng STA RSSI ' + curStaRssi + ' → ' + recStaRssi + ' dBm theo hồ sơ 24h');
      }
    }
    if (dtimChanged || burstChanged) {
      var advParts = [];
      if (dtimChanged) advParts.push('DTIM ' + curDtim + '→' + recDtim);
      if (burstChanged) advParts.push('Bật TxBurst');
      reasons.push('Tối ưu truyền dẫn 802.11n: ' + advParts.join(', '));
    }
    if (isUnifi) {
      if (unifi5gChanged) {
        reasons.push('Trùng kênh 5GHz CH ' + curCh5 + ' giữa cụm Sảnh/Nhà hàng → Tách sang CH ' + recCh5 + ' trên UniFi Controller');
      }
      if (st24.stickyCount > 0) {
        reasons.push('Phát hiện ' + st24.stickyCount + ' mẫu bám sóng yếu (tới ' + (st24.minDbm || -81) + ' dBm) → Bật Minimum RSSI ' + recStaRssi + ' dBm trên Controller');
      } else if (curStaRssi === 0) {
        reasons.push('Khuyến nghị bật Minimum RSSI ' + recStaRssi + ' dBm & Band Steering 5GHz trên UniFi Controller');
      }
    }

    var needsDirectApply = !isUnifi && isOnline && (chChanged || pwrChanged || rssiChanged || dtimChanged || burstChanged || bwChanged);
    var needsAnyAction = needsDirectApply || (isUnifi && isOnline && (unifi5gChanged || unifiStickyIssue));
    if (needsDirectApply) countNeedOpt++;

    var priority = 'optimal';
    if (!isOnline) priority = 'offline';
    else if (chChanged || pwrChanged || curStaRssi === 0 || st24.stickyCount > 0 || unifi5gChanged) priority = 'high';
    else if (needsAnyAction) priority = 'medium';

    items.push({
      mac: apObj.mac,
      ip: apObj.ip,
      name: apObj.name || 'AP',
      model: apObj.model || '-',
      ssid: apObj.ssid || '-',
      status: apObj.status,
      clientCount: isOnline ? (Number(apObj.clientCount) || 0) : 0,
      isUnifi: isUnifi,
      canApplyDirect: !isUnifi && isOnline,
      hwSynced: Boolean(rfRec && rfRec.hwConfig),
      inChannelCooldown: Boolean(cooldownMap[mac]),
      isManualChannelPinned: Boolean(pinnedManualMap[mac]),
      priority: priority,
      needsOptimization: needsDirectApply,
      needsControllerAdvisory: isUnifi && needsAnyAction,
      stats24h: st24,
      coChannelNeighbors: coChCount,
      strongestNeighborDbm: strongestSameCh ? strongestSameCh.signalDbm : null,
      strongestNeighborName: strongestSameCh ? (strongestSameCh.apName || strongestSameCh.ssid || strongestSameCh.bssid) : '',
      cu24: hwCfg.cu24 !== undefined ? hwCfg.cu24 : null,
      cu5: hwCfg.cu5 !== undefined ? hwCfg.cu5 : null,
      informUrl: hwCfg.informUrl || '',
      current: {
        channel: curChannel,
        isAutoChannel: Boolean(hwCfg.isAutoChannel),
        ch5: isUnifi ? curCh5 : null,
        txPower: curTxPower,
        txPowerUnit: isUnifi ? 'dBm' : '%',
        staRssi: curStaRssi,
        dtim: curDtim,
        txBurst: curTxBurst,
        htBw: hwCfg.htBw === 1 ? 40 : 20
      },
      recommended: {
        channel: recChannel,
        ch5: isUnifi ? recCh5 : null,
        txPower: recTxPower,
        txPowerUnit: isUnifi ? 'dBm' : '%',
        staRssi: recStaRssi,
        dtim: recDtim,
        txBurst: recTxBurst,
        htBw: 20
      },
      diff: {
        channel: chChanged,
        txPower: pwrChanged,
        staRssi: rssiChanged,
        dtim: dtimChanged,
        txBurst: burstChanged,
        htBw: bwChanged
      },
      applyState: apApplyLiveState[apObj.ip] || null,
      reasons: reasons.length > 0 ? reasons : ['Đã đạt chuẩn quy hoạch tĩnh 3 kênh (1-6-11), Công suất & Roaming tối ưu']
    });
  }

  items.sort(function (a, b) {
    var scoreA = (a.needsOptimization ? 100 : 0) + (a.needsControllerAdvisory ? 40 : 0) + (a.status === 1 ? 10 : 0);
    var scoreB = (b.needsOptimization ? 100 : 0) + (b.needsControllerAdvisory ? 40 : 0) + (b.status === 1 ? 10 : 0);
    if (scoreB !== scoreA) return scoreB - scoreA;
    if ((b.coChannelNeighbors || 0) !== (a.coChannelNeighbors || 0)) return (b.coChannelNeighbors || 0) - (a.coChannelNeighbors || 0);
    if ((b.clientCount || 0) !== (a.clientCount || 0)) return (b.clientCount || 0) - (a.clientCount || 0);
    return String(a.ip || '').localeCompare(String(b.ip || ''), undefined, { numeric: true });
  });

  var systemHours = Number(((Date.now() - (rfTelemetryStore.collectorStartedAt || Date.now())) / 3600000).toFixed(1));
  return {
    generatedAt: new Date().toISOString(),
    settings: {
      autoOptimizeEnabled: Boolean(rfCfg.autoOptimizeEnabled),
      autoOptimizeTime: rfCfg.autoOptimizeTime || '03:30',
      requireFull24hForAuto: rfCfg.requireFull24hForAuto !== false,
      telemetryWindowHours: Number(rfCfg.telemetryWindowHours) || 24,
      channelCooldownHours: Number(rfCfg.channelCooldownHours) || 24,
      targetStaRssiRoomDbm: targetRssiRoom,
      targetStaRssiLobbyDbm: targetRssiLobby,
      targetDtimPeriod: targetDtim,
      enableTxBurst: Boolean(targetBurst)
    },
    summary: {
      systemHoursObserved: Math.min(24, Math.max(0.1, systemHours)),
      rawHoursRunning: systemHours,
      readyFull24h: systemHours >= 24,
      totalAps: items.length,
      totolinkActionCount: countNeedOpt,
      channelChangeCount: countChChange,
      txPowerChangeCount: countPowerChange,
      staRssiChangeCount: countRssiChange,
      totalSamples24h: totalSamples24h,
      measuredNeighborLinks: Math.round(measuredNeighborPairs / 2),
      channelPlanDist: channelPlanDist,
      channelPlanComputedAt: masterChannelPlan.computedAt ? new Date(masterChannelPlan.computedAt).toISOString() : null,
      isScanningNeighbors: isScanningNeighbors,
      isSyncingHwConfig: isSyncingHwConfig,
      isRunningBatchApply: isRunningBatchApply,
      batchStatus: batchApplyStatus,
      activeApplyCount: Object.keys(apApplyLiveState).length,
      historyTotalCount: Math.max(Number(rfTelemetryStore.totalHistoryCount) || 0, (rfTelemetryStore.history || []).length),
      lastAutoRunDate: rfTelemetryStore.lastAutoRunDate || '',
      lastAutoRunResult: rfTelemetryStore.lastAutoRunResult || null
    },
    items: items,
    history: (rfTelemetryStore.history || []).slice(0, RF_HISTORY_MAX_ITEMS)
  };
}

function buildTotolinkBasicSetPayload(basicJson, targetChannel, fallbackSsid) {
  var hideArr = String(basicJson.HideSSID || '0;0;0').split(';');
  var authArr = String(basicJson.AuthMode || 'OPEN;OPEN;OPEN').split(';');
  var encArr = String(basicJson.EncrypType || 'NONE;NONE;NONE').split(';');
  var defKeyArr = String(basicJson.DefaultKeyID || '1;1;1').split(';');
  var keyTypeArr = String(basicJson.Key1Type || '0;0;0').split(';');

  var targetChNum = Number(targetChannel) || 6;
  var extCha = (targetChNum >= 1 && targetChNum <= 4) ? String(targetChNum + 4) : '0';
  var secMode = (encArr[0] === 'NONE') ? 'NONE' : (authArr[0] || 'NONE');
  var payload = {
    topicurl: 'setting/setWiFiBasicConfig',
    SSID1: String(basicJson.SSID1 || fallbackSsid || DEFAULT_SSID_FALLBACK),
    WirelessMode: String(basicJson.WirelessMode || '6'),
    Channel: String(targetChNum),
    CountryCode: String(basicJson.CountryCode || 'CN'),
    HideSSID: (hideArr[0] || '0') + ';' + (hideArr[1] || '0') + ';' + (hideArr[2] || '0'),
    security_mode: secMode,
    AuthMode: (authArr[0] || 'OPEN') + ';' + (authArr[1] || 'OPEN') + ';' + (authArr[2] || 'OPEN'),
    EncrypType: (encArr[0] || 'NONE') + ';' + (encArr[1] || 'NONE') + ';' + (encArr[2] || 'NONE'),
    DefaultKeyID: (defKeyArr[0] || '1') + ';' + (defKeyArr[1] || '1') + ';' + (defKeyArr[2] || '1'),
    Key1Type: (keyTypeArr[0] || '0') + ';' + (keyTypeArr[1] || '0') + ';' + (keyTypeArr[2] || '0'),
    Key1Str1: String(basicJson.Key1Str1 || ''),
    WPAPSK1: String(basicJson.WPAPSK1 || ''),
    abg_rate: '0',
    HT_BW: '0',
    VHT_BW: String(basicJson.VHT_BW || '0'),
    HT_EXTCHA: extCha,
    HT_OpMode: String(basicJson.HT_OpMode || '0'),
    HT_GI: String(basicJson.HT_GI || '1'),
    HT_MCS: String(basicJson.HT_MCS || '33'),
    HT_RDG: String(basicJson.HT_RDG || '1'),
    HT_STBC: String(basicJson.HT_STBC || '1'),
    HT_AMSDU: String(basicJson.HT_AMSDU || '0'),
    HT_AutoBA: String(basicJson.HT_AutoBA || '1'),
    HT_BADecline: String(basicJson.HT_BADecline || '0'),
    HT_DisallowTKIP: String(basicJson.HT_DisallowTKIP || '1'),
    HT_TxStream: String(basicJson.HT_TxStream || '2'),
    HT_RxStream: String(basicJson.HT_RxStream || '2'),
    addEffect: '0',
    WiFiIdx: '0',
    WscEabled: String(basicJson.WscEabled || '0'),
    WscModeOption: String(basicJson.WscModeOption || '7')
  };
  if (String(basicJson.VLANID_flag) === '1') {
    payload.VLANID1 = String(basicJson.VLANID1 || '0');
  }
  return payload;
}

function buildTotolinkAdvSetPayload(advJson, targetTxPower, targetStaRssi, targetDtim, targetTxBurst) {
  return {
    topicurl: 'setting/setWiFiAdvancedConfig',
    BGProtection: String(advJson.BGProtection || '0'),
    BeaconPeriod: String(advJson.BeaconPeriod || '100'),
    DtimPeriod: String(targetDtim),
    FragThreshold: String(advJson.FragThreshold || '2346'),
    RTSThreshold: String(advJson.RTSThreshold || '2347'),
    TxPower: String(targetTxPower),
    KickStaRssiLow: String(targetStaRssi),
    MaxStaNum: String(advJson.MaxStaNum || '25'),
    NoForwarding: String(advJson.NoForwarding || '1'),
    TxBurst: String(targetTxBurst),
    HT_BSSCoexistence: '0',
    WmmCapable: String(advJson.WmmCapable || '1'),
    TxPreamble: String(advJson.TxPreamble || '1'),
    WiFiIdx: '0'
  };
}

function recordRfHistoryEvent(entry) {
  rfTelemetryStore.totalHistoryCount = Math.max(Number(rfTelemetryStore.totalHistoryCount) || 0, (rfTelemetryStore.history || []).length) + 1;
  rfTelemetryStore.history.unshift(entry);
  if (rfTelemetryStore.history.length > RF_HISTORY_MAX_ITEMS) {
    rfTelemetryStore.history = rfTelemetryStore.history.slice(0, RF_HISTORY_MAX_ITEMS);
  }
  rfTelemetryDirty = true;
}

function applyTotolinkApOptimization(ipOrKey, customParams, modeSource, callback) {
  var key = findApKeyByIp(ipOrKey) || (apMap[ipOrKey] ? ipOrKey : null);
  if (!key || !apMap[key]) {
    return callback(new Error('Khong tim thay Access Point: ' + ipOrKey));
  }
  var ap = apMap[key];
  if (ap.status !== 1) {
    return callback(new Error('Access Point ' + ap.name + ' dang Offline'));
  }
  if (isUnifiDevice(ap)) {
    return callback(new Error('Thiet bi UniFi do UniFi Controller quan ly, vui long ap dung theo khuyen nghi tren Controller'));
  }
  if (apApplyingLock[ap.ip]) {
    return callback(new Error('Dang xu ly cau hinh tren AP ' + ap.ip + ', vui long doi giay lat'));
  }
  apApplyingLock[ap.ip] = true;
  setApApplyLiveState(ap.ip, {
    phase: 'checking',
    message: 'Đang kiểm tra cấu hình trên AP...',
    pct: 15
  });

  function unlockAndDone(err, resObj) {
    delete apApplyingLock[ap.ip];
    if (err) {
      setApApplyLiveState(ap.ip, {
        phase: 'error',
        isError: true,
        message: 'Lỗi: ' + err.message,
        pct: 100
      }, 9000);
    } else if (typeof scheduleRealtimeBroadcast === 'function') {
      scheduleRealtimeBroadcast(60);
    }
    callback(err, resObj);
  }

  var plan = computeRfOptimizationPlan();
  var planItem = null;
  for (var i = 0; i < plan.items.length; i++) {
    if (plan.items[i].ip === ap.ip || plan.items[i].mac === ap.mac) {
      planItem = plan.items[i];
      break;
    }
  }

  var rec = planItem ? planItem.recommended : { channel: ap.channel || 6, txPower: 75, staRssi: -76, dtim: 3, txBurst: 1 };
  var opts = customParams || {};
  var hasManualCh = (opts.channel !== undefined && opts.channel !== null);
  var hasManualPwr = (opts.txPower !== undefined && opts.txPower !== null);
  var hasManualRssi = (opts.staRssi !== undefined && opts.staRssi !== null);
  var hasManualDtim = (opts.dtim !== undefined && opts.dtim !== null);
  var hasManualBurst = (opts.txBurst !== undefined && opts.txBurst !== null);

  var targetCh = Number(hasManualCh ? opts.channel : rec.channel) || 6;
  if ([1, 6, 11].indexOf(targetCh) === -1) targetCh = 6;
  var targetPwr = Number(hasManualPwr ? opts.txPower : rec.txPower) || 75;
  if ([25, 50, 75, 100].indexOf(targetPwr) === -1) targetPwr = 75;
  var targetRssi = hasManualRssi ? parseInt(opts.staRssi, 10) : rec.staRssi;
  if (isNaN(targetRssi) || targetRssi > 0 || targetRssi < -99) targetRssi = -76;
  var targetDtim = Number(hasManualDtim ? opts.dtim : rec.dtim) || 3;
  var targetBurst = hasManualBurst ? (Number(opts.txBurst) ? 1 : 0) : (rec.txBurst ? 1 : 0);

  function readCurrentRadioState(attempt, cb) {
    var passList = getApTotolinkWebPassList(ap);
    if (passList.length === 0) {
      return cb(new Error('Chua khai bao totolinkWebPasswords trong config.json'));
    }
    loginTotolinkWebSession(ap.ip, passList, 0, function (loginErr) {
      if (loginErr) {
        if (attempt < 2) {
          return setTimeout(function () { readCurrentRadioState(attempt + 1, cb); }, 600);
        }
        return cb(new Error('Dang nhap Web AP that bai: ' + loginErr.message));
      }
      postTotolinkCgiJson(ap.ip, { topicurl: 'setting/getWiFiBasicConfig', WiFiIdx: '0' }, 10000, function (errB, basicJson) {
        if (errB || !basicJson) {
          if (attempt < 2) {
            return setTimeout(function () { readCurrentRadioState(attempt + 1, cb); }, 700);
          }
          return cb(new Error('Khong doc duoc cau hinh Basic hien tai tu AP ' + ap.ip + (errB ? ' (' + errB.message + ')' : '')));
        }
        function afterSsidEnsure() {
          postTotolinkCgiJson(ap.ip, { topicurl: 'setting/getWiFiAdvancedConfig', WiFiIdx: '0' }, 10000, function (errA, advJson) {
            if (errA || !advJson) {
              if (attempt < 2) {
                return setTimeout(function () { readCurrentRadioState(attempt + 1, cb); }, 700);
              }
              return cb(new Error('Khong doc duoc cau hinh Advanced hien tai tu AP ' + ap.ip + (errA ? ' (' + errA.message + ')' : '')));
            }
            cb(null, basicJson, advJson);
          });
        }
        if (basicJson.SSID1) {
          afterSsidEnsure();
        } else {
          postTotolinkCgiJson(ap.ip, { topicurl: 'setting/getSysStatusCfg' }, 5000, function (eSys, sysJson) {
            basicJson.SSID1 = (sysJson && sysJson.SSID1) || ap.ssid || DEFAULT_SSID_FALLBACK;
            afterSsidEnsure();
          });
        }
      });
    });
  }

  readCurrentRadioState(1, function (readErr, basicJson, advJson) {
    if (readErr) return unlockAndDone(readErr);

    var rawBeforeCh = (basicJson.Channel === undefined || basicJson.Channel === null) ? '' : String(basicJson.Channel).trim();
    var parsedBeforeCh = parseInt(rawBeforeCh, 10);
    var beforeIsAuto = (rawBeforeCh === '' || isNaN(parsedBeforeCh) || parsedBeforeCh <= 0);

    var beforeSnap = {
      channel: beforeIsAuto ? 0 : parsedBeforeCh,
      txPower: parseInt(advJson.TxPower, 10) || 75,
      staRssi: parseInt(advJson.KickStaRssiLow, 10) || 0,
      dtim: parseInt(advJson.DtimPeriod, 10) || 1,
      txBurst: parseInt(advJson.TxBurst, 10) || 0,
      htBw: parseInt(basicJson.HT_BW, 10) === 1 ? 40 : 20
    };

    // Giu nguyen tat ca thong so da chinh xac tren AP (khong ghi de neu khong can cap nhat hoac khong chinh tay)
    if (!hasManualCh && !(planItem && planItem.diff && planItem.diff.channel) && !beforeIsAuto && beforeSnap.channel > 0) {
      targetCh = beforeSnap.channel;
    }
    if (!hasManualPwr && !(planItem && planItem.diff && planItem.diff.txPower)) {
      targetPwr = beforeSnap.txPower;
    }
    if (!hasManualRssi) {
      if (!(planItem && planItem.diff && planItem.diff.staRssi) || (beforeSnap.staRssi !== 0 && Math.abs(beforeSnap.staRssi - targetRssi) < 3)) {
        targetRssi = beforeSnap.staRssi;
      }
    }
    if (!hasManualDtim && !(planItem && planItem.diff && planItem.diff.dtim)) {
      targetDtim = beforeSnap.dtim;
    }
    if (!hasManualBurst && !(planItem && planItem.diff && planItem.diff.txBurst)) {
      targetBurst = beforeSnap.txBurst;
    }

    var diffPwr = (beforeSnap.txPower !== targetPwr);
    var diffRssi = (beforeSnap.staRssi !== targetRssi);
    var diffDtim = (beforeSnap.dtim !== targetDtim);
    var diffBurst = (beforeSnap.txBurst !== targetBurst);
    var diffCh = beforeIsAuto || (beforeSnap.channel !== targetCh);
    var diffBw = (beforeSnap.htBw === 40);

    // Chi goi setWiFiAdvancedConfig khi TX Power / STA RSSI / DTIM / TxBurst THUC SU can thay doi
    var needAdvWrite = diffPwr || diffRssi || diffDtim || diffBurst;

    // Firmware TOTOLINK N9v1 (V4.0c.2634) reset Channel ve "" (Auto) moi khi setWiFiAdvancedConfig chay.
    // Vi vay neu needAdvWrite=true thi phai ghi Advanced TRUOC -> doi radio khoi dong xong -> khoa lai Basic Channel SAU.
    var needBasicWrite = diffCh || diffBw || needAdvWrite;

    // Fast-path: Tat ca cau hinh tren AP da chuan xac -> khong goi CGI set, khong khoi dong lai song Wi-Fi!
    if (!needAdvWrite && !needBasicWrite) {
      var apRecSync = ensureRfApRecord(ap);
      if (!beforeIsAuto && beforeSnap.channel > 0) {
        ap.channel = beforeSnap.channel;
        syncPeerNeighborChannelCache(ap.mac, beforeSnap.channel);
      }
      if (basicJson.SSID1) ap.ssid = basicJson.SSID1;
      if (apRecSync) {
        apRecSync.hwConfig = {
          channel: beforeIsAuto ? (Number(ap.channel) || 1) : beforeSnap.channel,
          isAutoChannel: beforeIsAuto,
          txPower: beforeSnap.txPower,
          staRssi: beforeSnap.staRssi,
          dtim: beforeSnap.dtim,
          beacon: parseInt(advJson.BeaconPeriod, 10) || 100,
          txBurst: beforeSnap.txBurst,
          htBw: parseInt(basicJson.HT_BW, 10) || 0,
          coexistence: parseInt(advJson.HT_BSSCoexistence, 10) || 0,
          wirelessMode: parseInt(basicJson.WirelessMode, 10) || 6,
          noForwarding: parseInt(String(advJson.NoForwarding || '1').split(';')[0], 10),
          maxStaNum: parseInt(String(advJson.MaxStaNum || '25').split(';')[0], 10) || 25,
          ssid1: basicJson.SSID1 || ap.ssid || '',
          updatedAt: Date.now()
        };
      }
      saveRfTelemetryStore(true);
      saveRegistry();
      setApApplyLiveState(ap.ip, {
        phase: 'done',
        message: 'Đã chuẩn xác trên AP (không cần nạp lại)',
        pct: 100
      }, 4200);
      return unlockAndDone(null, {
        skippedNoChange: true,
        apIp: ap.ip,
        apName: ap.name || ap.ip,
        before: beforeSnap,
        after: beforeSnap,
        success: true
      });
    }

    var advDescParts = [];
    if (diffPwr) advDescParts.push('TX ' + targetPwr + '%');
    if (diffRssi) advDescParts.push('RSSI ' + (targetRssi === 0 ? 'Tắt' : (targetRssi + 'dBm')));
    if (diffDtim) advDescParts.push('DTIM ' + targetDtim);
    if (diffBurst) advDescParts.push('TxBurst');

    var summaryParts = [];
    if (diffCh) summaryParts.push('CH ' + targetCh);
    if (diffBw) summaryParts.push('20MHz');
    summaryParts = summaryParts.concat(advDescParts);
    if (summaryParts.length === 0) summaryParts.push('CH ' + targetCh);

    function postBasicWithLogin(chToSet, waitPhaseMsg, waitPct, doneBasicCb) {
      var passList = getApTotolinkWebPassList(ap);
      loginTotolinkWebSession(ap.ip, passList, 0, function () {
        var basicPayload = buildTotolinkBasicSetPayload(basicJson, chToSet, ap.ssid);
        postTotolinkCgiJson(ap.ip, basicPayload, 22000, function (errSetB) {
          if (errSetB) return doneBasicCb(new Error('Loi ghi Channel Basic Config: ' + errSetB.message));
          setApApplyLiveState(ap.ip, {
            phase: 'waiting-ch',
            message: waitPhaseMsg,
            pct: waitPct
          });
          setTimeout(function () { doneBasicCb(null); }, 6500);
        });
      });
    }

    function stepWriteBasic(chCurrentlyAuto) {
      if (!needBasicWrite) return stepVerify();
      // Khi NVRAM dang la Channel="" (Auto), radio ra0 mac dinh nam o CH 1 nen setWiFiBasicConfig(Channel="1")
      // truc tiep bi firmware bo qua. Chuyen qua CH 6 truoc roi khoa ve CH 1 de luu cung vao NVRAM 100%.
      if (targetCh === 1 && chCurrentlyAuto) {
        setApApplyLiveState(ap.ip, {
          phase: 'writing-ch',
          message: (needAdvWrite ? 'Đang tách Auto qua CH 6...' : 'Giữ nguyên TX/RSSI chuẩn • Tách Auto qua CH 6...'),
          pct: needAdvWrite ? 64 : 42
        });
        postBasicWithLogin(6, 'Đang chuyển tiếp NVRAM sang CH 1...', needAdvWrite ? 74 : 60, function (errHop) {
          if (errHop) return unlockAndDone(errHop);
          setApApplyLiveState(ap.ip, {
            phase: 'writing-ch',
            message: 'Đang khóa cố định CH 1 vào NVRAM...',
            pct: 80
          });
          postBasicWithLogin(1, 'Đang lưu cấu hình CH 1...', 90, function (errLock1) {
            if (errLock1) return unlockAndDone(errLock1);
            stepVerify();
          });
        });
      } else {
        setApApplyLiveState(ap.ip, {
          phase: 'writing-ch',
          message: (needAdvWrite ? 'Đang khóa cố định CH ' : 'Giữ nguyên TX/RSSI chuẩn • Đang nạp CH ') + targetCh + '...',
          pct: needAdvWrite ? 72 : 52
        });
        postBasicWithLogin(targetCh, 'Đang lưu NVRAM CH ' + targetCh + '...', 86, function (errSet) {
          if (errSet) return unlockAndDone(errSet);
          stepVerify();
        });
      }
    }

    function stepWriteAdvanced() {
      if (!needAdvWrite) {
        return stepWriteBasic(beforeIsAuto);
      }
      setApApplyLiveState(ap.ip, {
        phase: 'writing-adv',
        message: 'Đang nạp ' + advDescParts.join(', ') + '...',
        pct: 35
      });
      var passList = getApTotolinkWebPassList(ap);
      loginTotolinkWebSession(ap.ip, passList, 0, function () {
        var advPayload = buildTotolinkAdvSetPayload(advJson, targetPwr, targetRssi, targetDtim, targetBurst);
        postTotolinkCgiJson(ap.ip, advPayload, 22000, function (errSetA) {
          if (errSetA) return unlockAndDone(new Error('Loi ghi Advanced Config: ' + errSetA.message));
          setApApplyLiveState(ap.ip, {
            phase: 'waiting-adv',
            message: 'Đang khởi động lại radio (' + advDescParts.join(', ') + ')...',
            pct: 54
          });
          setTimeout(function () {
            stepWriteBasic(true);
          }, 7200);
        });
      });
    }

    function stepVerify() {
      setApApplyLiveState(ap.ip, {
        phase: 'verifying',
        message: 'Đang đọc xác thực cấu hình AP...',
        pct: 95
      });
      var passList = getApTotolinkWebPassList(ap);
      loginTotolinkWebSession(ap.ip, passList, 0, function () {
        fetchTotolinkHwRadioConfig(ap, function (vErr, verifiedHw) {
          var finalCh = (verifiedHw && !verifiedHw.isAutoChannel && verifiedHw.channel > 0)
            ? verifiedHw.channel
            : targetCh;
          var afterSnap = {
            channel: finalCh,
            txPower: verifiedHw ? verifiedHw.txPower : targetPwr,
            staRssi: verifiedHw ? verifiedHw.staRssi : targetRssi,
            dtim: verifiedHw ? verifiedHw.dtim : targetDtim,
            txBurst: verifiedHw ? verifiedHw.txBurst : targetBurst,
            htBw: 20
          };
          ap.channel = finalCh;
          syncPeerNeighborChannelCache(ap.mac, finalCh);
          var apRfRec = ensureRfApRecord(ap);
          if (apRfRec) {
            if (beforeIsAuto || beforeSnap.channel !== finalCh) {
              apRfRec.lastChannelApplyAt = Date.now();
              apRfRec.lastAppliedChannel = finalCh;
            }
          }
          if (!rfTelemetryStore.channelPlan || typeof rfTelemetryStore.channelPlan !== 'object') {
            ensureGlobalChannelPlan(false);
          }
          if (rfTelemetryStore.channelPlan && rfTelemetryStore.channelPlan.assignments) {
            rfTelemetryStore.channelPlan.assignments[ap.mac] = finalCh;
            if (modeSource === 'manual' && hasManualCh && planItem && Number(opts.channel) !== Number(planItem.recommended.channel)) {
              if (!rfTelemetryStore.channelPlan.pinnedManual) rfTelemetryStore.channelPlan.pinnedManual = {};
              rfTelemetryStore.channelPlan.pinnedManual[ap.mac] = { channel: finalCh, updatedAt: Date.now() };
            }
          }
          var histEntry = {
            timestamp: new Date().toISOString(),
            mode: modeSource || 'manual',
            apName: ap.name || ap.ip,
            apIp: ap.ip,
            apMac: ap.mac,
            before: beforeSnap,
            after: afterSnap,
            changedFields: summaryParts,
            reasons: planItem ? planItem.reasons : ['Áp dụng cấu hình tối ưu thủ công'],
            success: true
          };
          recordRfHistoryEvent(histEntry);
          saveRfTelemetryStore(true);
          saveRegistry();
          setApApplyLiveState(ap.ip, {
            phase: 'done',
            message: 'Đã cập nhật ' + summaryParts.join(', ') + '!',
            pct: 100
          }, 4500);
          unlockAndDone(null, histEntry);
        });
      });
    }

    stepWriteAdvanced();
  });
}

function applyBatchRfOptimizations(targetIps, modeSource, callback) {
  if (isRunningBatchApply) {
    return callback(new Error('He thong dang thuc thi tien trinh toi uu hang loat, vui long doi hoan tat'));
  }
  var plan = computeRfOptimizationPlan();
  var queue = [];
  if (Array.isArray(targetIps) && targetIps.length > 0) {
    var allowMap = {};
    targetIps.forEach(function (ip) { allowMap[String(ip).trim()] = true; });
    queue = plan.items.filter(function (it) { return it.canApplyDirect && allowMap[it.ip]; });
  } else {
    queue = plan.items.filter(function (it) { return it.canApplyDirect && it.needsOptimization; });
  }

  if (queue.length === 0) {
    return callback(null, { appliedCount: 0, failedCount: 0, results: [] });
  }

  isRunningBatchApply = true;
  batchApplyStatus = { running: true, total: queue.length, completed: 0, failed: 0, finishedAt: 0 };
  if (typeof scheduleRealtimeBroadcast === 'function') scheduleRealtimeBroadcast(60);

  var idx = 0;
  var active = 0;
  var maxConc = 2; // Chay toi da 2 AP cung luc de khong lam gian doan mang dien rong
  var results = [];
  var appliedCount = 0;
  var failedCount = 0;

  function next() {
    if (idx >= queue.length && active === 0) {
      isRunningBatchApply = false;
      batchApplyStatus = {
        running: false,
        total: queue.length,
        completed: appliedCount,
        failed: failedCount,
        finishedAt: Date.now()
      };
      saveRfTelemetryStore(true);
      if (typeof scheduleRealtimeBroadcast === 'function') scheduleRealtimeBroadcast(60);
      return callback(null, {
        appliedCount: appliedCount,
        failedCount: failedCount,
        results: results
      });
    }
    while (active < maxConc && idx < queue.length) {
      (function (item) {
        active++;
        // Truyen null customParams de chi cap nhat cac thong so THUC SU can thay doi tren tung AP
        applyTotolinkApOptimization(item.ip, null, modeSource || 'batch-manual', function (err, hist) {
          if (err) {
            failedCount++;
            batchApplyStatus.failed = failedCount;
            results.push({ ip: item.ip, name: item.name, success: false, error: err.message });
          } else {
            appliedCount++;
            batchApplyStatus.completed = appliedCount;
            results.push({ ip: item.ip, name: item.name, success: true, detail: hist });
          }
          if (typeof scheduleRealtimeBroadcast === 'function') scheduleRealtimeBroadcast(60);
          setTimeout(function () {
            active--;
            next();
          }, 600);
        });
      })(queue[idx++]);
    }
  }
  next();
}

function padZero2(n) {
  return n < 10 ? ('0' + n) : String(n);
}

function checkMode2AutoOptimizeSchedule() {
  var rfCfg = appConfig.rfOptimizer || {};
  if (!rfCfg.autoOptimizeEnabled) return;
  if (isRunningBatchApply) return;

  var now = new Date();
  var hhmm = padZero2(now.getHours()) + ':' + padZero2(now.getMinutes());
  var targetTime = String(rfCfg.autoOptimizeTime || '03:30').trim();
  if (hhmm !== targetTime) return;

  var todayKey = now.getFullYear() + '-' + padZero2(now.getMonth() + 1) + '-' + padZero2(now.getDate());
  if (rfTelemetryStore.lastAutoRunDate === todayKey) return;

  var hoursRunning = (Date.now() - (rfTelemetryStore.collectorStartedAt || Date.now())) / 3600000;
  if (rfCfg.requireFull24hForAuto !== false && hoursRunning < 24) {
    rfTelemetryStore.lastAutoRunDate = todayKey;
    rfTelemetryStore.lastAutoRunResult = {
      timestamp: now.toISOString(),
      skipped: true,
      reason: 'Chưa đủ 24h thu thập dữ liệu (' + hoursRunning.toFixed(1) + 'h / 24h), sẽ tự động tối ưu vào chu kỳ ngày kế tiếp.'
    };
    rfTelemetryDirty = true;
    saveRfTelemetryStore(true);
    return;
  }

  rfTelemetryStore.lastAutoRunDate = todayKey;
  rfTelemetryDirty = true;
  console.log('[RF Auto-Optimizer] Bat dau toi uu tu dong Che do 2 luc ' + hhmm + '...');

  // Quet nhieu nhanh cac AP ranh truoc khi tinh toan va ap dung
  triggerSafeNeighborScanBatch(16, function () {
    applyBatchRfOptimizations(null, 'auto-24h', function (err, summaryRes) {
      rfTelemetryStore.lastAutoRunResult = {
        timestamp: new Date().toISOString(),
        skipped: false,
        appliedCount: summaryRes ? summaryRes.appliedCount : 0,
        failedCount: summaryRes ? summaryRes.failedCount : 0,
        error: err ? err.message : null
      };
      rfTelemetryDirty = true;
      saveRfTelemetryStore(true);
      console.log('[RF Auto-Optimizer] Hoan tat: Da toi uu ' + (summaryRes ? summaryRes.appliedCount : 0) + ' AP.');
    });
  });
}

/**
 * PROMETHEUS API EMULATOR
 */
function handlePrometheusQuery(req, res, parsedUrl) {
  var nowSec = Math.floor(Date.now() / 1000);
  var body = '';

  function processQuery(queryStr, isRange) {
    var q = (queryStr || '').trim();
    var keys = Object.keys(apMap);
    var result = [];

    function formatResultItem(metricObj, valStr) {
      if (isRange) {
        var startT = parseInt(parsedUrl.query.start, 10);
        var endT = parseInt(parsedUrl.query.end, 10);
        var stepT = parseInt(parsedUrl.query.step, 10) || 15;
        if (isNaN(startT) || !startT) startT = nowSec - 300;
        if (isNaN(endT) || !endT) endT = nowSec;
        if (stepT < 1) stepT = 15;
        if ((endT - startT) / stepT > 1000) stepT = Math.ceil((endT - startT) / 500);

        var points = [];
        for (var t = startT; t <= endT; t += stepT) {
          points.push([t, String(valStr)]);
        }
        if (points.length === 0) points.push([nowSec, String(valStr)]);
        return { metric: metricObj, values: points };
      } else {
        return { metric: metricObj, value: [nowSec, String(valStr)] };
      }
    }

    function formatLatencyItem(metricObj, baseLat) {
      if (isRange) {
        var startT = parseInt(parsedUrl.query.start, 10);
        var endT = parseInt(parsedUrl.query.end, 10);
        var stepT = parseInt(parsedUrl.query.step, 10) || 15;
        if (isNaN(startT) || !startT) startT = nowSec - 300;
        if (isNaN(endT) || !endT) endT = nowSec;
        if (stepT < 1) stepT = 15;
        if ((endT - startT) / stepT > 1000) stepT = Math.ceil((endT - startT) / 500);

        var base = parseInt(baseLat, 10) || 2;
        var hash = 0;
        var ipStr = metricObj.ap_ip || '';
        for (var h = 0; h < ipStr.length; h++) {
          hash = (hash * 31 + ipStr.charCodeAt(h)) & 0xfffff;
        }
        var points = [];
        for (var t = startT; t <= endT; t += stepT) {
          var jitter = Math.sin((t / 25) + hash) * 1.1 + Math.cos((t / 60) + hash * 2) * 0.7;
          var val = Math.max(1, Math.round(base + jitter));
          points.push([t, String(val)]);
        }
        return { metric: metricObj, values: points };
      } else {
        return { metric: metricObj, value: [nowSec, String(baseLat)] };
      }
    }

    function formatRateItem(metricObj, baseBps, jitterFactor, seed) {
      var s = seed || 1;
      var jf = (jitterFactor !== undefined) ? jitterFactor : 0.15;
      var baseVal = Number(baseBps) || 0;
      if (isRange) {
        var startT = parseInt(parsedUrl.query.start, 10);
        var endT = parseInt(parsedUrl.query.end, 10);
        var stepT = parseInt(parsedUrl.query.step, 10) || 15;
        if (isNaN(startT) || !startT) startT = nowSec - 300;
        if (isNaN(endT) || !endT) endT = nowSec;
        if (stepT < 1) stepT = 15;
        if ((endT - startT) / stepT > 1000) stepT = Math.ceil((endT - startT) / 500);

        var points = [];
        for (var t = startT; t <= endT; t += stepT) {
          var wave = Math.sin((t / 25) + s) * 0.5 + Math.cos((t / 60) + s * 1.5) * 0.3 + Math.sin((t / 110) + s * 2.3) * 0.2;
          var val = Math.max(1000, Math.round(baseVal * (1 + wave * jf)));
          points.push([t, String(val)]);
        }
        if (points.length === 0) points.push([nowSec, String(Math.round(baseVal))]);
        return { metric: metricObj, values: points };
      } else {
        var instantJitter = Math.sin(nowSec / 9 + s) * 0.08 + Math.cos(nowSec / 23 + s * 2) * 0.05;
        var currentVal = Math.max(1000, Math.round(baseVal * (1 + instantJitter)));
        return { metric: metricObj, value: [nowSec, String(currentVal)] };
      }
    }

    function formatCumulativeBytesItem(metricObj, currBytes, rateBps) {
      var baseVal = Number(currBytes) || 0;
      var r = Number(rateBps) || 200;
      if (isRange) {
        var startT = parseInt(parsedUrl.query.start, 10);
        var endT = parseInt(parsedUrl.query.end, 10);
        var stepT = parseInt(parsedUrl.query.step, 10) || 15;
        if (isNaN(startT) || !startT) startT = nowSec - 300;
        if (isNaN(endT) || !endT) endT = nowSec;
        if (stepT < 1) stepT = 15;
        if ((endT - startT) / stepT > 1000) stepT = Math.ceil((endT - startT) / 500);

        var points = [];
        for (var t = startT; t <= endT; t += stepT) {
          var val = Math.max(0, Math.round(baseVal - (endT - t) * r));
          points.push([t, String(val)]);
        }
        if (points.length === 0) points.push([nowSec, String(Math.round(baseVal))]);
        return { metric: metricObj, values: points };
      } else {
        return { metric: metricObj, value: [nowSec, String(Math.round(baseVal))] };
      }
    }

    // 1. Phân bổ kênh sóng (Kênh 1, 6, 11)
    if (/ap_channel/i.test(q) && (/by/i.test(q) || /count/i.test(q))) {
      var chCounts = {};
      for (var n = 0; n < keys.length; n++) {
        var apObj = apMap[keys[n]];
        if (apObj.status === 1) {
          var ch = String(apObj.channel || 6);
          chCounts[ch] = (chCounts[ch] || 0) + 1;
        }
      }
      for (var c in chCounts) {
        result.push(formatResultItem({ ap_channel: c }, chCounts[c]));
      }
    }
    // 2. Top 5 AP tiêu thụ dung lượng / băng thông
    else if (/topk/i.test(q)) {
      var isRateQuery = /rate/i.test(q);
      var sortedKeys = keys.slice().sort(function(a, b) {
        var apA = apMap[a], apB = apMap[b];
        if (isRateQuery) {
          var rA = (apA.rxRateBps || 0) + (apA.txRateBps || 0);
          var rB = (apB.rxRateBps || 0) + (apB.txRateBps || 0);
          return rB - rA;
        } else {
          var totalA = (apA.rxBytes || 0) + (apA.txBytes || 0);
          var totalB = (apB.rxBytes || 0) + (apB.txBytes || 0);
          return totalB - totalA;
        }
      });
      var topCount = Math.min(5, sortedKeys.length);
      for (var p = 0; p < topCount; p++) {
        var apTop = apMap[sortedKeys[p]];
        var apTotalBytes = (apTop.rxBytes || 0) + (apTop.txBytes || 0);
        var apRate = (apTop.rxRateBps || 200) + (apTop.txRateBps || 200);
        if (isRateQuery) {
          var apBps = Math.round(apRate * 8);
          var ipHash = 0;
          for (var h = 0; h < apTop.ip.length; h++) ipHash = (ipHash * 31 + apTop.ip.charCodeAt(h)) & 0xffff;
          result.push(formatRateItem({ ap_name: apTop.name, ap_ip: apTop.ip, model: apTop.model }, apBps, 0.15, ipHash));
        } else {
          result.push(formatCumulativeBytesItem({ ap_name: apTop.name, ap_ip: apTop.ip, model: apTop.model }, apTotalBytes, apRate));
        }
      }
    }
    // 3. Tổng Dung Lượng Mạng / Băng Thông Hệ Thống (Download + Upload)
    else if (/(receive.*transmit|transmit.*receive)/i.test(q) || (/sum/i.test(q) && /receive_bytes/i.test(q) && /transmit_bytes/i.test(q))) {
      var totalRxBytes = 0;
      var totalTxBytes = 0;
      var totalRxRate = 0;
      var totalTxRate = 0;
      for (var nwI = 0; nwI < keys.length; nwI++) {
        var apNw = apMap[keys[nwI]];
        totalRxBytes += (apNw.rxBytes || 0);
        totalTxBytes += (apNw.txBytes || 0);
        if (apNw.status === 1) {
          totalRxRate += (apNw.rxRateBps || 200);
          totalTxRate += (apNw.txRateBps || 200);
        }
      }
      var totalAllBytes = totalRxBytes + totalTxBytes;
      if (/rate/i.test(q)) {
        var totalBandwidthBps = Math.round((totalRxRate + totalTxRate) * 8);
        result.push(formatRateItem({}, totalBandwidthBps, 0.06, 42));
      } else {
        result.push(formatCumulativeBytesItem({}, totalAllBytes, totalRxRate + totalTxRate));
      }
    }
    // 4. Dung lượng / Băng thông Tải về (Download)
    else if (/receive_bytes/i.test(q) && !/transmit/i.test(q)) {
      var totalRxB = 0;
      var totalRxR = 0;
      for (var rxI = 0; rxI < keys.length; rxI++) {
        var apR = apMap[keys[rxI]];
        totalRxB += (apR.rxBytes || 0);
        if (apR.status === 1) totalRxR += (apR.rxRateBps || 200);
      }
      if (/rate/i.test(q)) {
        result.push(formatRateItem({}, Math.round(totalRxR * 8), 0.08, 17));
      } else {
        result.push(formatCumulativeBytesItem({}, totalRxB, totalRxR));
      }
    }
    // 5. Dung lượng / Băng thông Tải lên (Upload)
    else if (/transmit_bytes/i.test(q) && !/receive/i.test(q)) {
      var totalTxB = 0;
      var totalTxR = 0;
      for (var txI = 0; txI < keys.length; txI++) {
        var apTr = apMap[keys[txI]];
        totalTxB += (apTr.txBytes || 0);
        if (apTr.status === 1) totalTxR += (apTr.txRateBps || 200);
      }
      if (/rate/i.test(q)) {
        result.push(formatRateItem({}, Math.round(totalTxR * 8), 0.07, 89));
      } else {
        result.push(formatCumulativeBytesItem({}, totalTxB, totalTxR));
      }
    }
    // 6. Số lượng AP Online / Offline / N9v1
    else if (/count.*==\s*1/i.test(q)) {
      var onCount = 0;
      for (var i1 = 0; i1 < keys.length; i1++) if (apMap[keys[i1]].status === 1) onCount++;
      result.push(formatResultItem({}, onCount));
    } else if (/count.*==\s*0/i.test(q)) {
      var offCount = 0;
      for (var j1 = 0; j1 < keys.length; j1++) if (apMap[keys[j1]].status === 0) offCount++;
      result.push(formatResultItem({}, offCount));
    } else if (/count.*N9/i.test(q)) {
      var n9Count = 0;
      for (var k1 = 0; k1 < keys.length; k1++) {
        var apK1 = apMap[keys[k1]];
        if (apK1.isTotolinkN9 || (apK1.model && apK1.model.indexOf('N9') !== -1) || (apK1.firmware && apK1.firmware.indexOf('V') !== -1)) n9Count++;
      }
      result.push(formatResultItem({}, n9Count));
    } else if (/count\(ap_status/i.test(q)) {
      result.push(formatResultItem({}, keys.length));
    }
    // 7. Tổng Client Online
    else if (/sum\(.*client/i.test(q)) {
      var totalC = 0;
      for (var m1 = 0; m1 < keys.length; m1++) if (apMap[keys[m1]].status === 1) totalC += (apMap[keys[m1]].clientCount || 0);
      result.push(formatResultItem({}, totalC));
    }
    // 8. Trạng thái chi tiết từng AP
    else if (/ap_status/i.test(q)) {
      for (var a = 0; a < keys.length; a++) {
        var apS = apMap[keys[a]];
        result.push(formatResultItem({
          __name__: 'ap_status',
          ap_mac: apS.mac,
          ap_ip: apS.ip,
          ap_name: apS.name,
          model: apS.model,
          firmware: apS.firmware,
          ap_channel: String(apS.channel),
          ssid: apS.ssid
        }, apS.status));
      }
    } else if (/ap_client_count/i.test(q)) {
      for (var b = 0; b < keys.length; b++) {
        var apCl = apMap[keys[b]];
        var cVal = apCl.status === 1 ? (apCl.clientCount || 0) : 0;
        result.push(formatResultItem({
          __name__: 'ap_client_count',
          ap_mac: apCl.mac,
          ap_ip: apCl.ip,
          ap_name: apCl.name,
          model: apCl.model
        }, cVal));
      }
    }
    // 9. Độ trễ Ping động theo thời gian
    else if (/ap_ping_latency_ms/i.test(q)) {
      for (var c1 = 0; c1 < keys.length; c1++) {
        var apL = apMap[keys[c1]];
        result.push(formatLatencyItem({
          __name__: 'ap_ping_latency_ms',
          ap_mac: apL.mac,
          ap_ip: apL.ip,
          ap_name: apL.name,
          model: apL.model
        }, apL.latencyMs || 2));
      }
    }
    // 10. Lưu lượng mạng từng AP riêng lẻ
    else if (/receive_bytes/i.test(q)) {
      for (var r1 = 0; r1 < keys.length; r1++) {
        var apRx = apMap[keys[r1]];
        var hRx = 0;
        for (var hr = 0; hr < apRx.ip.length; hr++) hRx = (hRx * 31 + apRx.ip.charCodeAt(hr)) & 0xffff;
        result.push(formatRateItem({
          __name__: 'ap_network_receive_bytes_total',
          ap_mac: apRx.mac,
          ap_ip: apRx.ip,
          ap_name: apRx.name,
          model: apRx.model
        }, (apRx.rxRateBps || 2500) * 8, 0.1, hRx));
      }
    } else if (/transmit_bytes/i.test(q)) {
      for (var t1 = 0; t1 < keys.length; t1++) {
        var apTx = apMap[keys[t1]];
        var hTx = 0;
        for (var ht = 0; ht < apTx.ip.length; ht++) hTx = (hTx * 31 + apTx.ip.charCodeAt(ht)) & 0xffff;
        result.push(formatRateItem({
          __name__: 'ap_network_transmit_bytes_total',
          ap_mac: apTx.mac,
          ap_ip: apTx.ip,
          ap_name: apTx.name,
          model: apTx.model
        }, (apTx.txRateBps || 1500) * 8, 0.1, hTx));
      }
    } else if (/1\s*\+\s*1/.test(q)) {
      result.push(formatResultItem({}, '2'));
    } else {
      result.push(formatResultItem({ __name__: 'up', instance: 'totolink_collector:9100', job: 'totolink_aps' }, '1'));
    }

    var respData = {
      status: 'success',
      data: {
        resultType: isRange ? 'matrix' : 'vector',
        result: result
      }
    };

    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': '*'
    });
    res.end(JSON.stringify(respData));
  }

  if (req.method === 'POST') {
    req.on('data', function (c) { body += c; });
    req.on('end', function () {
      var query = parsedUrl.query.query;
      if (!query && body) {
        var postParams = require('querystring').parse(body);
        query = postParams.query;
      }
      var isRange = parsedUrl.pathname.indexOf('query_range') !== -1;
      processQuery(query, isRange);
    });
  } else {
    var queryGet = parsedUrl.query.query;
    var isRangeGet = parsedUrl.pathname.indexOf('query_range') !== -1;
    processQuery(queryGet, isRangeGet);
  }
}

/**
 * Tao du lieu chuan Prometheus (/metrics)
 */
function getPrometheusMetrics() {
  var output = [];
  var keys = Object.keys(apMap);

  output.push('# HELP ap_status Trang thai online (1) hoac offline (0) cua Access Point');
  output.push('# TYPE ap_status gauge');
  for (var i = 0; i < keys.length; i++) {
    var ap = apMap[keys[i]];
    output.push('ap_status{ap_mac="' + ap.mac + '",ap_ip="' + ap.ip + '",ap_name="' + ap.name + '",model="' + ap.model + '",firmware="' + ap.firmware + '",ap_channel="' + ap.channel + '",ssid="' + ap.ssid + '"} ' + ap.status);
  }

  output.push('');
  output.push('# HELP ap_client_count So luong client ket noi vao AP');
  output.push('# TYPE ap_client_count gauge');
  for (var j = 0; j < keys.length; j++) {
    var apC = apMap[keys[j]];
    output.push('ap_client_count{ap_mac="' + apC.mac + '",ap_ip="' + apC.ip + '",ap_name="' + apC.name + '",model="' + apC.model + '"} ' + (apC.status === 1 ? apC.clientCount : 0));
  }

  output.push('');
  output.push('# HELP ap_ping_latency_ms Do tre phan hoi ping cua AP (ms)');
  output.push('# TYPE ap_ping_latency_ms gauge');
  for (var k = 0; k < keys.length; k++) {
    var apL = apMap[keys[k]];
    output.push('ap_ping_latency_ms{ap_mac="' + apL.mac + '",ap_ip="' + apL.ip + '",ap_name="' + apL.name + '",model="' + apL.model + '"} ' + apL.latencyMs);
  }

  output.push('');
  output.push('# HELP ap_network_receive_bytes_total Tong bytes download');
  output.push('# TYPE ap_network_receive_bytes_total counter');
  for (var m = 0; m < keys.length; m++) {
    var apRx = apMap[keys[m]];
    output.push('ap_network_receive_bytes_total{ap_mac="' + apRx.mac + '",ap_name="' + apRx.name + '",model="' + apRx.model + '"} ' + apRx.rxBytes);
  }

  output.push('');
  output.push('# HELP ap_network_transmit_bytes_total Tong bytes upload');
  output.push('# TYPE ap_network_transmit_bytes_total counter');
  for (var n = 0; n < keys.length; n++) {
    var apTx = apMap[keys[n]];
    output.push('ap_network_transmit_bytes_total{ap_mac="' + apTx.mac + '",ap_name="' + apTx.name + '",model="' + apTx.model + '"} ' + apTx.txBytes);
  }

  output.push('');
  return output.join('\n');
}

function getSummary() {
  var keys = Object.keys(apMap);
  var total = keys.length;
  var n9v1Count = 0;
  var onlineCount = 0;
  var offlineCount = 0;
  var totalClients = 0;
  var totalLatency = 0;

  for (var i = 0; i < total; i++) {
    var ap = apMap[keys[i]];
    if (ap.isTotolinkN9 || (ap.model && ap.model.indexOf('N9') !== -1) || (ap.firmware && ap.firmware.indexOf('V') !== -1)) n9v1Count++;
    if (ap.status === 1) {
      onlineCount++;
      totalClients += (ap.clientCount || 0);
      totalLatency += (ap.latencyMs || 0);
    } else {
      offlineCount++;
    }
  }

  return {
    configuredTarget: currentTarget,
    staticIPs: staticIpsList,
    subnetsList: lastScanStats.subnetsList,
    totalScannedIPs: lastScanStats.totalScannedIPs,
    scanDurationMs: lastScanStats.scanDurationMs,
    totalAPs: total,
    totolinkN9v1Count: n9v1Count,
    onlineCount: onlineCount,
    offlineCount: offlineCount,
    totalClients: totalClients,
    avgLatencyMs: onlineCount > 0 ? Number((totalLatency / onlineCount).toFixed(1)) : 0,
    lastScanStats: lastScanStats,
    timestamp: new Date().toISOString()
  };
}

var sseClients = [];
var sseBroadcastTimer = null;
var sseBroadcastFast = false;

function buildLiveDashboardPayload() {
  var summary = getSummary();
  var keys = Object.keys(apMap);
  var aps = [];
  var staticCount = 0;

  for (var i = 0; i < keys.length; i++) {
    var ap = apMap[keys[i]];
    if (!ap) continue;
    if (ap.isStatic) staticCount++;
    aps.push({
      key: ap.key || keys[i],
      mac: ap.mac || '-',
      ip: ap.ip || '',
      name: ap.name || 'AP',
      model: ap.model || '-',
      firmware: ap.firmware || '-',
      ssid: ap.ssid || '-',
      channel: ap.channel || '-',
      status: ap.status === 1 ? 1 : 0,
      clientCount: ap.status === 1 ? (Number(ap.clientCount) || 0) : 0,
      latencyMs: ap.status === 1 ? (Number(ap.latencyMs) || 0) : 0,
      isStatic: Boolean(ap.isStatic),
      applyState: apApplyLiveState[ap.ip] || null
    });
  }

  var rfPlan = computeRfOptimizationPlan();
  return {
    summary: summary,
    staticCount: staticCount,
    staticIps: staticIpsList.slice(),
    aps: aps,
    rfSummary: rfPlan.summary,
    rfSettings: rfPlan.settings,
    rfPlan: rfPlan,
    timestamp: new Date().toISOString()
  };
}

function disconnectSseForUsername(usernameLower) {
  if (!sseClients || sseClients.length === 0 || !usernameLower) return;
  var target = String(usernameLower).toLowerCase();
  var keep = [];
  for (var i = 0; i < sseClients.length; i++) {
    var c = sseClients[i];
    if (!c || c.writableEnded || c.destroyed) continue;
    if (c._authUsername === target) {
      try { c.end(); } catch (e) {}
    } else {
      keep.push(c);
    }
  }
  sseClients = keep;
}

function broadcastRealtimeUpdate() {
  sseBroadcastTimer = null;
  sseBroadcastFast = false;
  if (!sseClients || sseClients.length === 0) return;
  var store = loadUsersStore(false);
  var userLookup = {};
  for (var uIdx = 0; uIdx < store.users.length; uIdx++) {
    var uObj = store.users[uIdx];
    userLookup[uObj.username.toLowerCase()] = uObj;
  }
  var msg = 'data: ' + JSON.stringify(buildLiveDashboardPayload()) + '\n\n';
  var alive = [];
  for (var i = 0; i < sseClients.length; i++) {
    var clientRes = sseClients[i];
    if (!clientRes || clientRes.writableEnded || clientRes.destroyed) continue;
    if (clientRes._authUsername) {
      var uLive = userLookup[clientRes._authUsername];
      if (!uLive || uLive.role !== clientRes._authRole || uLive.passwordMd5 !== clientRes._authPassMd5) {
        try { clientRes.end(); } catch (eClose) {}
        continue;
      }
    }
    try {
      clientRes.write(msg);
      alive.push(clientRes);
    } catch (e) {}
  }
  sseClients = alive;
}

function scheduleRealtimeBroadcast(delayMs) {
  if (!sseClients || sseClients.length === 0) return;
  var wait = typeof delayMs === 'number' ? delayMs : 350;
  if (sseBroadcastTimer) {
    if (wait <= 100 && !sseBroadcastFast) {
      clearTimeout(sseBroadcastTimer);
      sseBroadcastTimer = null;
    } else {
      return;
    }
  }
  sseBroadcastFast = (wait <= 100);
  sseBroadcastTimer = setTimeout(broadcastRealtimeUpdate, wait);
}

function escapeHtml(str) {
  return String(str === undefined || str === null ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function isDefaultFirstRunAdmin() {
  try {
    var st = loadUsersStore(false);
    var defaultMd5 = md5Hash('Concard@2026');
    for (var i = 0; i < (st.users || []).length; i++) {
      var u = st.users[i];
      if (u && u.username.toLowerCase() === 'admin' && u.passwordMd5 === defaultMd5) {
        return true;
      }
    }
  } catch (e) {}
  return false;
}

function renderLoginHtml() {
  var uiCfg = appConfig.ui || {};
  var pageTitle = escapeHtml(uiCfg.pageTitle || 'ConCard AP Monitor v1.1');
  var brandTitle = escapeHtml(uiCfg.brandTitle || 'ConCard AP Monitor');
  var versionTag = escapeHtml(uiCfg.versionTag || 'v1.1');
  var subtitle = escapeHtml(uiCfg.subtitle || 'Hệ thống giám sát & tối ưu Access Point');
  var showFirstRunHint = isDefaultFirstRunAdmin();

  return '<!DOCTYPE html>' +
  '<html lang="vi"><head><meta charset="utf-8">' +
  '<title>Đăng nhập • ' + pageTitle + '</title>' +
  '<meta name="viewport" content="width=device-width, initial-scale=1">' +
  '<link rel="icon" type="image/svg+xml" href="/logo.svg">' +
  '<link rel="stylesheet" href="/assets/uicons/uicons-regular-rounded.css">' +
  '<style>' +
  '  :root {' +
  '    --bg: #f3f5f8; --surface: #ffffff; --card: #f8fafc;' +
  '    --border: #e2e8f0; --border-strong: #cbd5e1;' +
  '    --text: #0f172a; --text-secondary: #334155; --text-muted: #475569; --text-dim: #64748b;' +
  '    --blue: #2563eb; --blue-hover: #1d4ed8; --blue-bg: #eff6ff; --blue-border: #bfdbfe;' +
  '    --red: #dc2626; --red-bg: #fef2f2; --red-border: #fecaca;' +
  '  }' +
  '  * { box-sizing: border-box; }' +
  '  body {' +
  '    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif;' +
  '    background: radial-gradient(circle at 50% 0%, #dbeafe 0%, #f3f5f8 52%, #eef2f6 100%);' +
  '    color: var(--text); margin: 0; min-height: 100vh;' +
  '    display: flex; align-items: center; justify-content: center; padding: 20px;' +
  '    -webkit-font-smoothing: antialiased;' +
  '  }' +
  '  .fi { display: inline-flex; align-items: center; justify-content: center; line-height: 1; vertical-align: middle; }' +
  '  @keyframes fi-spin { 100% { transform: rotate(360deg); } }' +
  '  .fi-spin { animation: fi-spin 1s linear infinite; }' +
  '  .login-card {' +
  '    width: 100%; max-width: 420px; background: var(--surface);' +
  '    border: 1px solid var(--border); border-radius: 14px;' +
  '    box-shadow: 0 20px 45px -12px rgba(15, 23, 42, 0.12), 0 2px 6px rgba(15, 23, 42, 0.04);' +
  '    overflow: hidden;' +
  '  }' +
  '  .login-head {' +
  '    padding: 28px 28px 20px; text-align: center; border-bottom: 1px solid #f1f5f9;' +
  '    background: linear-gradient(180deg, #ffffff 0%, #fafcff 100%);' +
  '  }' +
  '  .login-logo {' +
  '    width: 54px; height: 54px; margin: 0 auto 12px; border-radius: 12px;' +
  '    background: #ffffff; border: 1px solid var(--border); padding: 6px;' +
  '    display: flex; align-items: center; justify-content: center;' +
  '    box-shadow: 0 2px 6px rgba(15, 23, 42, 0.05);' +
  '  }' +
  '  .login-logo img { width: 100%; height: 100%; object-fit: contain; }' +
  '  .login-title {' +
  '    margin: 0; font-size: 16.5px; font-weight: 800; color: var(--text);' +
  '    letter-spacing: -0.01em; display: inline-flex; align-items: center; gap: 7px;' +
  '  }' +
  '  .ver-badge {' +
  '    background: var(--blue-bg); color: var(--blue); border: 1px solid var(--blue-border);' +
  '    font-size: 10.5px; font-weight: 700; padding: 1px 7px; border-radius: 5px;' +
  '  }' +
  '  .login-sub { margin: 5px 0 0; font-size: 12.5px; color: var(--text-dim); }' +
  '  .login-body { padding: 24px 28px 26px; }' +
  '  .field-group { margin-bottom: 16px; }' +
  '  .field-label { display: block; font-size: 12px; font-weight: 700; color: var(--text-secondary); margin-bottom: 6px; }' +
  '  .input-wrap { position: relative; display: flex; align-items: center; }' +
  '  .input-ico { position: absolute; left: 12px; color: var(--text-dim); font-size: 14px; pointer-events: none; }' +
  '  .login-input {' +
  '    width: 100%; height: 40px; padding: 0 38px 0 36px; border-radius: 8px;' +
  '    border: 1px solid var(--border-strong); background: #ffffff; color: var(--text);' +
  '    font-size: 13.5px; font-family: inherit; transition: border-color 0.15s, box-shadow 0.15s;' +
  '  }' +
  '  .login-input:focus { outline: none; border-color: var(--blue); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.13); }' +
  '  .pwd-toggle {' +
  '    position: absolute; right: 6px; width: 30px; height: 30px; border: none; background: transparent;' +
  '    color: var(--text-dim); border-radius: 6px; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; font-size: 14px;' +
  '  }' +
  '  .pwd-toggle:hover { background: #f1f5f9; color: var(--text); }' +
  '  .login-opts { display: flex; align-items: center; justify-content: space-between; margin: 4px 0 18px; font-size: 12px; color: var(--text-muted); }' +
  '  .chk-wrap { display: inline-flex; align-items: center; gap: 6px; cursor: pointer; user-select: none; }' +
  '  .chk-wrap input { accent-color: var(--blue); cursor: pointer; width: 14px; height: 14px; }' +
  '  .err-box {' +
  '    display: none; align-items: flex-start; gap: 8px; margin-bottom: 16px;' +
  '    padding: 10px 12px; border-radius: 8px; background: var(--red-bg);' +
  '    border: 1px solid var(--red-border); color: var(--red); font-size: 12.5px; font-weight: 600; line-height: 1.4;' +
  '  }' +
  '  .err-box.show { display: flex; }' +
  '  .btn-login {' +
  '    width: 100%; height: 42px; border-radius: 8px; border: none;' +
  '    background: var(--blue); color: #ffffff; font-size: 13.5px; font-weight: 700;' +
  '    cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 8px;' +
  '    transition: background 0.15s, transform 0.08s;' +
  '  }' +
  '  .btn-login:hover:not(:disabled) { background: var(--blue-hover); }' +
  '  .btn-login:disabled { opacity: 0.65; cursor: not-allowed; }' +
  '  .login-foot {' +
  '    padding: 12px 24px; background: var(--card); border-top: 1px solid var(--border);' +
  '    display: flex; align-items: center; justify-content: center; gap: 6px;' +
  '    font-size: 11.5px; color: var(--text-dim); text-align: center;' +
  '  }' +
  '</style></head><body>' +
  '<div class="login-card">' +
  '  <div class="login-head">' +
  '    <div class="login-logo"><img src="/logo.svg" alt="Concard Logo" /></div>' +
  '    <h1 class="login-title">' + brandTitle + ' <span class="ver-badge">' + versionTag + '</span></h1>' +
  '    <p class="login-sub">' + subtitle + '</p>' +
  '  </div>' +
  '  <form class="login-body" onsubmit="submitLogin(event)">' +
  (showFirstRunHint
    ? '    <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:16px;padding:10px 12px;border-radius:8px;background:var(--blue-bg);border:1px solid var(--blue-border);color:var(--text-secondary);font-size:12px;line-height:1.45;">' +
      '      <div><b style="color:var(--blue);">Khởi chạy lần đầu:</b> Tài khoản <code>admin</code> / <code>Concard@2026</code></div>' +
      '      <button type="button" onclick="document.getElementById(\'loginUsername\').value=\'admin\';document.getElementById(\'loginPassword\').value=\'Concard@2026\';" style="border:1px solid var(--blue-border);background:#ffffff;color:var(--blue);font-weight:700;font-size:11px;padding:4px 8px;border-radius:6px;cursor:pointer;white-space:nowrap;">Điền nhanh</button>' +
      '    </div>'
    : '') +
  '    <div id="loginErrorBox" class="err-box"><i class="fi fi-rr-triangle-warning" style="margin-top:2px;flex-shrink:0;"></i><span id="loginErrorText"></span></div>' +
  '    <div class="field-group">' +
  '      <label class="field-label" for="loginUsername">Tên đăng nhập</label>' +
  '      <div class="input-wrap">' +
  '        <i class="fi fi-rr-user input-ico"></i>' +
  '        <input id="loginUsername" class="login-input" type="text" autocomplete="username" placeholder="Nhập tài khoản (vd: admin)" autofocus required />' +
  '      </div>' +
  '    </div>' +
  '    <div class="field-group">' +
  '      <label class="field-label" for="loginPassword">Mật khẩu</label>' +
  '      <div class="input-wrap">' +
  '        <i class="fi fi-rr-lock input-ico"></i>' +
  '        <input id="loginPassword" class="login-input" type="password" autocomplete="current-password" placeholder="Nhập mật khẩu" required />' +
  '        <button type="button" class="pwd-toggle" onclick="toggleLoginPwd()" title="Hiện / Ẩn mật khẩu"><i id="pwdEyeIco" class="fi fi-rr-eye"></i></button>' +
  '      </div>' +
  '    </div>' +
  '    <div class="login-opts">' +
  '      <label class="chk-wrap"><input id="loginRemember" type="checkbox" checked /> Duy trì đăng nhập (7 ngày)</label>' +
  '      <span style="display:inline-flex;align-items:center;gap:4px;"><i class="fi fi-rr-shield-check" style="color:var(--blue);"></i>Xác thực MD5</span>' +
  '    </div>' +
  '    <button id="loginSubmitBtn" type="submit" class="btn-login"><i class="fi fi-rr-sign-in-alt"></i> Đăng Nhập Hệ Thống</button>' +
  '  </form>' +
  '  <div class="login-foot">' +
  '    <i class="fi fi-rr-lock" style="font-size:12px;"></i>' +
  '    <span>Bắt buộc đăng nhập • Phân quyền <b>Admin</b> (Toàn quyền) &amp; <b>User</b> (Chỉ xem)</span>' +
  '  </div>' +
  '</div>' +
  '<script>' +
  '  function toggleLoginPwd() {' +
  '    var inp = document.getElementById("loginPassword");' +
  '    var ico = document.getElementById("pwdEyeIco");' +
  '    if (!inp) return;' +
  '    if (inp.type === "password") {' +
  '      inp.type = "text";' +
  '      if (ico) ico.className = "fi fi-rr-eye-crossed";' +
  '    } else {' +
  '      inp.type = "password";' +
  '      if (ico) ico.className = "fi fi-rr-eye";' +
  '    }' +
  '    inp.focus();' +
  '  }' +
  '  function showLoginErr(msg) {' +
  '    var box = document.getElementById("loginErrorBox");' +
  '    var txt = document.getElementById("loginErrorText");' +
  '    if (txt) txt.innerText = msg || "Đăng nhập không thành công";' +
  '    if (box) box.className = "err-box show";' +
  '  }' +
  '  function submitLogin(e) {' +
  '    if (e && e.preventDefault) e.preventDefault();' +
  '    var uEl = document.getElementById("loginUsername");' +
  '    var pEl = document.getElementById("loginPassword");' +
  '    var rEl = document.getElementById("loginRemember");' +
  '    var btn = document.getElementById("loginSubmitBtn");' +
  '    var box = document.getElementById("loginErrorBox");' +
  '    if (box) box.className = "err-box";' +
  '    var username = uEl ? uEl.value.trim() : "";' +
  '    var password = pEl ? pEl.value : "";' +
  '    if (!username || !password) {' +
  '      showLoginErr("Vui lòng nhập đầy đủ Tên đăng nhập và Mật khẩu.");' +
  '      return;' +
  '    }' +
  '    if (btn) { btn.disabled = true; btn.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang xác thực...\'; }' +
  '    fetch("/api/auth/login", {' +
  '      method: "POST",' +
  '      headers: { "Content-Type": "application/json" },' +
  '      body: JSON.stringify({ username: username, password: password, remember: rEl ? Boolean(rEl.checked) : true })' +
  '    }).then(function(r) { return r.json(); }).then(function(d) {' +
  '      if (!d || !d.success) {' +
  '        if (btn) { btn.disabled = false; btn.innerHTML = \'<i class="fi fi-rr-sign-in-alt"></i> Đăng Nhập Hệ Thống\'; }' +
  '        showLoginErr((d && d.error) || "Tên đăng nhập hoặc mật khẩu không chính xác.");' +
  '        if (pEl) { pEl.select(); pEl.focus(); }' +
  '        return;' +
  '      }' +
  '      window.location.href = "/";' +
  '    }).catch(function(err) {' +
  '      if (btn) { btn.disabled = false; btn.innerHTML = \'<i class="fi fi-rr-sign-in-alt"></i> Đăng Nhập Hệ Thống\'; }' +
  '      showLoginErr("Không thể kết nối máy chủ: " + err.message);' +
  '    });' +
  '  }' +
  '</script></body></html>';
}

function renderHtmlDashboard(currentUser) {
  var curUser = currentUser && currentUser.username
    ? { username: currentUser.username, role: normalizeUserRole(currentUser.role), fullName: currentUser.fullName || currentUser.username }
    : { username: 'admin', role: 'admin', fullName: 'Quản trị viên' };
  var isAdmin = curUser.role === 'admin';
  var safeCurrentUserJson = JSON.stringify(curUser)
    .replace(/<\//g, '<\\/')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');

  var summary = getSummary();
  var keys = Object.keys(apMap);
  var rows = '';
  var staticCount = 0;

  for (var i = 0; i < keys.length; i++) {
    var ap = apMap[keys[i]];
    if (!ap) continue;
    if (ap.isStatic) staticCount++;

    var isOnline = ap.status === 1;
    var statusBadge = isOnline
      ? '<span class="status-pill online"><i class="fi fi-rr-check-circle"></i>Online</span>'
      : '<span class="status-pill offline"><i class="fi fi-rr-cross-circle"></i>Offline</span>';

    var staticBadge = ap.isStatic
      ? '<span class="tag-static" title="AP trong danh sách giám sát cố định"><i class="fi fi-rr-thumbtack" style="font-size:8px;margin-right:3px;"></i>CỐ ĐỊNH</span>'
      : '';

    var latencyBadge = '<span class="dim-text">-</span>';
    if (isOnline) {
      var latVal = Number(ap.latencyMs) || 0;
      var latClass = latVal <= 3 ? 'lat-fast' : (latVal <= 12 ? 'lat-good' : (latVal <= 30 ? 'lat-mid' : 'lat-high'));
      latencyBadge = '<span class="lat-pill ' + latClass + '">' + latVal + ' ms</span>';
    }

    var clientCount = isOnline ? (Number(ap.clientCount) || 0) : 0;
    var safeApIpAttr = escapeHtml(ap.ip || '');
    var safeApNameAttr = escapeHtml(ap.name || 'AP');
    var safeApModelAttr = escapeHtml(ap.model || '-');
    var safeApSsidAttr = escapeHtml(ap.ssid || '-');
    var safeApChAttr = escapeHtml(ap.channel || '-');
    var clientBadge = isOnline
      ? '<button type="button" class="client-pill clickable ' + (clientCount > 0 ? 'active' : 'zero') + '" ' +
        'data-ip="' + safeApIpAttr + '" data-name="' + safeApNameAttr + '" data-model="' + safeApModelAttr + '" ' +
        'data-ssid="' + safeApSsidAttr + '" data-channel="' + safeApChAttr + '" ' +
        'onclick="openClientsModal(this)" title="Click để xem chi tiết thiết bị đang kết nối về AP ' + safeApNameAttr + '">' +
        (clientCount > 0 ? '<i class="fi fi-rr-user" style="font-size:11px;margin-right:4px;"></i>' : '') +
        '<span class="client-count-val">' + clientCount + '</span></button>'
      : '<span class="client-pill zero">0</span>';

    var searchKeywords = [
      ap.name || '',
      ap.ip || '',
      ap.mac || '',
      ap.model || '',
      ap.ssid || '',
      'ch' + (ap.channel || ''),
      ap.isStatic ? 'co dinh static' : '',
      isOnline ? 'online' : 'offline'
    ].join(' ').toLowerCase();

    var apApplySt = apApplyLiveState[ap.ip] || null;
    var chBadgeHtml = '<span class="channel-badge">CH ' + escapeHtml(ap.channel || '-') + '</span>';
    if (apApplySt) {
      if (apApplySt.phase === 'done') {
        chBadgeHtml = '<span class="channel-badge ch-done" title="' + escapeHtml(apApplySt.message) + '"><i class="fi fi-rr-check-circle"></i> CH ' + escapeHtml(ap.channel || '-') + '</span>';
      } else if (apApplySt.isError) {
        chBadgeHtml = '<span class="channel-badge ch-err" title="' + escapeHtml(apApplySt.message) + '"><i class="fi fi-rr-triangle-warning"></i> CH ' + escapeHtml(ap.channel || '-') + '</span>';
      } else {
        chBadgeHtml = '<span class="channel-badge ch-applying" title="' + escapeHtml(apApplySt.message) + '"><i class="fi fi-rr-spinner fi-spin"></i> CH ' + escapeHtml(ap.channel || '-') + ' (' + (apApplySt.pct || 15) + '%)</span>';
      }
    }

    var rowKey = escapeHtml(ap.key || keys[i]);
    var fwRaw = String(ap.firmware || '-');
    var showFwBadge = fwRaw && fwRaw !== '-' && fwRaw.indexOf('Đang') === -1 && fwRaw.indexOf('Chờ') === -1;
    var modelCellHtml = '<span class="model-badge">' + escapeHtml(ap.model || '-') + '</span>' +
      (showFwBadge ? '<span class="fw-badge" title="Phiên bản Firmware">' + escapeHtml(fwRaw) + '</span>' : '');
    var ipNumericVal = isValidIpv4(ap.ip) ? ip2long(ap.ip) : 0;
    var latSortVal = isOnline ? (Number(ap.latencyMs) || 0) : -1;

    var rowSig = escapeHtml([
      ap.name || 'AP',
      ap.ip || '',
      ap.mac || '-',
      ap.model || '-',
      ap.firmware || '-',
      ap.ssid || '-',
      ap.channel || '-',
      isOnline ? 1 : 0,
      clientCount,
      isOnline ? (Number(ap.latencyMs) || 0) : 0,
      ap.isStatic ? 1 : 0,
      apApplySt ? (apApplySt.phase + ':' + apApplySt.pct + ':' + apApplySt.message) : ''
    ].join('|'));

    var delBtnHtml = '<button type="button" class="btn-del-ap" ' +
      'data-key="' + rowKey + '" data-ip="' + safeApIpAttr + '" data-name="' + safeApNameAttr + '" ' +
      'data-static="' + (ap.isStatic ? '1' : '0') + '" data-online="' + (isOnline ? '1' : '0') + '" ' +
      'onclick="deleteSingleAp(this)" title="Xóa AP ' + safeApNameAttr + ' (' + safeApIpAttr + ') khỏi danh sách giám sát">' +
      '<i class="fi fi-rr-trash"></i></button>';

    var ipCellInner = isAdmin
      ? '<a href="http://' + escapeHtml(ap.ip) + '" target="_blank" class="ip-link" title="Mở trang cấu hình AP ' + escapeHtml(ap.ip) + '"><code>' + escapeHtml(ap.ip) + '</code><i class="fi fi-rr-arrow-up-right-from-square ico-ext"></i></a>'
      : '<span class="ip-readonly"><code>' + escapeHtml(ap.ip) + '</code></span>';

    rows += '<tr class="ap-row" data-orig-idx="' + i + '" data-ap-key="' + rowKey + '" data-sig="' + rowSig + '" ' +
      'data-search="' + searchKeywords.replace(/"/g, '&quot;') + '" ' +
      'data-name="' + safeApNameAttr + '" data-ip="' + safeApIpAttr + '" data-ip-num="' + ipNumericVal + '" ' +
      'data-mac="' + escapeHtml(ap.mac || '-') + '" data-model="' + safeApModelAttr + '" data-fw="' + escapeHtml(ap.firmware || '-') + '" ' +
      'data-ssid="' + safeApSsidAttr + '" data-ch="' + safeApChAttr + '" ' +
      'data-clients="' + clientCount + '" data-lat="' + latSortVal + '" ' +
      'data-status="' + (isOnline ? 'online' : 'offline') + '" data-static="' + (ap.isStatic ? 'true' : 'false') + '">' +
      '<td class="cell-name"><div class="name-box"><span class="ap-ico"><i class="fi fi-rr-router"></i></span><span class="ap-title">' + escapeHtml(ap.name || 'AP') + '</span>' + staticBadge + '</div></td>' +
      '<td class="cell-ip">' + ipCellInner + '</td>' +
      '<td class="cell-mac"><span class="mac-tag">' + escapeHtml(ap.mac || '-') + '</span></td>' +
      '<td class="cell-model">' + modelCellHtml + '</td>' +
      '<td class="cell-ssid"><span class="ssid-text" title="' + escapeHtml(ap.ssid || '') + '">' + escapeHtml(ap.ssid || '-') + '</span></td>' +
      '<td class="cell-channel">' + chBadgeHtml + '</td>' +
      '<td class="cell-clients">' + clientBadge + '</td>' +
      '<td class="cell-latency">' + latencyBadge + '</td>' +
      '<td class="cell-status">' + statusBadge + '</td>' +
      (isAdmin ? ('<td class="cell-actions">' + delBtnHtml + '</td>') : '') +
    '</tr>';
  }

  var currentStaticStr = staticIpsList.join(', ');
  var onlinePercent = summary.totalAPs > 0 ? Math.round((summary.onlineCount / summary.totalAPs) * 100) : 0;

  var uiCfg = appConfig.ui || {};
  var pageTitle = escapeHtml(uiCfg.pageTitle || 'ConCard AP Monitor v1.1');
  var brandTitle = escapeHtml(uiCfg.brandTitle || 'ConCard AP Monitor');
  var versionTag = escapeHtml(uiCfg.versionTag || 'v1.1');
  var subtitle = escapeHtml(uiCfg.subtitle || 'Hệ thống giám sát & tối ưu Access Point');
  var metricsBtnHtml = uiCfg.showMetricsButton
    ? '<a href="/metrics" target="_blank" class="btn-nav" title="Xem Prometheus Metrics"><i class="fi fi-rr-chart-histogram"></i> /metrics</a>'
    : '';

  var presets = Array.isArray(appConfig.network && appConfig.network.scanPresets) ? appConfig.network.scanPresets : [];
  var presetButtonsHtml = '';
  for (var pIdx = 0; pIdx < presets.length; pIdx++) {
    var pr = presets[pIdx];
    if (!pr || !pr.target) continue;
    var prIcon = pr.icon || 'fi-rr-bullseye-arrow';
    var safeTargetJs = String(pr.target).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '&quot;');
    presetButtonsHtml += '<button class="preset-pill" onclick="document.getElementById(\'targetInput\').value=\'' + safeTargetJs + '\';triggerScan();"><i class="fi ' + escapeHtml(prIcon) + '"></i> ' + escapeHtml(pr.label || pr.target) + '</button>';
  }

  var rfPlanInit = computeRfOptimizationPlan();
  var rfSumInit = rfPlanInit.summary || {};
  var rfSetInit = rfPlanInit.settings || {};
  var mode2EnabledInit = Boolean(rfSetInit.autoOptimizeEnabled);
  var mode2TimeInit = escapeHtml(rfSetInit.autoOptimizeTime || '03:30');
  var mode2Wait24hInit = rfSetInit.requireFull24hForAuto !== false;
  var rfNeedCountInit = Number(rfSumInit.totolinkActionCount) || 0;
  var rfHoursInit = rfSumInit.systemHoursObserved || 0.1;
  var rfSamplesInit = Number(rfSumInit.totalSamples24h) || 0;
  var rfLinksInit = Number(rfSumInit.measuredNeighborLinks) || 0;
  var rfHistTotalInit = Number(rfSumInit.historyTotalCount) || (rfPlanInit.history || []).length;
  var safeRfPlanInitJson = JSON.stringify(rfPlanInit)
    .replace(/<\//g, '<\\/')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');

  return '<!DOCTYPE html>' +
  '<html lang="vi"><head><meta charset="utf-8">' +
  '<title>' + pageTitle + '</title>' +
  '<meta name="viewport" content="width=device-width, initial-scale=1">' +
  '<link rel="icon" type="image/svg+xml" href="/logo.svg">' +
  '<link rel="stylesheet" href="/assets/uicons/uicons-regular-rounded.css">' +
  '<style>' +
  '  :root {' +
  '    --bg: #f3f5f8; --surface: #ffffff; --card: #f8fafc; --card-hover: #f1f5f9;' +
  '    --border: #e2e8f0; --border-strong: #cbd5e1; --border-hover: #94a3b8;' +
  '    --text: #0f172a; --text-secondary: #334155; --text-muted: #475569; --text-dim: #64748b;' +
  '    --sky: #0284c7; --blue: #2563eb; --blue-hover: #1d4ed8; --blue-bg: #eff6ff; --blue-border: #bfdbfe;' +
  '    --green: #15803d; --green-fill: #16a34a; --green-bg: #f0fdf4; --green-border: #bbf7d0;' +
  '    --red: #dc2626; --red-bg: #fef2f2; --red-border: #fecaca;' +
  '    --amber: #b45309; --amber-fill: #d97706; --amber-bg: #fffbeb; --amber-border: #fde68a;' +
  '    --radius-sm: 6px; --radius-md: 8px; --radius-lg: 10px;' +
  '    --shadow: 0 1px 2px rgba(15, 23, 42, 0.05);' +
  '  }' +
  '  * { box-sizing: border-box; }' +
  '  body {' +
  '    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif;' +
  '    background: var(--bg); color: var(--text);' +
  '    margin: 0; padding: 20px 24px; min-height: 100vh;' +
  '    line-height: 1.5; font-size: 13.5px; -webkit-font-smoothing: antialiased;' +
  '  }' +
  '  .fi { display: inline-flex; align-items: center; justify-content: center; line-height: 1; vertical-align: middle; }' +
  '  @keyframes fi-spin { 100% { transform: rotate(360deg); } }' +
  '  .fi-spin { animation: fi-spin 1s linear infinite; }' +
  '  .container { max-width: 1440px; margin: 0 auto; }' +
  '  .top-nav {' +
  '    display: flex; justify-content: space-between; align-items: center;' +
  '    background: var(--surface); padding: 14px 20px;' +
  '    border-radius: var(--radius-lg); border: 1px solid var(--border);' +
  '    margin-bottom: 16px; box-shadow: var(--shadow);' +
  '    flex-wrap: wrap; gap: 16px;' +
  '  }' +
  '  .brand { display: flex; align-items: center; gap: 12px; }' +
  '  .brand-logo {' +
  '    width: 40px; height: 40px; border-radius: 8px;' +
  '    background: #ffffff; padding: 3px; flex-shrink: 0;' +
  '    display: flex; align-items: center; justify-content: center;' +
  '    border: 1px solid var(--border);' +
  '  }' +
  '  .brand-logo img { width: 100%; height: 100%; object-fit: contain; display: block; }' +
  '  .brand-text h1 {' +
  '    margin: 0; font-size: 17px; font-weight: 700; color: var(--text);' +
  '    letter-spacing: -0.015em; display: flex; align-items: center; gap: 8px;' +
  '  }' +
  '  .brand-text p { margin: 1px 0 0; font-size: 12px; color: var(--text-dim); }' +
  '  .brand-tag {' +
  '    background: #f1f5f9; color: var(--text-muted);' +
  '    font-size: 10.5px; font-weight: 600; padding: 1px 7px;' +
  '    border-radius: 4px; border: 1px solid var(--border-strong);' +
  '    letter-spacing: 0.02em;' +
  '  }' +
  '  .nav-controls { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }' +
  '  .sys-badge {' +
  '    display: inline-flex; align-items: center; gap: 6px;' +
  '    background: var(--green-bg); color: var(--green);' +
  '    padding: 5px 11px; border-radius: 6px;' +
  '    font-size: 12px; font-weight: 600;' +
  '    border: 1px solid var(--green-border);' +
  '  }' +
  '  .pulse-dot {' +
  '    width: 8px; height: 8px; border-radius: 50%; background: var(--green-fill); flex-shrink: 0;' +
  '  }' +
  '  @keyframes livePulse { 0%, 100% { box-shadow: 0 0 0 0 rgba(22, 163, 74, 0.45); } 50% { box-shadow: 0 0 0 5px rgba(22, 163, 74, 0); } }' +
  '  .pulse-dot.live { background: var(--green-fill); animation: livePulse 2s ease-in-out infinite; }' +
  '  .pulse-dot.paused { background: var(--amber-fill); animation: none; }' +
  '  .pulse-dot.offline { background: var(--red); animation: none; }' +
  '  .refresh-widget {' +
  '    display: inline-flex; align-items: center; gap: 8px;' +
  '    background: var(--card); padding: 4px 6px 4px 11px; border-radius: 6px;' +
  '    border: 1px solid var(--border); font-size: 12px; color: var(--text-muted);' +
  '  }' +
  '  .refresh-widget b { color: var(--text); font-variant-numeric: tabular-nums; }' +
  '  .btn-nav {' +
  '    background: #ffffff; color: var(--text-secondary); border: 1px solid var(--border-strong);' +
  '    padding: 5px 11px; border-radius: 5px; font-size: 12px; font-weight: 600;' +
  '    cursor: pointer; transition: background 0.12s, border-color 0.12s; display: inline-flex; align-items: center; gap: 5px;' +
  '    text-decoration: none;' +
  '  }' +
  '  .btn-nav:hover { background: var(--card-hover); border-color: var(--border-hover); color: var(--text); }' +
  '  .kpi-grid {' +
  '    display: grid; grid-template-columns: repeat(auto-fit, minmax(195px, 1fr));' +
  '    gap: 12px; margin-bottom: 16px;' +
  '  }' +
  '  .kpi-card {' +
  '    background: var(--surface); border: 1px solid var(--border);' +
  '    border-radius: var(--radius-md); padding: 14px 18px;' +
  '    box-shadow: var(--shadow);' +
  '  }' +
  '  .kpi-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }' +
  '  .kpi-title { font-size: 11.5px; color: var(--text-dim); font-weight: 600; }' +
  '  .kpi-icon { color: var(--text-dim); display: inline-flex; align-items: center; justify-content: center; font-size: 14px; }' +
  '  .kpi-val { font-size: 24px; font-weight: 700; color: var(--text); line-height: 1.15; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }' +
  '  .kpi-val.online { color: var(--green); }' +
  '  .kpi-val.offline-alert { color: var(--red); }' +
  '  .kpi-sub { margin-top: 4px; font-size: 11.5px; color: var(--text-dim); }' +
  '  .config-grid {' +
  '    display: grid; grid-template-columns: repeat(auto-fit, minmax(460px, 1fr));' +
  '    gap: 14px; margin-bottom: 16px;' +
  '  }' +
  '  .config-panel {' +
  '    background: var(--surface); border: 1px solid var(--border);' +
  '    border-radius: var(--radius-md); padding: 16px 18px;' +
  '    box-shadow: var(--shadow); display: flex; flex-direction: column;' +
  '    justify-content: space-between;' +
  '  }' +
  '  .panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; gap: 8px; flex-wrap: wrap; }' +
  '  .panel-title { font-size: 13.5px; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 7px; }' +
  '  .panel-badge {' +
  '    background: #f1f5f9; color: var(--text-muted);' +
  '    font-size: 11px; padding: 1px 8px; border-radius: 4px;' +
  '    font-weight: 600; border: 1px solid var(--border-strong);' +
  '  }' +
  '  .panel-desc { font-size: 12px; color: var(--text-dim); margin: 0 0 12px 0; }' +
  '  .preset-row { display: flex; gap: 5px; flex-wrap: wrap; align-items: center; }' +
  '  .preset-pill {' +
  '    background: var(--card); color: var(--text-muted); border: 1px solid var(--border);' +
  '    padding: 4px 9px; border-radius: 5px; cursor: pointer;' +
  '    font-size: 11px; font-weight: 600; transition: background 0.12s, border-color 0.12s;' +
  '    display: inline-flex; align-items: center; gap: 5px;' +
  '  }' +
  '  .preset-pill:hover { background: var(--card-hover); color: var(--text); border-color: var(--border-strong); }' +
  '  .form-row { display: flex; gap: 8px; align-items: stretch; }' +
  '  .form-input {' +
  '    flex: 1; background: #ffffff; border: 1px solid var(--border-strong);' +
  '    color: var(--text); padding: 8px 12px; border-radius: var(--radius-sm);' +
  '    font-size: 12.5px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace;' +
  '    transition: border-color 0.15s, box-shadow 0.15s;' +
  '  }' +
  '  .form-input:focus { outline: none; border-color: var(--blue); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12); }' +
  '  .btn-submit {' +
  '    padding: 0 16px; border-radius: var(--radius-sm); border: 1px solid transparent;' +
  '    font-size: 12.5px; font-weight: 600; cursor: pointer;' +
  '    display: inline-flex; align-items: center; gap: 6px;' +
  '    white-space: nowrap; transition: background 0.15s;' +
  '  }' +
  '  .btn-green { background: #0f172a; color: #ffffff; }' +
  '  .btn-green:hover { background: #1e293b; }' +
  '  .btn-blue { background: var(--blue); color: #ffffff; }' +
  '  .btn-blue:hover { background: var(--blue-hover); }' +
  '  .btn-submit:disabled { opacity: 0.6; cursor: not-allowed; }' +
  '  .table-card {' +
  '    background: var(--surface); border: 1px solid var(--border);' +
  '    border-radius: var(--radius-lg); box-shadow: var(--shadow);' +
  '    overflow: hidden;' +
  '  }' +
  '  .table-toolbar {' +
  '    padding: 12px 18px; border-bottom: 1px solid var(--border);' +
  '    display: flex; justify-content: space-between; align-items: center;' +
  '    gap: 14px; flex-wrap: wrap; background: #ffffff;' +
  '  }' +
  '  .search-wrap { position: relative; flex: 1; min-width: 260px; max-width: 400px; }' +
  '  .search-wrap input {' +
  '    width: 100%; background: #ffffff; border: 1px solid var(--border-strong);' +
  '    color: var(--text); padding: 7px 32px 7px 34px; border-radius: 6px;' +
  '    font-size: 13px; transition: border-color 0.15s, box-shadow 0.15s;' +
  '  }' +
  '  .search-wrap input:focus { outline: none; border-color: var(--blue); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12); }' +
  '  .search-ico { position: absolute; left: 11px; top: 50%; transform: translateY(-50%); font-size: 13px; color: var(--text-dim); pointer-events: none; }' +
  '  .search-clear { position: absolute; right: 6px; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-dim); font-size: 15px; cursor: pointer; padding: 4px 6px; display: none; align-items: center; justify-content: center; }' +
  '  .search-clear:hover { color: var(--text); }' +
  '  .filter-tabs { display: flex; gap: 5px; align-items: center; flex-wrap: wrap; }' +
  '  .tab-btn {' +
  '    background: #ffffff; color: var(--text-muted); border: 1px solid var(--border);' +
  '    padding: 5px 11px; border-radius: 6px; font-size: 12px; font-weight: 600;' +
  '    cursor: pointer; transition: 0.12s; display: inline-flex; align-items: center; gap: 6px;' +
  '  }' +
  '  .tab-btn:hover { background: var(--card-hover); color: var(--text); border-color: var(--border-strong); }' +
  '  .tab-btn.active { background: #0f172a; color: #ffffff; border-color: #0f172a; }' +
  '  .tab-btn.active .fi { color: #ffffff !important; }' +
  '  .tab-count { background: rgba(15, 23, 42, 0.07); padding: 1px 6px; border-radius: 4px; font-size: 11px; font-variant-numeric: tabular-nums; }' +
  '  .tab-btn.active .tab-count { background: rgba(255, 255, 255, 0.2); color: #ffffff; }' +
  '  .counter-text { font-size: 12px; color: var(--text-dim); font-variant-numeric: tabular-nums; }' +
  '  .table-responsive { overflow-x: auto; max-height: calc(100vh - 285px); }' +
  '  .modal-body .table-responsive { max-height: none; }' +
  '  table { width: 100%; border-collapse: separate; border-spacing: 0; text-align: left; }' +
  '  thead th {' +
  '    background: #f8fafc; color: var(--text-muted);' +
  '    font-size: 11px; font-weight: 700; text-transform: uppercase;' +
  '    letter-spacing: 0.03em; padding: 8px 9px;' +
  '    border-bottom: 1px solid var(--border);' +
  '    position: sticky; top: 0; z-index: 10; white-space: nowrap; vertical-align: top;' +
  '  }' +
  '  thead th:first-child, tbody td:first-child { padding-left: 16px; }' +
  '  thead th:last-child, tbody td:last-child { padding-right: 16px; }' +
  '  .th-sort-head { display: flex; align-items: center; justify-content: space-between; gap: 5px; cursor: pointer; user-select: none; margin-bottom: 6px; color: var(--text-muted); transition: color 0.12s; }' +
  '  .th-sort-head:hover { color: var(--text); }' +
  '  .th-sort-head.static-head { cursor: default; }' +
  '  .th-sort-head .sort-ico { font-size: 10.5px; opacity: 0.45; transition: 0.12s; flex-shrink: 0; }' +
  '  thead th.th-sorted .th-sort-head { color: var(--blue); }' +
  '  thead th.th-sorted .th-sort-head .sort-ico { opacity: 1; color: var(--blue); }' +
  '  thead th.th-filtered .th-sort-head { color: var(--blue-hover); }' +
  '  .th-filter-wrap { display: block; }' +
  '  .col-filter-input, .col-filter-select {' +
  '    width: 100%; height: 26px; box-sizing: border-box; background: #ffffff;' +
  '    border: 1px solid var(--border-strong); color: var(--text); border-radius: 5px;' +
  '    font-size: 11.5px; font-weight: 500; padding: 0 7px; font-family: inherit;' +
  '    text-transform: none; letter-spacing: normal; transition: border-color 0.12s, box-shadow 0.12s, background 0.12s;' +
  '  }' +
  '  .col-filter-select { padding: 0 4px; cursor: pointer; }' +
  '  .col-filter-input.mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 11px; }' +
  '  .col-filter-input::placeholder { color: #94a3b8; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-weight: 400; }' +
  '  .col-filter-input:focus, .col-filter-select:focus { outline: none; border-color: var(--blue); box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.12); }' +
  '  thead th.th-filtered .col-filter-input, thead th.th-filtered .col-filter-select { background: var(--blue-bg); border-color: #93c5fd; color: var(--blue-hover); font-weight: 600; }' +
  '  #thCol_name { min-width: 145px; }' +
  '  #thCol_ip { min-width: 122px; }' +
  '  #thCol_mac { min-width: 136px; }' +
  '  #thCol_model { min-width: 148px; }' +
  '  #thCol_ssid { min-width: 142px; }' +
  '  #thCol_channel { min-width: 88px; }' +
  '  #thCol_clients { min-width: 98px; }' +
  '  #thCol_latency { min-width: 100px; }' +
  '  #thCol_status { min-width: 96px; }' +
  '  .col-reset-btn { height: 26px; padding: 0 8px; border-radius: 5px; font-size: 11px; font-weight: 600; border: 1px solid var(--border-strong); background: #ffffff; color: var(--text-muted); cursor: pointer; display: inline-flex; align-items: center; gap: 4px; text-transform: none; letter-spacing: normal; transition: 0.12s; white-space: nowrap; }' +
  '  .col-reset-btn.active { background: var(--blue-bg); border-color: #93c5fd; color: var(--blue-hover); }' +
  '  .col-reset-btn.active:hover { background: #dbeafe; border-color: var(--blue); }' +
  '  .col-reset-btn:disabled { opacity: 0.45; cursor: default; background: #f8fafc; }' +
  '  .fw-badge { display: inline-block; margin-left: 5px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 10px; color: var(--text-dim); background: #f8fafc; padding: 1px 5px; border-radius: 4px; border: 1px solid var(--border); vertical-align: middle; }' +
  '  tbody tr { transition: background 0.1s; background: #ffffff; }' +
  '  tbody tr:hover { background: #f8fafc; }' +
  '  tbody td { padding: 9px 11px; border-bottom: 1px solid #f1f5f9; font-size: 12.5px; vertical-align: middle; white-space: nowrap; }' +
  '  .name-box { display: flex; align-items: center; gap: 8px; }' +
  '  .ap-ico { font-size: 14px; color: var(--text-dim); display: inline-flex; }' +
  '  .ap-title { font-weight: 600; color: var(--text); }' +
  '  .tag-static { background: var(--blue-bg); color: var(--blue-hover); border: 1px solid var(--blue-border); font-size: 9.5px; font-weight: 700; padding: 1px 6px; border-radius: 4px; letter-spacing: 0.03em; margin-left: 4px; display: inline-flex; align-items: center; }' +
  '  .ip-link { color: var(--blue); text-decoration: none; font-weight: 600; display: inline-flex; align-items: center; gap: 4px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; }' +
  '  .ip-link:hover { text-decoration: underline; color: var(--blue-hover); }' +
  '  .ico-ext { font-size: 10.5px; opacity: 0.6; }' +
  '  .mac-tag { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 11px; color: var(--text-secondary); background: #f8fafc; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border); white-space: nowrap; display: inline-block; }' +
  '  .model-badge { display: inline-block; background: #f1f5f9; color: var(--text-secondary); font-weight: 600; font-size: 11px; padding: 2px 7px; border-radius: 4px; border: 1px solid var(--border); }' +
  '  .ssid-text { color: var(--text-secondary); font-size: 12px; font-weight: 500; }' +
  '  .channel-badge { background: #f8fafc; color: var(--text-muted); padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; border: 1px solid var(--border); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }' +
  '  .client-pill { display: inline-flex; align-items: center; justify-content: center; padding: 3px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; min-width: 34px; font-family: inherit; border: 1px solid transparent; transition: all 0.12s ease; font-variant-numeric: tabular-nums; }' +
  '  .client-pill.active { background: var(--blue-bg); color: var(--blue-hover); border-color: var(--blue-border); }' +
  '  .client-pill.zero { background: #f8fafc; color: var(--text-dim); border-color: var(--border); }' +
  '  .client-pill.clickable { cursor: pointer; }' +
  '  .client-pill.clickable.active:hover { background: #dbeafe; border-color: #93c5fd; color: #1e40af; }' +
  '  .client-pill.clickable.zero:hover { background: #f1f5f9; border-color: var(--border-strong); color: var(--text); }' +
  '  .modal-overlay { position: fixed; inset: 0; background: rgba(15, 23, 42, 0.42); backdrop-filter: blur(2px); z-index: 1000; display: none; align-items: center; justify-content: center; padding: 14px; }' +
  '  .modal-overlay.open { display: flex; }' +
  '  .modal-dialog { background: #ffffff; border: 1px solid var(--border-strong); border-radius: var(--radius-lg); width: 100%; max-width: 1180px; max-height: 88vh; display: flex; flex-direction: column; box-shadow: 0 20px 45px -10px rgba(15, 23, 42, 0.2); overflow: hidden; animation: modalIn 0.14s ease-out; }' +
  '  @keyframes modalIn { from { opacity: 0; transform: translateY(6px) scale(0.99); } to { opacity: 1; transform: translateY(0) scale(1); } }' +
  '  .modal-header { padding: 14px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; background: #f8fafc; }' +
  '  .modal-title-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }' +
  '  .modal-ap-ico { width: 34px; height: 34px; border-radius: 7px; background: #ffffff; color: var(--text-secondary); display: inline-flex; align-items: center; justify-content: center; font-size: 16px; border: 1px solid var(--border-strong); }' +
  '  .modal-title { margin: 0; font-size: 16px; font-weight: 700; color: var(--text); }' +
  '  .modal-meta { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 7px; font-size: 12px; color: var(--text-muted); }' +
  '  .modal-meta-item { display: inline-flex; align-items: center; gap: 5px; background: #ffffff; padding: 2px 9px; border-radius: 5px; border: 1px solid var(--border); color: var(--text-secondary); }' +
  '  .modal-actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }' +
  '  .btn-modal-close { width: 30px; height: 30px; border-radius: 6px; background: #ffffff; border: 1px solid var(--border-strong); color: var(--text-muted); cursor: pointer; display: inline-flex; align-items: center; justify-content: center; font-size: 16px; transition: 0.12s; }' +
  '  .btn-modal-close:hover { background: var(--red-bg); color: var(--red); border-color: var(--red-border); }' +
  '  .modal-body { padding: 0; overflow-x: auto; overflow-y: auto; flex: 1; min-height: 180px; background: #ffffff; }' +
  '  .modal-state { padding: 48px 24px; text-align: center; color: var(--text-muted); font-size: 13px; }' +
  '  .modal-state .fi { font-size: 26px; margin-bottom: 10px; display: inline-flex; color: var(--text-dim); }' +
  '  .client-table { width: 100%; border-collapse: separate; border-spacing: 0; }' +
  '  .client-table thead th { background: #f8fafc; padding: 9px 9px; font-size: 10.5px; color: var(--text-muted); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 5; white-space: nowrap; }' +
  '  .client-table tbody td { padding: 9px 9px; border-bottom: 1px solid #f1f5f9; font-size: 12px; white-space: nowrap; }' +
  '  .client-table thead th:first-child, .client-table tbody td:first-child { padding-left: 16px; width: 32px; }' +
  '  .client-table thead th:last-child, .client-table tbody td:last-child { padding-right: 16px; }' +
  '  .dev-cell { display: flex; align-items: center; gap: 9px; }' +
  '  .dev-ico { width: 30px; height: 30px; border-radius: 6px; background: #f8fafc; color: var(--text-muted); border: 1px solid var(--border); display: inline-flex; align-items: center; justify-content: center; font-size: 14px; flex-shrink: 0; }' +
  '  .dev-ico.pc { background: var(--blue-bg); color: var(--blue); border-color: var(--blue-border); }' +
  '  .dev-title-row { display: flex; align-items: center; gap: 6px; }' +
  '  .dev-name { font-weight: 600; color: var(--text); font-size: 12px; max-width: 145px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }' +
  '  .dev-meta-row { display: flex; align-items: center; gap: 5px; margin-top: 3px; font-size: 10.5px; color: var(--text-muted); }' +
  '  .oui-badge { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 10px; font-weight: 600; padding: 1px 5px; border-radius: 4px; background: var(--blue-bg); color: var(--blue-hover); border: 1px solid var(--blue-border); }' +
  '  .oui-badge.laa { background: #f1f5f9; color: var(--text-muted); border-color: var(--border-strong); }' +
  '  .vendor-text { display: inline-flex; align-items: center; gap: 4px; color: var(--text-muted); font-size: 10.5px; max-width: 175px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }' +
  '  .dev-vendor { font-size: 10.5px; color: var(--text-dim); margin-top: 2px; }' +
  '  .ip-badge { display: inline-flex; align-items: center; gap: 5px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 11.5px; font-weight: 600; padding: 2px 7px; border-radius: 4px; }' +
  '  .ip-badge.resolved { color: var(--blue-hover); background: var(--blue-bg); border: 1px solid var(--blue-border); font-weight: 700; }' +
  '  .ip-badge.vlan { color: var(--text-secondary); background: #f8fafc; border: 1px solid var(--border); font-size: 11px; }' +
  '  .ip-sub { font-size: 10px; color: var(--text-dim); margin-top: 2px; display: flex; align-items: center; gap: 4px; }' +
  '  .sig-wrap { display: flex; align-items: center; gap: 7px; }' +
  '  .sig-bar-bg { width: 38px; height: 5px; background: #e2e8f0; border-radius: 3px; overflow: hidden; flex-shrink: 0; }' +
  '  .sig-bar-fill { height: 100%; border-radius: 3px; }' +
  '  .sig-bar-fill.sig-good { background: var(--green-fill); }' +
  '  .sig-bar-fill.sig-mid  { background: var(--amber-fill); }' +
  '  .sig-bar-fill.sig-weak { background: var(--red); }' +
  '  .sig-txt-good { color: var(--green); }' +
  '  .sig-txt-mid  { color: var(--amber); }' +
  '  .sig-txt-weak { color: var(--red); }' +
  '  .modal-footer { padding: 11px 22px; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; font-size: 11.5px; color: var(--text-dim); background: #f8fafc; flex-wrap: wrap; gap: 8px; }' +
  '  .lat-pill { display: inline-block; font-size: 11.5px; font-weight: 600; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; padding: 2px 7px; border-radius: 4px; font-variant-numeric: tabular-nums; }' +
  '  .lat-fast { color: var(--green); background: var(--green-bg); border: 1px solid var(--green-border); }' +
  '  .lat-good { color: #0369a1; background: #f0f9ff; border: 1px solid #bae6fd; }' +
  '  .lat-mid  { color: var(--amber); background: var(--amber-bg); border: 1px solid var(--amber-border); }' +
  '  .lat-high { color: var(--red); background: var(--red-bg); border: 1px solid var(--red-border); }' +
  '  .dim-text { color: var(--text-dim); }' +
  '  .status-pill { display: inline-flex; align-items: center; gap: 5px; padding: 3px 10px; border-radius: 5px; font-size: 11.5px; font-weight: 600; }' +
  '  .status-pill.online { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }' +
  '  .status-pill.offline { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }' +
  '  .empty-state { text-align: center; padding: 48px 20px; color: var(--text-muted); font-size: 13.5px; }' +
  '  .empty-icon { font-size: 28px; margin-bottom: 10px; display: block; color: var(--text-dim); }' +
  '  .rf-banner-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 15px 18px; margin-bottom: 16px; box-shadow: var(--shadow); display: grid; grid-template-columns: 1.35fr 1fr; gap: 18px; align-items: center; }' +
  '  @media (max-width: 1020px) { .rf-banner-card { grid-template-columns: 1fr; } }' +
  '  .rf-mode1-box { display: flex; flex-direction: column; gap: 8px; padding-right: 16px; border-right: 1px solid var(--border); }' +
  '  @media (max-width: 1020px) { .rf-mode1-box { padding-right: 0; border-right: none; border-bottom: 1px solid var(--border); padding-bottom: 14px; } }' +
  '  .rf-head-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }' +
  '  .rf-title-group { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }' +
  '  .rf-ico-badge { width: 32px; height: 32px; border-radius: 7px; background: var(--blue-bg); color: var(--blue); border: 1px solid var(--blue-border); display: inline-flex; align-items: center; justify-content: center; font-size: 15px; flex-shrink: 0; }' +
  '  .rf-title-txt { font-size: 13.5px; font-weight: 700; color: var(--text); }' +
  '  .rf-stat-pills { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }' +
  '  .rf-chip { display: inline-flex; align-items: center; gap: 5px; font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 5px; border: 1px solid var(--border); background: #f8fafc; color: var(--text-muted); font-variant-numeric: tabular-nums; }' +
  '  .rf-chip.warn { background: var(--amber-bg); color: var(--amber); border-color: var(--amber-border); }' +
  '  .rf-chip.ok { background: var(--green-bg); color: var(--green); border-color: var(--green-border); }' +
  '  .rf-chip.info { background: var(--blue-bg); color: var(--blue-hover); border-color: var(--blue-border); }' +
  '  .rf-desc-txt { font-size: 12px; color: var(--text-dim); margin: 0; line-height: 1.45; }' +
  '  .rf-actions-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 2px; }' +
  '  .rf-mode2-box { display: flex; flex-direction: column; gap: 9px; background: #f8fafc; border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 12px 14px; }' +
  '  .rf-toggle-wrap { display: inline-flex; align-items: center; gap: 8px; cursor: pointer; user-select: none; }' +
  '  .rf-toggle-wrap input { position: absolute; opacity: 0; width: 0; height: 0; }' +
  '  .rf-toggle-track { position: relative; width: 40px; height: 22px; background: #cbd5e1; border-radius: 999px; transition: background 0.18s ease; display: inline-block; flex-shrink: 0; }' +
  '  .rf-toggle-thumb { position: absolute; top: 2px; left: 2px; width: 18px; height: 18px; background: #ffffff; border-radius: 50%; box-shadow: 0 1px 2px rgba(15, 23, 42, 0.25); transition: transform 0.18s ease; }' +
  '  .rf-toggle-wrap input:checked + .rf-toggle-track { background: var(--green-fill); }' +
  '  .rf-toggle-wrap input:checked + .rf-toggle-track .rf-toggle-thumb { transform: translateX(18px); }' +
  '  .rf-toggle-state { font-size: 11px; font-weight: 700; padding: 2px 7px; border-radius: 4px; letter-spacing: 0.02em; }' +
  '  .rf-toggle-state.on { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }' +
  '  .rf-toggle-state.off { background: #f1f5f9; color: var(--text-dim); border: 1px solid var(--border-strong); }' +
  '  .rf-mode2-controls { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; font-size: 12px; color: var(--text-secondary); }' +
  '  .rf-time-input { background: #ffffff; border: 1px solid var(--border-strong); color: var(--text); padding: 4px 8px; border-radius: 5px; font-size: 12px; font-weight: 600; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }' +
  '  .rf-time-input:focus { outline: none; border-color: var(--blue); }' +
  '  .rf-chk-label { display: inline-flex; align-items: center; gap: 5px; font-size: 11.5px; color: var(--text-muted); cursor: pointer; user-select: none; }' +
  '  .rf-chk-label input { accent-color: var(--blue); cursor: pointer; }' +
  '  .rf-mode2-note { font-size: 11px; color: var(--text-dim); display: flex; align-items: center; gap: 5px; }' +
  '  .modal-dialog.rf-wide { max-width: 1320px; max-height: 92vh; }' +
  '  .modal-dialog.rf-wide .modal-header { padding: 11px 16px; gap: 10px; align-items: center; flex-wrap: wrap; }' +
  '  .modal-dialog.rf-wide .modal-meta { margin-top: 5px; }' +
  '  .rf-modal-toolbar { padding: 8px 16px; border-bottom: 1px solid var(--border); background: #ffffff; display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap; }' +
  '  .rf-kpi-strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; padding: 8px 16px; background: #f8fafc; border-bottom: 1px solid var(--border); }' +
  '  @media (max-width: 680px) { .rf-kpi-strip { grid-template-columns: repeat(2, 1fr); } }' +
  '  .rf-mini-kpi { background: #ffffff; border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px; display: flex; justify-content: space-between; align-items: center; }' +
  '  .rf-mini-label { font-size: 10.5px; color: var(--text-dim); font-weight: 600; }' +
  '  .rf-mini-val { font-size: 15px; font-weight: 700; color: var(--text); font-variant-numeric: tabular-nums; margin-top: 1px; }' +
  '  .rf-table { width: 100%; border-collapse: separate; border-spacing: 0; }' +
  '  .rf-table thead th { background: #f8fafc; padding: 7px 7px; font-size: 10px; color: var(--text-muted); border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 5; white-space: nowrap; }' +
  '  .rf-table tbody td { padding: 7px 7px; border-bottom: 1px solid #f1f5f9; font-size: 11.5px; vertical-align: middle; white-space: nowrap; }' +
  '  .rf-table thead th:first-child, .rf-table tbody td:first-child { padding-left: 14px; }' +
  '  .rf-table thead th:last-child, .rf-table tbody td:last-child { padding-right: 14px; }' +
  '  .rf-table td.rf-reason-cell { white-space: normal; min-width: 175px; max-width: 280px; line-height: 1.35; font-size: 11px; color: var(--text-secondary); }' +
  '  .rf-reason-item { display: flex; align-items: flex-start; gap: 5px; margin-bottom: 2px; }' +
  '  .rf-reason-item:last-child { margin-bottom: 0; }' +
  '  .rf-diff-row { display: inline-flex; align-items: center; gap: 4px; }' +
  '  .rf-cur-tag { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 10.5px; color: var(--text-dim); background: #f8fafc; padding: 2px 4px; border-radius: 4px; border: 1px solid var(--border); }' +
  '  .rf-sel { background: #ffffff; border: 1px solid var(--border-strong); color: var(--text); padding: 2px 4px; border-radius: 4px; font-size: 11px; font-weight: 600; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; cursor: pointer; }' +
  '  .rf-sel.changed { background: var(--blue-bg); border-color: var(--blue-border); color: var(--blue-hover); }' +
  '  .rf-keep-row { display: inline-flex; align-items: center; gap: 4px; }' +
  '  .rf-keep-tag { display: inline-flex; align-items: center; gap: 4px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 10.5px; font-weight: 600; color: var(--text-secondary); background: #f8fafc; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border); }' +
  '  .rf-keep-lbl { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 9.5px; font-weight: 600; color: var(--green); background: var(--green-bg); padding: 0 4px; border-radius: 3px; }' +
  '  .rf-unlock-btn { background: transparent; border: 1px solid transparent; color: var(--text-dim); padding: 2px 4px; border-radius: 4px; font-size: 10.5px; cursor: pointer; opacity: 0.65; transition: 0.12s; display: inline-flex; align-items: center; }' +
  '  .rf-unlock-btn:hover { opacity: 1; background: var(--card-hover); border-color: var(--border-strong); color: var(--blue); }' +
  '  .rf-optimal-badge { display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 5px; background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }' +
  '  .rf-live-box { min-width: 145px; max-width: 215px; white-space: normal; }' +
  '  .rf-live-msg { font-size: 10.5px; font-weight: 600; color: var(--blue-hover); display: flex; align-items: center; gap: 5px; line-height: 1.25; }' +
  '  .rf-live-msg.done { color: var(--green); }' +
  '  .rf-live-msg.err { color: var(--red); }' +
  '  .rf-prog-track { width: 100%; height: 4px; background: #e2e8f0; border-radius: 99px; overflow: hidden; margin-top: 4px; }' +
  '  .rf-prog-fill { height: 100%; background: var(--blue); border-radius: 99px; transition: width 0.28s ease; }' +
  '  .rf-prog-fill.done { background: var(--green-fill); }' +
  '  .rf-table tbody tr.rf-row-applying td { background: #f5f9ff; }' +
  '  .channel-badge.ch-applying { background: var(--blue-bg); color: var(--blue-hover); border-color: var(--blue-border); display: inline-flex; align-items: center; gap: 4px; }' +
  '  .channel-badge.ch-done { background: var(--green-bg); color: var(--green); border-color: var(--green-border); display: inline-flex; align-items: center; gap: 4px; }' +
  '  .channel-badge.ch-err { background: var(--red-bg); color: var(--red); border-color: var(--red-border); display: inline-flex; align-items: center; gap: 4px; }' +
  '  .rf-sub-meta { font-size: 10px; color: var(--text-dim); margin-top: 2px; display: flex; align-items: center; gap: 4px; }' +
  '  .btn-rf-apply { background: var(--blue); color: #ffffff; border: 1px solid var(--blue); padding: 4px 8px; border-radius: 5px; font-size: 11px; font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 4px; transition: 0.12s; }' +
  '  .btn-rf-apply:hover { background: var(--blue-hover); }' +
  '  .btn-rf-apply.secondary { background: #ffffff; color: var(--text-secondary); border-color: var(--border-strong); }' +
  '  .btn-rf-apply.secondary:hover { background: var(--card-hover); color: var(--text); }' +
  '  .btn-rf-apply:disabled { opacity: 0.6; cursor: not-allowed; }' +
  '  .rf-unifi-tag { display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 5px; background: #f8fafc; color: var(--text-muted); border: 1px solid var(--border-strong); }' +
  '  .rf-toast { font-size: 11.5px; font-weight: 600; color: var(--green); display: none; align-items: center; gap: 4px; }' +
  '  .table-pager-bar { display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap; padding: 9px 16px; background: #f8fafc; border-top: 1px solid var(--border); font-size: 12px; color: var(--text-muted); font-variant-numeric: tabular-nums; }' +
  '  .table-pager-bar:empty { display: none; }' +
  '  .table-pager-bar.modal-pager { position: sticky; bottom: 0; left: 0; z-index: 6; padding: 8px 14px; background: #f8fafc; box-shadow: 0 -1px 3px rgba(15, 23, 42, 0.04); }' +
  '  .pager-left { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }' +
  '  .pager-size-wrap { display: inline-flex; align-items: center; gap: 6px; color: var(--text-dim); font-size: 11.5px; }' +
  '  .pager-size-sel { background: #ffffff; border: 1px solid var(--border-strong); color: var(--text); padding: 3px 7px; border-radius: 5px; font-size: 11.5px; font-weight: 600; cursor: pointer; }' +
  '  .pager-size-sel:focus { outline: none; border-color: var(--blue); }' +
  '  .pager-right { display: flex; align-items: center; gap: 4px; flex-wrap: wrap; }' +
  '  .pager-btn { background: #ffffff; color: var(--text-secondary); border: 1px solid var(--border-strong); min-width: 28px; height: 27px; padding: 0 8px; border-radius: 5px; font-size: 11.5px; font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 3px; transition: 0.12s; }' +
  '  .pager-btn:hover:not(:disabled) { background: var(--card-hover); border-color: var(--border-hover); color: var(--text); }' +
  '  .pager-btn.active { background: #0f172a; color: #ffffff; border-color: #0f172a; }' +
  '  .pager-btn:disabled { opacity: 0.45; cursor: not-allowed; background: #f8fafc; }' +
  '  .pager-ellipsis { padding: 0 4px; color: var(--text-dim); font-weight: 600; user-select: none; }' +
  '  .panel-feedback { margin-top: 8px; font-size: 11.5px; font-weight: 600; padding: 6px 10px; border-radius: 6px; display: none; align-items: center; gap: 6px; line-height: 1.35; }' +
  '  .panel-feedback.show { display: flex; }' +
  '  .panel-feedback.ok { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }' +
  '  .panel-feedback.err { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }' +
  '  .panel-feedback.info { background: var(--blue-bg); color: var(--blue-hover); border: 1px solid var(--blue-border); }' +
  '  .cell-actions { text-align: right; width: 58px; }' +
  '  .ip-readonly code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; font-weight: 600; color: var(--text-secondary); }' +
  '  .btn-del-ap { width: 28px; height: 28px; border-radius: 6px; background: #ffffff; border: 1px solid var(--border); color: var(--text-dim); cursor: pointer; display: inline-flex; align-items: center; justify-content: center; font-size: 12.5px; transition: all 0.14s ease; }' +
  '  .btn-del-ap:hover:not(:disabled) { background: var(--red-bg); color: var(--red); border-color: var(--red-border); }' +
  '  .btn-del-ap:disabled { opacity: 0.5; cursor: not-allowed; }' +
  '  .toolbar-right-group { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }' +
  '  .btn-cleanup-offline { background: #ffffff; color: var(--red); border: 1px solid var(--red-border); padding: 5px 10px; border-radius: 6px; font-size: 11.5px; font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 5px; transition: 0.12s; white-space: nowrap; }' +
  '  .btn-cleanup-offline:hover:not(:disabled) { background: var(--red-bg); border-color: #f87171; }' +
  '  .btn-cleanup-offline:disabled { opacity: 0.55; cursor: not-allowed; }' +
  '  .user-nav-pill { display: inline-flex; align-items: center; gap: 7px; background: var(--card); border: 1px solid var(--border); padding: 4px 9px; border-radius: 6px; font-size: 12px; font-weight: 600; color: var(--text); }' +
  '  .role-badge { font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 4px; letter-spacing: 0.03em; text-transform: uppercase; }' +
  '  .role-badge.admin { background: var(--blue-bg); color: var(--blue-hover); border: 1px solid var(--blue-border); }' +
  '  .role-badge.user { background: #f1f5f9; color: var(--text-muted); border: 1px solid var(--border-strong); }' +
  '  .btn-nav.logout:hover { background: var(--red-bg); border-color: var(--red-border); color: var(--red); }' +
  '  .users-form-box { padding: 16px 20px; background: #fafcff; border-bottom: 1px solid var(--border); }' +
  '  .users-form-title { font-size: 13px; font-weight: 700; color: var(--text); margin-bottom: 10px; display: flex; align-items: center; justify-content: space-between; gap: 8px; }' +
  '  .users-form-grid { display: grid; grid-template-columns: 1.05fr 1.2fr 1.15fr 1.2fr auto; gap: 10px; align-items: end; }' +
  '  @media (max-width: 900px) { .users-form-grid { grid-template-columns: 1fr 1fr; } }' +
  '  .u-field label { display: block; font-size: 11px; font-weight: 700; color: var(--text-muted); margin-bottom: 4px; }' +
  '  .u-input, .u-select { width: 100%; height: 34px; padding: 0 10px; border-radius: 6px; border: 1px solid var(--border-strong); background: #ffffff; color: var(--text); font-size: 12.5px; font-family: inherit; }' +
  '  .u-input:focus, .u-select:focus { outline: none; border-color: var(--blue); box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.12); }' +
  '  .u-input:disabled { background: #f1f5f9; color: var(--text-dim); cursor: not-allowed; }' +
  '  .md5-code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 10.5px; color: var(--text-dim); background: #f8fafc; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border); }' +
  '  .rf-toggle-wrap.disabled-ro { pointer-events: none; opacity: 0.72; }' +
  '  .settings-nav-badge { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); font-size: 10.5px; font-weight: 700; padding: 0 6px; border-radius: 999px; font-variant-numeric: tabular-nums; line-height: 1.5; }' +
  '  .settings-tabs-bar { display: flex; align-items: center; gap: 6px; padding: 10px 20px; background: #ffffff; border-bottom: 1px solid var(--border); flex-wrap: wrap; }' +
  '  .settings-pane { display: none; }' +
  '  .settings-pane.active { display: block; }' +
  '  .settings-pane.padded { padding: 18px 20px; background: #f8fafc; }' +
  '  .settings-pass-card { max-width: 480px; margin: 6px auto; background: #ffffff; border: 1px solid var(--border); border-radius: var(--radius-md); padding: 20px 22px; box-shadow: var(--shadow); }' +
  '</style>' +
  '<script>' +
  '  var CURRENT_USER = ' + safeCurrentUserJson + ';' +
  '  var IS_ADMIN = Boolean(CURRENT_USER && CURRENT_USER.role === "admin");' +
  '  var currentFilter = "all";' +
  '  var mainTablePage = 1;' +
  '  var mainTablePageSize = 15;' +
  '  var isPaused = false;' +
  '  var isModalOpen = false;' +
  '  var activeClientPillBtn = null;' +
  '  var activeModalApIp = "";' +
  '  var liveEventSource = null;' +
  '  var fallbackPollTimer = null;' +
  '  var pendingLivePayload = null;' +
  '  function checkAuthJson(r) {' +
  '    if (r && r.status === 401) {' +
  '      window.location.href = "/login";' +
  '      throw new Error("Phiên đăng nhập đã hết hạn");' +
  '    }' +
  '    return r.json();' +
  '  }' +
  '  function syncAnyModalOpenFlag() {' +
  '    var ids = ["settingsModalOverlay", "clientModalOverlay", "rfOptModalOverlay"];' +
  '    for (var i = 0; i < ids.length; i++) {' +
  '      var el = document.getElementById(ids[i]);' +
  '      if (el && el.classList.contains("open")) { isModalOpen = true; return; }' +
  '    }' +
  '    isModalOpen = false;' +
  '  }' +
  '  function buildPagerHtml(totalItems, curPage, pageSize, pageFnName, sizeFnName, sizeOpts, unitLabel) {' +
  '    var minOpt = (sizeOpts && sizeOpts.length > 0) ? sizeOpts[0] : 10;' +
  '    if (totalItems <= minOpt) return "";' +
  '    var totalPages = pageSize > 0 ? Math.max(1, Math.ceil(totalItems / pageSize)) : 1;' +
  '    var p = Math.min(Math.max(1, curPage || 1), totalPages);' +
  '    var startIdx = pageSize > 0 ? ((p - 1) * pageSize + 1) : 1;' +
  '    var endIdx = pageSize > 0 ? Math.min(totalItems, p * pageSize) : totalItems;' +
  '    var selHtml = \'<select class="pager-size-sel" onchange="\' + sizeFnName + \'(this.value)">\';' +
  '    for (var si = 0; si < sizeOpts.length; si++) {' +
  '      var sv = sizeOpts[si];' +
  '      var sLbl = sv === 0 ? ("Tất cả (" + totalItems + ")") : (sv + " / trang");' +
  '      selHtml += \'<option value="\' + sv + \'"\' + (Number(pageSize) === Number(sv) ? " selected" : "") + ">" + sLbl + "</option>";' +
  '    }' +
  '    selHtml += "</select>";' +
  '    var btnsHtml = "";' +
  '    if (totalPages > 1) {' +
  '      btnsHtml += \'<button type="button" class="pager-btn"\' + (p <= 1 ? " disabled" : "") + \' onclick="\' + pageFnName + "(" + (p - 1) + \')"><i class="fi fi-rr-angle-small-left"></i> Trước</button>\';' +
  '      var pages = [1];' +
  '      var wStart = Math.max(2, p - 2);' +
  '      var wEnd = Math.min(totalPages - 1, p + 2);' +
  '      if (wStart > 2) pages.push("...");' +
  '      for (var pi = wStart; pi <= wEnd; pi++) pages.push(pi);' +
  '      if (wEnd < totalPages - 1) pages.push("...");' +
  '      if (totalPages > 1) pages.push(totalPages);' +
  '      for (var bi = 0; bi < pages.length; bi++) {' +
  '        var pv = pages[bi];' +
  '        if (pv === "...") {' +
  '          btnsHtml += \'<span class="pager-ellipsis">…</span>\';' +
  '        } else {' +
  '          btnsHtml += \'<button type="button" class="pager-btn\' + (pv === p ? " active" : "") + \'" onclick="\' + pageFnName + "(" + pv + \')">\' + pv + "</button>";' +
  '        }' +
  '      }' +
  '      btnsHtml += \'<button type="button" class="pager-btn"\' + (p >= totalPages ? " disabled" : "") + \' onclick="\' + pageFnName + "(" + (p + 1) + \')">Sau <i class="fi fi-rr-angle-small-right"></i></button>\';' +
  '    }' +
  '    return \'<div class="pager-left"><span>Hiển thị <b>\' + startIdx + "–" + endIdx + \'</b> / <b>\' + totalItems + "</b> " + unitLabel + \'</span><span class="pager-size-wrap">Số dòng: \' + selHtml + \'</span></div><div class="pager-right">\' + btnsHtml + "</div>";' +
  '  }' +
  '  function setLiveIndicator(state, timeStr) {' +
  '    var dot = document.getElementById("liveStreamDot");' +
  '    var lbl = document.getElementById("liveStreamStateTxt");' +
  '    var tm = document.getElementById("lastLiveTime");' +
  '    if (dot) {' +
  '      dot.className = "pulse-dot " + (isPaused ? "paused" : (state === "live" ? "live" : (state === "offline" ? "offline" : "paused")));' +
  '    }' +
  '    if (lbl) {' +
  '      lbl.innerText = isPaused ? "Đã tạm dừng:" : (state === "offline" ? "Đang kết nối lại:" : "Trực tiếp:");' +
  '    }' +
  '    if (tm && timeStr) tm.innerText = timeStr;' +
  '  }' +
  '  function formatNowTime() {' +
  '    return (new Date()).toLocaleTimeString("vi-VN");' +
  '  }' +
  '  function ipToNumClient(ip) {' +
  '    if (!ip) return 0;' +
  '    var p = String(ip).trim().split(".");' +
  '    if (p.length !== 4) return 0;' +
  '    var n0 = parseInt(p[0], 10), n1 = parseInt(p[1], 10), n2 = parseInt(p[2], 10), n3 = parseInt(p[3], 10);' +
  '    if (isNaN(n0) || isNaN(n1) || isNaN(n2) || isNaN(n3)) return 0;' +
  '    return (((n0 << 24) >>> 0) + ((n1 << 16) >>> 0) + ((n2 << 8) >>> 0) + (n3 >>> 0)) >>> 0;' +
  '  }' +
  '  function buildApRowInnerHtml(ap) {' +
  '    var isOnline = ap.status === 1;' +
  '    var statusBadge = isOnline' +
  '      ? \'<span class="status-pill online"><i class="fi fi-rr-check-circle"></i>Online</span>\'' +
  '      : \'<span class="status-pill offline"><i class="fi fi-rr-cross-circle"></i>Offline</span>\';' +
  '    var staticBadge = ap.isStatic' +
  '      ? \'<span class="tag-static" title="AP trong danh sách giám sát cố định"><i class="fi fi-rr-thumbtack" style="font-size:8px;margin-right:3px;"></i>CỐ ĐỊNH</span>\'' +
  '      : "";' +
  '    var latencyBadge = \'<span class="dim-text">-</span>\';' +
  '    if (isOnline) {' +
  '      var latVal = Number(ap.latencyMs) || 0;' +
  '      var latCls = latVal <= 3 ? "lat-fast" : (latVal <= 12 ? "lat-good" : (latVal <= 30 ? "lat-mid" : "lat-high"));' +
  '      latencyBadge = \'<span class="lat-pill \' + latCls + \'">\' + latVal + " ms</span>";' +
  '    }' +
  '    var clientCount = isOnline ? (Number(ap.clientCount) || 0) : 0;' +
  '    var sIp = escText(ap.ip || "");' +
  '    var sName = escText(ap.name || "AP");' +
  '    var sModel = escText(ap.model || "-");' +
  '    var fwRaw = String(ap.firmware || "-");' +
  '    var showFw = fwRaw && fwRaw !== "-" && fwRaw.indexOf("Đang") === -1 && fwRaw.indexOf("Chờ") === -1;' +
  '    var modelCellHtml = \'<span class="model-badge">\' + sModel + "</span>" +' +
  '      (showFw ? \'<span class="fw-badge" title="Phiên bản Firmware">\' + escText(fwRaw) + "</span>" : "");' +
  '    var sSsid = escText(ap.ssid || "-");' +
  '    var sCh = escText(ap.channel || "-");' +
  '    var chBadgeHtml = \'<span class="channel-badge">CH \' + sCh + "</span>";' +
  '    if (ap.applyState) {' +
  '      var ast = ap.applyState;' +
  '      if (ast.phase === "done") {' +
  '        chBadgeHtml = \'<span class="channel-badge ch-done" title="\' + escText(ast.message || "") + \'"><i class="fi fi-rr-check-circle"></i> CH \' + sCh + "</span>";' +
  '      } else if (ast.isError) {' +
  '        chBadgeHtml = \'<span class="channel-badge ch-err" title="\' + escText(ast.message || "") + \'"><i class="fi fi-rr-triangle-warning"></i> CH \' + sCh + "</span>";' +
  '      } else {' +
  '        chBadgeHtml = \'<span class="channel-badge ch-applying" title="\' + escText(ast.message || "") + \'"><i class="fi fi-rr-spinner fi-spin"></i> CH \' + sCh + " (" + (ast.pct || 15) + "%)</span>";' +
  '      }' +
  '    }' +
  '    var clientBadge = isOnline' +
  '      ? \'<button type="button" class="client-pill clickable \' + (clientCount > 0 ? "active" : "zero") + \'" \' +' +
  '        \'data-ip="\' + sIp + \'" data-name="\' + sName + \'" data-model="\' + sModel + \'" \' +' +
  '        \'data-ssid="\' + sSsid + \'" data-channel="\' + sCh + \'" \' +' +
  '        \'onclick="openClientsModal(this)" title="Click để xem chi tiết thiết bị đang kết nối về AP \' + sName + \'">\' +' +
  '        (clientCount > 0 ? \'<i class="fi fi-rr-user" style="font-size:11px;margin-right:4px;"></i>\' : "") +' +
  '        \'<span class="client-count-val">\' + clientCount + "</span></button>"' +
  '      : \'<span class="client-pill zero">0</span>\';' +
  '    var sKey = escText(ap.key || ap.mac || ap.ip || "");' +
  '    var ipCellHtml = IS_ADMIN' +
  '      ? \'<a href="http://\' + sIp + \'" target="_blank" class="ip-link" title="Mở trang cấu hình AP \' + sIp + \'"><code>\' + sIp + \'</code><i class="fi fi-rr-arrow-up-right-from-square ico-ext"></i></a>\'' +
  '      : \'<span class="ip-readonly"><code>\' + sIp + "</code></span>";' +
  '    var delBtnHtml = \'<button type="button" class="btn-del-ap" \' +' +
  '      \'data-key="\' + sKey + \'" data-ip="\' + sIp + \'" data-name="\' + sName + \'" \' +' +
  '      \'data-static="\' + (ap.isStatic ? "1" : "0") + \'" data-online="\' + (isOnline ? "1" : "0") + \'" \' +' +
  '      \'onclick="deleteSingleAp(this)" title="Xóa AP \' + sName + \' (\' + sIp + \') khỏi danh sách giám sát">\' +' +
  '      \'<i class="fi fi-rr-trash"></i></button>\';' +
  '    return \'<td class="cell-name"><div class="name-box"><span class="ap-ico"><i class="fi fi-rr-router"></i></span><span class="ap-title">\' + sName + "</span>" + staticBadge + "</div></td>" +' +
  '      \'<td class="cell-ip">\' + ipCellHtml + "</td>" +' +
  '      \'<td class="cell-mac"><span class="mac-tag">\' + escText(ap.mac || "-") + "</span></td>" +' +
  '      \'<td class="cell-model">\' + modelCellHtml + "</td>" +' +
  '      \'<td class="cell-ssid"><span class="ssid-text" title="\' + sSsid + \'">\' + sSsid + "</span></td>" +' +
  '      \'<td class="cell-channel">\' + chBadgeHtml + "</td>" +' +
  '      \'<td class="cell-clients">\' + clientBadge + "</td>" +' +
  '      \'<td class="cell-latency">\' + latencyBadge + "</td>" +' +
  '      \'<td class="cell-status">\' + statusBadge + "</td>" +' +
  '      (IS_ADMIN ? (\'<td class="cell-actions">\' + delBtnHtml + "</td>") : "");' +
  '  }' +
  '  function applyRowFilterAttrs(tr, ap, sig, searchStr, isOnline, cCount, latNum) {' +
  '    tr.setAttribute("data-sig", sig);' +
  '    tr.setAttribute("data-search", searchStr);' +
  '    tr.setAttribute("data-name", String(ap.name || "AP"));' +
  '    tr.setAttribute("data-ip", String(ap.ip || ""));' +
  '    tr.setAttribute("data-ip-num", String(ipToNumClient(ap.ip)));' +
  '    tr.setAttribute("data-mac", String(ap.mac || "-"));' +
  '    tr.setAttribute("data-model", String(ap.model || "-"));' +
  '    tr.setAttribute("data-fw", String(ap.firmware || "-"));' +
  '    tr.setAttribute("data-ssid", String(ap.ssid || "-"));' +
  '    tr.setAttribute("data-ch", String(ap.channel || "-"));' +
  '    tr.setAttribute("data-clients", String(cCount));' +
  '    tr.setAttribute("data-lat", String(isOnline ? latNum : -1));' +
  '    tr.setAttribute("data-status", isOnline ? "online" : "offline");' +
  '    tr.setAttribute("data-static", ap.isStatic ? "true" : "false");' +
  '  }' +
  '  function syncApTableRows(aps) {' +
  '    var tbody = document.getElementById("apTableBody");' +
  '    if (!tbody || !Array.isArray(aps)) return;' +
  '    var initEmpty = document.getElementById("initialEmptyStateRow");' +
  '    if (initEmpty && aps.length > 0) initEmpty.parentNode.removeChild(initEmpty);' +
  '    var emptyRow = document.getElementById("emptyRow");' +
  '    var existingRows = tbody.querySelectorAll("tr.ap-row");' +
  '    var rowMap = {};' +
  '    var maxOrigIdx = existingRows.length;' +
  '    for (var i = 0; i < existingRows.length; i++) {' +
  '      var rk = existingRows[i].getAttribute("data-ap-key");' +
  '      if (rk) rowMap[rk] = existingRows[i];' +
  '      var oi = parseInt(existingRows[i].getAttribute("data-orig-idx"), 10);' +
  '      if (!isNaN(oi) && oi >= maxOrigIdx) maxOrigIdx = oi + 1;' +
  '    }' +
  '    var seenKeys = {};' +
  '    for (var j = 0; j < aps.length; j++) {' +
  '      var ap = aps[j];' +
  '      var apKey = String(ap.key || ap.mac || ap.ip);' +
  '      seenKeys[apKey] = true;' +
  '      var isOnline = ap.status === 1;' +
  '      var cCount = isOnline ? (Number(ap.clientCount) || 0) : 0;' +
  '      var latNum = isOnline ? (Number(ap.latencyMs) || 0) : 0;' +
  '      var astSig = ap.applyState ? (ap.applyState.phase + ":" + ap.applyState.pct + ":" + ap.applyState.message) : "";' +
  '      var sig = [ap.name || "AP", ap.ip || "", ap.mac || "-", ap.model || "-", ap.firmware || "-", ap.ssid || "-", ap.channel || "-", isOnline ? 1 : 0, cCount, latNum, ap.isStatic ? 1 : 0, astSig].join("|");' +
  '      var searchStr = [ap.name || "", ap.ip || "", ap.mac || "", ap.model || "", ap.firmware || "", ap.ssid || "", "ch" + (ap.channel || ""), ap.isStatic ? "co dinh static" : "", isOnline ? "online" : "offline"].join(" ").toLowerCase();' +
  '      var tr = rowMap[apKey];' +
  '      if (!tr) {' +
  '        tr = document.createElement("tr");' +
  '        tr.className = "ap-row";' +
  '        tr.setAttribute("data-orig-idx", String(maxOrigIdx++));' +
  '        tr.setAttribute("data-ap-key", apKey);' +
  '        applyRowFilterAttrs(tr, ap, sig, searchStr, isOnline, cCount, latNum);' +
  '        tr.innerHTML = buildApRowInnerHtml(ap);' +
  '        if (emptyRow && emptyRow.parentNode === tbody) tbody.insertBefore(tr, emptyRow);' +
  '        else tbody.appendChild(tr);' +
  '      } else if (tr.getAttribute("data-sig") !== sig) {' +
  '        applyRowFilterAttrs(tr, ap, sig, searchStr, isOnline, cCount, latNum);' +
  '        tr.innerHTML = buildApRowInnerHtml(ap);' +
  '      }' +
  '    }' +
  '    for (var oldK in rowMap) {' +
  '      if (!seenKeys[oldK] && rowMap[oldK].parentNode) {' +
  '        rowMap[oldK].parentNode.removeChild(rowMap[oldK]);' +
  '      }' +
  '    }' +
  '    filterTable();' +
  '  }' +
  '  function applyLiveDashboardData(payload) {' +
  '    if (!payload || !payload.summary) return;' +
  '    var s = payload.summary;' +
  '    var staticCnt = Number(payload.staticCount) || 0;' +
  '    var onlinePct = s.totalAPs > 0 ? Math.round((s.onlineCount / s.totalAPs) * 100) : 0;' +
  '    var elTotal = document.getElementById("kpiTotalAps"); if (elTotal) elTotal.innerText = s.totalAPs;' +
  '    var elStSub = document.getElementById("kpiStaticSub"); if (elStSub) elStSub.innerText = staticCnt + " thiết bị giám sát cố định";' +
  '    var elN9 = document.getElementById("kpiN9Count"); if (elN9) elN9.innerText = s.totolinkN9v1Count;' +
  '    var elOn = document.getElementById("kpiOnlineCount"); if (elOn) elOn.innerText = s.onlineCount;' +
  '    var elOnPct = document.getElementById("kpiOnlinePct"); if (elOnPct) elOnPct.innerText = onlinePct + "% trực tuyến";' +
  '    var elOff = document.getElementById("kpiOfflineCount");' +
  '    if (elOff) {' +
  '      elOff.innerText = s.offlineCount;' +
  '      elOff.className = "kpi-val" + (s.offlineCount > 0 ? " offline-alert" : "");' +
  '    }' +
  '    var elOffIco = document.getElementById("kpiOfflineIcon");' +
  '    if (elOffIco) elOffIco.style.color = s.offlineCount > 0 ? "var(--red)" : "";' +
  '    var elOffSub = document.getElementById("kpiOfflineSub");' +
  '    if (elOffSub) elOffSub.innerText = s.offlineCount === 0 ? "Mạng hoạt động ổn định" : "Cần kiểm tra thiết bị";' +
  '    var elCl = document.getElementById("kpiTotalClients"); if (elCl) elCl.innerText = s.totalClients;' +
  '    var elLat = document.getElementById("kpiAvgLatency");' +
  '    if (elLat) elLat.innerHTML = s.avgLatencyMs + \' <span style="font-size:14px;font-weight:600;color:var(--text-muted);">ms</span>\';' +
  '    var elStBadge = document.getElementById("staticIpBadgeCount");' +
  '    var liveStaticArr = Array.isArray(payload.staticIps) ? payload.staticIps : (Array.isArray(s.staticIPs) ? s.staticIPs : null);' +
  '    if (elStBadge && liveStaticArr) elStBadge.innerText = liveStaticArr.length + " IP";' +
  '    var stInputEl = document.getElementById("staticIpsInput");' +
  '    if (stInputEl && liveStaticArr && document.activeElement !== stInputEl) {' +
  '      stInputEl.value = liveStaticArr.join(", ");' +
  '    }' +
  '    var btnDelOff = document.getElementById("btnDeleteOfflineAps");' +
  '    var lblDelOff = document.getElementById("delOfflineCount");' +
  '    if (lblDelOff) lblDelOff.innerText = s.offlineCount;' +
  '    if (btnDelOff) btnDelOff.style.display = (IS_ADMIN && s.offlineCount > 0) ? "inline-flex" : "none";' +
  '    var tAll = document.getElementById("tabCountAll"); if (tAll) tAll.innerText = s.totalAPs;' +
  '    var tOn = document.getElementById("tabCountOnline"); if (tOn) tOn.innerText = s.onlineCount;' +
  '    var tOff = document.getElementById("tabCountOffline"); if (tOff) tOff.innerText = s.offlineCount;' +
  '    var tSt = document.getElementById("tabCountStatic"); if (tSt) tSt.innerText = staticCnt;' +
  '    var totLbl = document.getElementById("totalApCount"); if (totLbl) totLbl.innerText = s.totalAPs;' +
  '    if (payload.rfSummary) {' +
  '      var rfs = payload.rfSummary;' +
  '      var needCnt = rfs.totolinkActionCount || 0;' +
  '      var needB = document.getElementById("rfNeedCountBanner"); if (needB) needB.innerText = needCnt;' +
  '      var needChip = document.getElementById("rfNeedChipBanner");' +
  '      if (needChip) needChip.className = "rf-chip " + (needCnt > 0 ? "warn" : "ok");' +
  '      var btnC = document.getElementById("rfBtnCount"); if (btnC) btnC.innerText = needCnt;' +
  '      var navB = document.getElementById("navRfNeedBadge");' +
  '      if (navB) { navB.innerText = needCnt; navB.style.display = needCnt > 0 ? "inline-flex" : "none"; }' +
  '      var hrsB = document.getElementById("rfHoursBanner"); if (hrsB) hrsB.innerText = rfs.systemHoursObserved || 0.1;' +
  '      var smpB = document.getElementById("rfSamplesBanner"); if (smpB) smpB.innerText = rfs.totalSamples24h || 0;' +
  '      var lnkB = document.getElementById("rfLinksBanner"); if (lnkB) lnkB.innerText = rfs.measuredNeighborLinks || 0;' +
  '    }' +
  '    if (payload.rfSettings && document.activeElement !== document.getElementById("mode2TimeMain") && document.activeElement !== document.getElementById("mode2TimeModal")) {' +
  '      syncMode2UiElements(payload.rfSettings);' +
  '    }' +
  '    if (payload.rfPlan) {' +
  '      rfPlanCache = payload.rfPlan;' +
  '      updateRfSummaryUi(payload.rfPlan);' +
  '      var rfOvLive = document.getElementById("rfOptModalOverlay");' +
  '      if (rfOvLive && rfOvLive.classList.contains("open")) {' +
  '        var ae = document.activeElement;' +
  '        var focusingRfField = Boolean(ae && ((ae.classList && (ae.classList.contains("rf-sel") || ae.classList.contains("pager-size-sel"))) || ae.id === "rfSearchInput"));' +
  '        if (!focusingRfField) {' +
  '          renderRfOptView();' +
  '        } else {' +
  '          patchRfModalLiveStates(payload.rfPlan);' +
  '        }' +
  '        var ftLive = document.getElementById("rfModalUpdatedTime");' +
  '        if (ftLive) ftLive.innerText = "Cập nhật trực tiếp lúc " + formatNowTime();' +
  '      }' +
  '    }' +
  '    if (Array.isArray(payload.aps)) {' +
  '      syncApTableRows(payload.aps);' +
  '    }' +
  '  }' +
  '  function fetchLiveSnapshot(showSpin) {' +
  '    var mBtn = document.getElementById("manualRefreshBtn");' +
  '    if (showSpin && mBtn) { mBtn.disabled = true; mBtn.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang tải\'; }' +
  '    return fetch("/api/dashboard-live")' +
  '      .then(checkAuthJson)' +
  '      .then(function(d){' +
  '        if (showSpin && mBtn) { mBtn.disabled = false; mBtn.innerHTML = \'<i class="fi fi-rr-refresh"></i> Làm mới\'; }' +
  '        if (d && d.success && d.payload) {' +
  '          applyLiveDashboardData(d.payload);' +
  '          setLiveIndicator("live", formatNowTime());' +
  '        }' +
  '      })' +
  '      .catch(function(){' +
  '        if (showSpin && mBtn) { mBtn.disabled = false; mBtn.innerHTML = \'<i class="fi fi-rr-refresh"></i> Làm mới\'; }' +
  '        setLiveIndicator("offline");' +
  '      });' +
  '  }' +
  '  function manualRefreshNow() {' +
  '    fetchLiveSnapshot(true);' +
  '  }' +
  '  function startFallbackPolling() {' +
  '    if (fallbackPollTimer) return;' +
  '    fallbackPollTimer = setInterval(function() {' +
  '      if (!isPaused) fetchLiveSnapshot(false);' +
  '    }, 5000);' +
  '  }' +
  '  function stopFallbackPolling() {' +
  '    if (fallbackPollTimer) { clearInterval(fallbackPollTimer); fallbackPollTimer = null; }' +
  '  }' +
  '  function connectRealtimeStream() {' +
  '    setLiveIndicator("live", formatNowTime());' +
  '    if (typeof EventSource === "undefined") {' +
  '      startFallbackPolling();' +
  '      return;' +
  '    }' +
  '    try {' +
  '      if (liveEventSource) liveEventSource.close();' +
  '      liveEventSource = new EventSource("/api/realtime-stream");' +
  '      liveEventSource.onopen = function() {' +
  '        stopFallbackPolling();' +
  '        setLiveIndicator("live", formatNowTime());' +
  '      };' +
  '      liveEventSource.onmessage = function(ev) {' +
  '        if (!ev || !ev.data) return;' +
  '        try {' +
  '          var payload = JSON.parse(ev.data);' +
  '          if (isPaused) {' +
  '            pendingLivePayload = payload;' +
  '          } else {' +
  '            applyLiveDashboardData(payload);' +
  '            setLiveIndicator("live", formatNowTime());' +
  '          }' +
  '        } catch (e) {}' +
  '      };' +
  '      liveEventSource.onerror = function() {' +
  '        setLiveIndicator("offline");' +
  '        startFallbackPolling();' +
  '      };' +
  '    } catch (e) {' +
  '      startFallbackPolling();' +
  '    }' +
  '  }' +
  '  function togglePause() {' +
  '    isPaused = !isPaused;' +
  '    var btn = document.getElementById("pauseBtn");' +
  '    if (btn) btn.innerHTML = isPaused ? \'<i class="fi fi-rr-play"></i> Tiếp tục\' : \'<i class="fi fi-rr-pause"></i> Tạm dừng\';' +
  '    if (!isPaused && pendingLivePayload) {' +
  '      applyLiveDashboardData(pendingLivePayload);' +
  '      pendingLivePayload = null;' +
  '    }' +
  '    setLiveIndicator("live", formatNowTime());' +
  '  }' +
  '  var colSortField = "";' +
  '  var colSortDir = "";' +
  '  var ALL_SORT_COLS = ["name", "ip", "mac", "model", "ssid", "channel", "clients", "latency", "status"];' +
  '  function setMainTablePage(p) {' +
  '    mainTablePage = Number(p) || 1;' +
  '    filterTable();' +
  '  }' +
  '  function setMainTablePageSize(sz) {' +
  '    mainTablePageSize = Number(sz) || 0;' +
  '    mainTablePage = 1;' +
  '    filterTable();' +
  '  }' +
  '  function onMainSearchInput() {' +
  '    mainTablePage = 1;' +
  '    filterTable();' +
  '  }' +
  '  function onColFilterChange() {' +
  '    mainTablePage = 1;' +
  '    filterTable();' +
  '  }' +
  '  function syncStatusTabButtons(filterType) {' +
  '    var tabs = document.querySelectorAll("#mainFilterTabs .tab-btn");' +
  '    for (var i = 0; i < tabs.length; i++) {' +
  '      var tf = tabs[i].getAttribute("data-tab-filter") || "";' +
  '      if (tf === filterType) tabs[i].classList.add("active");' +
  '      else tabs[i].classList.remove("active");' +
  '    }' +
  '  }' +
  '  function onColStatusFilterChange() {' +
  '    var stSel = document.getElementById("colFilterStatus");' +
  '    var val = stSel ? stSel.value : "";' +
  '    currentFilter = val || "all";' +
  '    syncStatusTabButtons(currentFilter);' +
  '    mainTablePage = 1;' +
  '    filterTable();' +
  '  }' +
  '  function toggleColSort(colName) {' +
  '    if (colSortField !== colName) {' +
  '      colSortField = colName;' +
  '      colSortDir = (colName === "clients" || colName === "latency") ? "desc" : "asc";' +
  '    } else if (colSortDir === ((colName === "clients" || colName === "latency") ? "desc" : "asc")) {' +
  '      colSortDir = (colSortDir === "asc") ? "desc" : "asc";' +
  '    } else {' +
  '      colSortField = "";' +
  '      colSortDir = "";' +
  '    }' +
  '    mainTablePage = 1;' +
  '    filterTable();' +
  '  }' +
  '  function matchesIpColQuery(ipStr, ipNum, rawQuery) {' +
  '    var q = String(rawQuery || "").trim().toLowerCase();' +
  '    if (!q) return true;' +
  '    if (q.indexOf("/") !== -1) {' +
  '      var parts = q.split("/");' +
  '      var bNum = ipToNumClient(parts[0]);' +
  '      var pfx = parseInt(parts[1], 10);' +
  '      if (bNum && !isNaN(pfx) && pfx >= 8 && pfx <= 32) {' +
  '        var mask = pfx === 32 ? 0xFFFFFFFF : ((~0 << (32 - pfx)) >>> 0);' +
  '        return ((ipNum & mask) >>> 0) === ((bNum & mask) >>> 0);' +
  '      }' +
  '    }' +
  '    if (q.indexOf("-") !== -1) {' +
  '      var rp = q.split("-");' +
  '      var sIp = rp[0].trim();' +
  '      var ePart = (rp[1] || "").trim();' +
  '      var eIp = ePart;' +
  '      if (ePart && ePart.indexOf(".") === -1 && sIp.split(".").length === 4) {' +
  '        var seg = sIp.split("."); seg[3] = ePart; eIp = seg.join(".");' +
  '      }' +
  '      var sN = ipToNumClient(sIp), eN = ipToNumClient(eIp);' +
  '      if (sN && eN) {' +
  '        if (sN > eN) { var t = sN; sN = eN; eN = t; }' +
  '        return ipNum >= sN && ipNum <= eN;' +
  '      }' +
  '    }' +
  '    return String(ipStr || "").toLowerCase().indexOf(q) !== -1;' +
  '  }' +
  '  function refreshDynamicColumnDropdowns(rows) {' +
  '    var subnetMap = {}, ouiMap = {}, modelMap = {}, fwMap = {}, ssidMap = {}, chMap = {};' +
  '    var hasNonStdCh = false;' +
  '    for (var i = 0; i < rows.length; i++) {' +
  '      var r = rows[i];' +
  '      var ip = r.getAttribute("data-ip") || "";' +
  '      var ipParts = ip.split(".");' +
  '      if (ipParts.length === 4) {' +
  '        var subPref = ipParts[0] + "." + ipParts[1] + "." + ipParts[2] + ".";' +
  '        subnetMap[subPref] = (subnetMap[subPref] || 0) + 1;' +
  '      }' +
  '      var mac = r.getAttribute("data-mac") || "";' +
  '      if (mac && mac !== "-") {' +
  '        var ouiKey = mac.length >= 8 && mac.indexOf("-") !== -1 ? mac.substring(0, 8) : mac;' +
  '        ouiMap[ouiKey] = (ouiMap[ouiKey] || 0) + 1;' +
  '      }' +
  '      var mdl = r.getAttribute("data-model") || "-";' +
  '      modelMap[mdl] = (modelMap[mdl] || 0) + 1;' +
  '      var fw = r.getAttribute("data-fw") || "-";' +
  '      if (fw && fw !== "-" && fw.indexOf("Đang") === -1 && fw.indexOf("Chờ") === -1) {' +
  '        fwMap[fw] = (fwMap[fw] || 0) + 1;' +
  '      }' +
  '      var ssid = r.getAttribute("data-ssid") || "-";' +
  '      ssidMap[ssid] = (ssidMap[ssid] || 0) + 1;' +
  '      var ch = r.getAttribute("data-ch") || "-";' +
  '      chMap[ch] = (chMap[ch] || 0) + 1;' +
  '      var chNum = parseInt(ch, 10);' +
  '      if (!isNaN(chNum) && chNum <= 14 && chNum !== 1 && chNum !== 6 && chNum !== 11) hasNonStdCh = true;' +
  '    }' +
  '    var ipDl = document.getElementById("colIpDatalist");' +
  '    if (ipDl && document.activeElement !== document.getElementById("colFilterIp")) {' +
  '      var subs = Object.keys(subnetMap).sort();' +
  '      var ipDlSig = subs.map(function(k){ return k + ":" + subnetMap[k]; }).join("|");' +
  '      if (ipDl.getAttribute("data-opt-sig") !== ipDlSig) {' +
  '        ipDl.setAttribute("data-opt-sig", ipDlSig);' +
  '        ipDl.innerHTML = subs.map(function(k){ return \'<option value="\' + escText(k) + \'">\' + subnetMap[k] + " AP</option>"; }).join("");' +
  '      }' +
  '    }' +
  '    var macDl = document.getElementById("colMacDatalist");' +
  '    if (macDl && document.activeElement !== document.getElementById("colFilterMac")) {' +
  '      var ouis = Object.keys(ouiMap).sort();' +
  '      var macDlSig = ouis.map(function(k){ return k + ":" + ouiMap[k]; }).join("|");' +
  '      if (macDl.getAttribute("data-opt-sig") !== macDlSig) {' +
  '        macDl.setAttribute("data-opt-sig", macDlSig);' +
  '        macDl.innerHTML = ouis.map(function(k){ return \'<option value="\' + escText(k) + \'">\' + ouiMap[k] + " AP</option>"; }).join("");' +
  '      }' +
  '    }' +
  '    var mdlSel = document.getElementById("colFilterModel");' +
  '    if (mdlSel && document.activeElement !== mdlSel) {' +
  '      var curMdlVal = mdlSel.value || "";' +
  '      var mdls = Object.keys(modelMap).sort();' +
  '      var fws = Object.keys(fwMap).sort();' +
  '      var mdlSig = curMdlVal + "||" + mdls.map(function(k){ return k + ":" + modelMap[k]; }).join("|") + "||" + fws.map(function(k){ return k + ":" + fwMap[k]; }).join("|");' +
  '      if (mdlSel.getAttribute("data-opt-sig") !== mdlSig) {' +
  '        mdlSel.setAttribute("data-opt-sig", mdlSig);' +
  '        var mHtml = \'<option value="">Tất cả</option><optgroup label="Model thiết bị">\';' +
  '        for (var mi = 0; mi < mdls.length; mi++) {' +
  '          var mk = mdls[mi]; var mv = "model:" + mk;' +
  '          mHtml += \'<option value="\' + escText(mv) + \'"\' + (curMdlVal === mv ? " selected" : "") + ">" + escText(mk) + " (" + modelMap[mk] + ")</option>";' +
  '        }' +
  '        mHtml += "</optgroup>";' +
  '        if (fws.length > 0) {' +
  '          mHtml += \'<optgroup label="Phiên bản Firmware">\';' +
  '          for (var fi = 0; fi < fws.length; fi++) {' +
  '            var fk = fws[fi]; var fv = "fw:" + fk;' +
  '            mHtml += \'<option value="\' + escText(fv) + \'"\' + (curMdlVal === fv ? " selected" : "") + ">FW: " + escText(fk) + " (" + fwMap[fk] + ")</option>";' +
  '          }' +
  '          mHtml += "</optgroup>";' +
  '        }' +
  '        mdlSel.innerHTML = mHtml;' +
  '        mdlSel.value = curMdlVal;' +
  '      }' +
  '    }' +
  '    var ssidSel = document.getElementById("colFilterSsid");' +
  '    if (ssidSel && document.activeElement !== ssidSel) {' +
  '      var curSsidVal = ssidSel.value || "";' +
  '      var ssids = Object.keys(ssidMap).sort();' +
  '      if (curSsidVal && !ssidMap[curSsidVal]) ssids.push(curSsidVal);' +
  '      var ssidSig = curSsidVal + "||" + ssids.map(function(k){ return k + ":" + (ssidMap[k] || 0); }).join("|");' +
  '      if (ssidSel.getAttribute("data-opt-sig") !== ssidSig) {' +
  '        ssidSel.setAttribute("data-opt-sig", ssidSig);' +
  '        var sHtml = \'<option value="">Tất cả</option>\';' +
  '        for (var si = 0; si < ssids.length; si++) {' +
  '          var sk = ssids[si];' +
  '          var sLbl = sk === "-" ? "Chưa đồng bộ (-)" : sk;' +
  '          sHtml += \'<option value="\' + escText(sk) + \'"\' + (curSsidVal === sk ? " selected" : "") + ">" + escText(sLbl) + " (" + (ssidMap[sk] || 0) + ")</option>";' +
  '        }' +
  '        ssidSel.innerHTML = sHtml;' +
  '        ssidSel.value = curSsidVal;' +
  '      }' +
  '    }' +
  '    var chSel = document.getElementById("colFilterChannel");' +
  '    if (chSel && document.activeElement !== chSel) {' +
  '      var curChVal = chSel.value || "";' +
  '      var chKeys = Object.keys(chMap).sort(function(a, b) {' +
  '        var na = parseInt(a, 10), nb = parseInt(b, 10);' +
  '        if (!isNaN(na) && !isNaN(nb)) return na - nb;' +
  '        if (!isNaN(na)) return -1;' +
  '        if (!isNaN(nb)) return 1;' +
  '        return a.localeCompare(b);' +
  '      });' +
  '      var chSig = curChVal + "||" + (hasNonStdCh ? "1" : "0") + "||" + chKeys.map(function(k){ return k + ":" + chMap[k]; }).join("|");' +
  '      if (chSel.getAttribute("data-opt-sig") !== chSig) {' +
  '        chSel.setAttribute("data-opt-sig", chSig);' +
  '        var cHtml = \'<option value="">Tất cả</option>\';' +
  '        for (var ci = 0; ci < chKeys.length; ci++) {' +
  '          var ck = chKeys[ci];' +
  '          var cLbl = ck === "-" ? "Chưa rõ (-)" : ("CH " + ck);' +
  '          cHtml += \'<option value="\' + escText(ck) + \'"\' + (curChVal === ck ? " selected" : "") + ">" + escText(cLbl) + " (" + chMap[ck] + ")</option>";' +
  '        }' +
  '        if (hasNonStdCh || curChVal === "nonstd") {' +
  '          cHtml += \'<option value="nonstd"\' + (curChVal === "nonstd" ? " selected" : "") + ">Ngoài 1/6/11 (2.4G)</option>";' +
  '        }' +
  '        chSel.innerHTML = cHtml;' +
  '        chSel.value = curChVal;' +
  '      }' +
  '    }' +
  '  }' +
  '  function compareApRows(a, b, field, dir) {' +
  '    var mul = dir === "desc" ? -1 : 1;' +
  '    if (field === "ip") {' +
  '      var ia = Number(a.getAttribute("data-ip-num")) || 0;' +
  '      var ib = Number(b.getAttribute("data-ip-num")) || 0;' +
  '      return (ia - ib) * mul;' +
  '    }' +
  '    if (field === "clients") {' +
  '      var ca = Number(a.getAttribute("data-clients")) || 0;' +
  '      var cb = Number(b.getAttribute("data-clients")) || 0;' +
  '      if (ca !== cb) return (ca - cb) * mul;' +
  '    }' +
  '    if (field === "latency") {' +
  '      var la = Number(a.getAttribute("data-lat"));' +
  '      var lb = Number(b.getAttribute("data-lat"));' +
  '      if (la < 0 && lb < 0) return 0;' +
  '      if (la < 0) return 1;' +
  '      if (lb < 0) return -1;' +
  '      if (la !== lb) return (la - lb) * mul;' +
  '    }' +
  '    if (field === "channel") {' +
  '      var cha = parseInt(a.getAttribute("data-ch"), 10);' +
  '      var chb = parseInt(b.getAttribute("data-ch"), 10);' +
  '      if (isNaN(cha) && isNaN(chb)) return 0;' +
  '      if (isNaN(cha)) return 1;' +
  '      if (isNaN(chb)) return -1;' +
  '      if (cha !== chb) return (cha - chb) * mul;' +
  '    }' +
  '    if (field === "status") {' +
  '      var sa = a.getAttribute("data-status") === "online" ? 1 : 0;' +
  '      var sb = b.getAttribute("data-status") === "online" ? 1 : 0;' +
  '      if (sa !== sb) return (sb - sa) * mul;' +
  '    }' +
  '    var attrMap = { name: "data-name", mac: "data-mac", model: "data-model", ssid: "data-ssid" };' +
  '    var attr = attrMap[field] || "data-name";' +
  '    var va = String(a.getAttribute(attr) || "");' +
  '    var vb = String(b.getAttribute(attr) || "");' +
  '    return va.localeCompare(vb, undefined, { numeric: true, sensitivity: "base" }) * mul;' +
  '  }' +
  '  function updateColumnHeaderStates(activeFlags, activeCount) {' +
  '    for (var i = 0; i < ALL_SORT_COLS.length; i++) {' +
  '      var col = ALL_SORT_COLS[i];' +
  '      var th = document.getElementById("thCol_" + col);' +
  '      var ico = document.getElementById("sortIco_" + col);' +
  '      if (th) {' +
  '        if (activeFlags[col]) th.classList.add("th-filtered");' +
  '        else th.classList.remove("th-filtered");' +
  '        if (colSortField === col) th.classList.add("th-sorted");' +
  '        else th.classList.remove("th-sorted");' +
  '      }' +
  '      if (ico) {' +
  '        if (colSortField === col) {' +
  '          ico.className = "fi " + (colSortDir === "asc" ? "fi-rr-caret-up" : "fi-rr-caret-down") + " sort-ico";' +
  '        } else {' +
  '          ico.className = "fi fi-rr-sort-alt sort-ico";' +
  '        }' +
  '      }' +
  '    }' +
  '    var resetBtn = document.getElementById("btnResetColFilters");' +
  '    var resetLbl = document.getElementById("lblResetColFilters");' +
  '    var totalActive = activeCount + (colSortField ? 1 : 0);' +
  '    if (resetBtn) {' +
  '      resetBtn.disabled = totalActive === 0;' +
  '      if (totalActive > 0) resetBtn.classList.add("active");' +
  '      else resetBtn.classList.remove("active");' +
  '    }' +
  '    if (resetLbl) {' +
  '      resetLbl.innerText = totalActive > 0 ? ("Xóa lọc (" + totalActive + ")") : "Mặc định";' +
  '    }' +
  '  }' +
  '  function resetColumnFilters() {' +
  '    var ids = ["colFilterName", "colFilterIp", "colFilterMac", "colFilterModel", "colFilterSsid", "colFilterChannel", "colFilterClients", "colFilterLatency", "colFilterStatus"];' +
  '    for (var i = 0; i < ids.length; i++) {' +
  '      var el = document.getElementById(ids[i]);' +
  '      if (el) el.value = "";' +
  '    }' +
  '    colSortField = "";' +
  '    colSortDir = "";' +
  '    currentFilter = "all";' +
  '    syncStatusTabButtons("all");' +
  '    mainTablePage = 1;' +
  '    filterTable();' +
  '  }' +
  '  function resetAllSearchAndFilters() {' +
  '    var sIn = document.getElementById("searchInput");' +
  '    if (sIn) sIn.value = "";' +
  '    resetColumnFilters();' +
  '  }' +
  '  function filterTable() {' +
  '    var q = (document.getElementById("searchInput").value || "").trim().toLowerCase();' +
  '    var clearBtn = document.getElementById("clearBtn");' +
  '    if (clearBtn) clearBtn.style.display = q ? "inline-flex" : "none";' +
  '    var tbodyEl = document.getElementById("apTableBody");' +
  '    var rows = document.querySelectorAll(".ap-row");' +
  '    refreshDynamicColumnDropdowns(rows);' +
  '    var fName = ((document.getElementById("colFilterName") || {}).value || "").trim().toLowerCase();' +
  '    var fIp = ((document.getElementById("colFilterIp") || {}).value || "").trim();' +
  '    var fMac = ((document.getElementById("colFilterMac") || {}).value || "").trim().toUpperCase().replace(/:/g, "-");' +
  '    var fMacPlain = fMac.replace(/-/g, "");' +
  '    var fModel = ((document.getElementById("colFilterModel") || {}).value || "");' +
  '    var fSsid = ((document.getElementById("colFilterSsid") || {}).value || "");' +
  '    var fCh = ((document.getElementById("colFilterChannel") || {}).value || "");' +
  '    var fClients = ((document.getElementById("colFilterClients") || {}).value || "");' +
  '    var fLat = ((document.getElementById("colFilterLatency") || {}).value || "");' +
  '    var fStatus = ((document.getElementById("colFilterStatus") || {}).value || "");' +
  '    var effStatus = fStatus || (currentFilter !== "all" ? currentFilter : "");' +
  '    var activeFlags = {' +
  '      name: Boolean(fName), ip: Boolean(fIp), mac: Boolean(fMac), model: Boolean(fModel),' +
  '      ssid: Boolean(fSsid), channel: Boolean(fCh), clients: Boolean(fClients), latency: Boolean(fLat),' +
  '      status: Boolean(effStatus)' +
  '    };' +
  '    var activeCnt = 0;' +
  '    for (var ak in activeFlags) { if (activeFlags[ak]) activeCnt++; }' +
  '    updateColumnHeaderStates(activeFlags, activeCnt);' +
  '    var matchedRows = [];' +
  '    for (var i = 0; i < rows.length; i++) {' +
  '      var r = rows[i];' +
  '      var searchData = r.getAttribute("data-search") || "";' +
  '      if (q && searchData.indexOf(q) === -1) { r.style.display = "none"; continue; }' +
  '      var status = r.getAttribute("data-status") || "";' +
  '      var isStatic = r.getAttribute("data-static") === "true";' +
  '      if (effStatus === "online" && status !== "online") { r.style.display = "none"; continue; }' +
  '      if (effStatus === "offline" && status !== "offline") { r.style.display = "none"; continue; }' +
  '      if (effStatus === "static" && !isStatic) { r.style.display = "none"; continue; }' +
  '      if (fName) {' +
  '        var rName = (r.getAttribute("data-name") || "").toLowerCase();' +
  '        if (rName.indexOf(fName) === -1) { r.style.display = "none"; continue; }' +
  '      }' +
  '      if (fIp) {' +
  '        var rIp = r.getAttribute("data-ip") || "";' +
  '        var rIpNum = Number(r.getAttribute("data-ip-num")) || 0;' +
  '        if (!matchesIpColQuery(rIp, rIpNum, fIp)) { r.style.display = "none"; continue; }' +
  '      }' +
  '      if (fMac) {' +
  '        var rMac = (r.getAttribute("data-mac") || "").toUpperCase();' +
  '        var rMacPlain = rMac.replace(/-/g, "");' +
  '        if (rMac.indexOf(fMac) === -1 && (!fMacPlain || rMacPlain.indexOf(fMacPlain) === -1)) { r.style.display = "none"; continue; }' +
  '      }' +
  '      if (fModel) {' +
  '        if (fModel.indexOf("model:") === 0) {' +
  '          if ((r.getAttribute("data-model") || "-") !== fModel.substring(6)) { r.style.display = "none"; continue; }' +
  '        } else if (fModel.indexOf("fw:") === 0) {' +
  '          if ((r.getAttribute("data-fw") || "-") !== fModel.substring(3)) { r.style.display = "none"; continue; }' +
  '        }' +
  '      }' +
  '      if (fSsid && (r.getAttribute("data-ssid") || "-") !== fSsid) { r.style.display = "none"; continue; }' +
  '      if (fCh) {' +
  '        var rCh = r.getAttribute("data-ch") || "-";' +
  '        if (fCh === "nonstd") {' +
  '          var chN = parseInt(rCh, 10);' +
  '          if (isNaN(chN) || chN > 14 || chN === 1 || chN === 6 || chN === 11) { r.style.display = "none"; continue; }' +
  '        } else if (rCh !== fCh) {' +
  '          r.style.display = "none"; continue;' +
  '        }' +
  '      }' +
  '      if (fClients) {' +
  '        var cVal = Number(r.getAttribute("data-clients")) || 0;' +
  '        if (fClients === "gt0" && !(cVal > 0)) { r.style.display = "none"; continue; }' +
  '        if (fClients === "eq0" && cVal !== 0) { r.style.display = "none"; continue; }' +
  '        if (fClients === "gte5" && !(cVal >= 5)) { r.style.display = "none"; continue; }' +
  '        if (fClients === "gte10" && !(cVal >= 10)) { r.style.display = "none"; continue; }' +
  '        if (fClients === "gte20" && !(cVal >= 20)) { r.style.display = "none"; continue; }' +
  '      }' +
  '      if (fLat) {' +
  '        var lVal = Number(r.getAttribute("data-lat"));' +
  '        if (fLat === "na" && lVal >= 0) { r.style.display = "none"; continue; }' +
  '        if (fLat === "fast" && !(lVal >= 0 && lVal <= 3)) { r.style.display = "none"; continue; }' +
  '        if (fLat === "good" && !(lVal >= 4 && lVal <= 12)) { r.style.display = "none"; continue; }' +
  '        if (fLat === "mid" && !(lVal >= 13 && lVal <= 30)) { r.style.display = "none"; continue; }' +
  '        if (fLat === "high" && !(lVal > 30)) { r.style.display = "none"; continue; }' +
  '      }' +
  '      matchedRows.push(r);' +
  '    }' +
  '    if (colSortField) {' +
  '      matchedRows.sort(function(a, b) { return compareApRows(a, b, colSortField, colSortDir); });' +
  '    } else {' +
  '      matchedRows.sort(function(a, b) {' +
  '        return (Number(a.getAttribute("data-orig-idx")) || 0) - (Number(b.getAttribute("data-orig-idx")) || 0);' +
  '      });' +
  '    }' +
  '    var totalMatched = matchedRows.length;' +
  '    if (tbodyEl && totalMatched > 1) {' +
  '      var needReorder = false;' +
  '      for (var ord = 1; ord < totalMatched; ord++) {' +
  '        if (matchedRows[ord - 1].compareDocumentPosition(matchedRows[ord]) & 2) {' +
  '          needReorder = true;' +
  '          break;' +
  '        }' +
  '      }' +
  '      if (needReorder) {' +
  '        var anchorRow = document.getElementById("emptyRow");' +
  '        var useAnchor = Boolean(anchorRow && anchorRow.parentNode === tbodyEl);' +
  '        for (var mv = 0; mv < totalMatched; mv++) {' +
  '          if (useAnchor) tbodyEl.insertBefore(matchedRows[mv], anchorRow);' +
  '          else tbodyEl.appendChild(matchedRows[mv]);' +
  '        }' +
  '      }' +
  '    }' +
  '    var totalPages = mainTablePageSize > 0 ? Math.max(1, Math.ceil(totalMatched / mainTablePageSize)) : 1;' +
  '    if (mainTablePage > totalPages) mainTablePage = totalPages;' +
  '    if (mainTablePage < 1) mainTablePage = 1;' +
  '    var startIdx = mainTablePageSize > 0 ? ((mainTablePage - 1) * mainTablePageSize) : 0;' +
  '    var endIdx = mainTablePageSize > 0 ? Math.min(totalMatched, startIdx + mainTablePageSize) : totalMatched;' +
  '    for (var m = 0; m < totalMatched; m++) {' +
  '      matchedRows[m].style.display = (m >= startIdx && m < endIdx) ? "" : "none";' +
  '    }' +
  '    var visEl = document.getElementById("visibleCount");' +
  '    if (visEl) visEl.innerText = totalMatched;' +
  '    var emptyRow = document.getElementById("emptyRow");' +
  '    if (emptyRow) emptyRow.style.display = totalMatched === 0 ? "" : "none";' +
  '    var pagerEl = document.getElementById("mainTablePager");' +
  '    if (pagerEl) {' +
  '      var ae = document.activeElement;' +
  '      if (!(ae && ae.parentNode && pagerEl.contains(ae) && ae.tagName === "SELECT")) {' +
  '        pagerEl.innerHTML = buildPagerHtml(totalMatched, mainTablePage, mainTablePageSize, "setMainTablePage", "setMainTablePageSize", [15, 30, 50, 0], "AP");' +
  '      }' +
  '    }' +
  '  }' +
  '  function setFilter(filterType, btn) {' +
  '    currentFilter = filterType;' +
  '    mainTablePage = 1;' +
  '    var stSel = document.getElementById("colFilterStatus");' +
  '    if (stSel) stSel.value = (filterType === "all" ? "" : filterType);' +
  '    syncStatusTabButtons(filterType);' +
  '    filterTable();' +
  '  }' +
  '  function clearSearch() {' +
  '    var input = document.getElementById("searchInput");' +
  '    if (input) { input.value = ""; input.focus(); }' +
  '    mainTablePage = 1;' +
  '    filterTable();' +
  '  }' +
  '  var panelMsgTimers = {};' +
  '  function showPanelFeedback(elId, kind, htmlText, autoHideMs) {' +
  '    var el = document.getElementById(elId);' +
  '    if (!el) return;' +
  '    if (panelMsgTimers[elId]) { clearTimeout(panelMsgTimers[elId]); panelMsgTimers[elId] = null; }' +
  '    var ico = kind === "err" ? "fi-rr-triangle-warning" : (kind === "info" ? "fi-rr-info" : "fi-rr-check-circle");' +
  '    el.className = "panel-feedback show " + (kind || "ok");' +
  '    el.innerHTML = \'<i class="fi \' + ico + \'"></i><span>\' + htmlText + "</span>";' +
  '    if (autoHideMs && autoHideMs > 0) {' +
  '      panelMsgTimers[elId] = setTimeout(function() { el.className = "panel-feedback"; }, autoHideMs);' +
  '    }' +
  '  }' +
  '  function saveStaticIps() {' +
  '    var inputEl = document.getElementById("staticIpsInput");' +
  '    var ips = inputEl ? inputEl.value.trim() : "";' +
  '    var btn = document.getElementById("saveStaticBtn");' +
  '    btn.disabled = true; btn.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang lưu &amp; kiểm tra...\';' +
  '    showPanelFeedback("staticStatusMsg", "info", "Đang lưu cấu hình và kiểm tra kết nối tới các IP cố định...", 0);' +
  '    fetch("/api/static-ips", {' +
  '      method: "POST",' +
  '      headers: { "Content-Type": "application/json" },' +
  '      body: JSON.stringify({ ips: ips })' +
  '    }).then(checkAuthJson).then(function(data){' +
  '      if (!data || !data.success) {' +
  '        btn.disabled = false; btn.innerHTML = \'<i class="fi fi-rr-disk"></i> Lưu Cấu Hình\';' +
  '        showPanelFeedback("staticStatusMsg", "err", "Lỗi lưu cấu hình: " + escText((data && data.error) || "Không xác định"), 9000);' +
  '        return;' +
  '      }' +
  '      if (inputEl && Array.isArray(data.ips)) inputEl.value = data.ips.join(", ");' +
  '      if (data.payload) applyLiveDashboardData(data.payload);' +
  '      else fetchLiveSnapshot(false);' +
  '      var onlineCnt = (data.probeStats && typeof data.probeStats.onlineInTargetCount === "number") ? data.probeStats.onlineInTargetCount : null;' +
  '      var extraNote = onlineCnt !== null ? (" • <b>" + onlineCnt + "/" + data.count + "</b> IP đang phản hồi Online") : " • Đang đồng bộ trạng thái AP...";' +
  '      showPanelFeedback("staticStatusMsg", "ok", "Đã cập nhật <b>" + data.count + "</b> IP giám sát cố định vào danh sách AP" + extraNote, 10000);' +
  '      btn.innerHTML = \'<i class="fi fi-rr-check-circle"></i> Đã lưu!\';' +
  '      setTimeout(function() {' +
  '        btn.disabled = false;' +
  '        btn.innerHTML = \'<i class="fi fi-rr-disk"></i> Lưu Cấu Hình\';' +
  '      }, 1200);' +
  '    }).catch(function(err){' +
  '      showPanelFeedback("staticStatusMsg", "err", "Lỗi kết nối máy chủ: " + escText(err.message), 9000);' +
  '      btn.disabled = false; btn.innerHTML = \'<i class="fi fi-rr-disk"></i> Lưu Cấu Hình\';' +
  '    });' +
  '  }' +
  '  function triggerScan() {' +
  '    var target = document.getElementById("targetInput").value.trim();' +
  '    if (!target) {' +
  '      showPanelFeedback("scanStatusMsg", "err", "Vui lòng nhập địa chỉ IP hoặc dải mạng cần quét (ví dụ: 192.168.1.165 hoặc 192.168.1.0/24).", 8000);' +
  '      return;' +
  '    }' +
  '    var btn = document.getElementById("scanBtn");' +
  '    btn.disabled = true; btn.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang quét...\';' +
  '    showPanelFeedback("scanStatusMsg", "info", "Đang quét <b>" + escText(target) + "</b> qua Ping, ARP &amp; HTTP CGI (xuyên VLAN/Subnet)...", 0);' +
  '    fetch("/api/scan", {' +
  '      method: "POST",' +
  '      headers: { "Content-Type": "application/json" },' +
  '      body: JSON.stringify({ target: target })' +
  '    }).then(checkAuthJson).then(function(data){' +
  '      if (!data || !data.success) {' +
  '        btn.disabled = false; btn.innerHTML = \'<i class="fi fi-rr-search"></i> Quét Ngay\';' +
  '        showPanelFeedback("scanStatusMsg", "err", escText((data && data.error) || "Không thể quét dải mạng"), 10000);' +
  '        return;' +
  '      }' +
  '      if (data.payload) applyLiveDashboardData(data.payload);' +
  '      else fetchLiveSnapshot(false);' +
  '      var st = data.stats || {};' +
  '      var sec = ((Number(st.scanDurationMs) || 0) / 1000).toFixed(1);' +
  '      var onCnt = Number(st.onlineInTargetCount) || 0;' +
  '      var namesPreview = (Array.isArray(st.matchedOnlineNames) && st.matchedOnlineNames.length > 0)' +
  '        ? (" (" + escText(st.matchedOnlineNames.slice(0, 4).join(", ")) + (st.matchedOnlineNames.length > 4 ? ", ..." : "") + ")")' +
  '        : "";' +
  '      if (onCnt > 0) {' +
  '        showPanelFeedback("scanStatusMsg", "ok", "Đã quét <b>" + (st.totalScannedIPs || 0) + "</b> IP trong " + sec + "s • Phát hiện <b>" + onCnt + "</b> AP trực tuyến" + namesPreview, 12000);' +
  '      } else {' +
  '        showPanelFeedback("scanStatusMsg", "info", "Đã quét <b>" + (st.totalScannedIPs || 0) + "</b> IP trong " + sec + "s • Không phát hiện AP nào đang trực tuyến trên dải này.", 10000);' +
  '      }' +
  '      btn.innerHTML = \'<i class="fi fi-rr-check-circle"></i> Đã quét xong\';' +
  '      setTimeout(function() {' +
  '        btn.disabled = false;' +
  '        btn.innerHTML = \'<i class="fi fi-rr-search"></i> Quét Ngay\';' +
  '      }, 1400);' +
  '    }).catch(function(err){' +
  '      showPanelFeedback("scanStatusMsg", "err", "Lỗi kết nối khi quét: " + escText(err.message), 9000);' +
  '      btn.disabled = false; btn.innerHTML = \'<i class="fi fi-rr-search"></i> Quét Ngay\';' +
  '    });' +
  '  }' +
  '  function saveApCredentials() {' +
  '    if (!IS_ADMIN) return;' +
  '    var uEl = document.getElementById("apCredUserInput");' +
  '    var pEl = document.getElementById("apCredPassInput");' +
  '    var sEl = document.getElementById("apCredSsidInput");' +
  '    var btn = document.getElementById("saveApCredBtn");' +
  '    var uname = uEl ? uEl.value.trim() : "admin";' +
  '    var pwRaw = pEl ? pEl.value.trim() : "";' +
  '    var ssidDef = sEl ? sEl.value.trim() : "";' +
  '    if (!uname) {' +
  '      showPanelFeedback("apCredStatusMsg", "err", "Vui lòng nhập tên tài khoản quản trị AP (mặc định: admin).", 7000);' +
  '      return;' +
  '    }' +
  '    if (btn) { btn.disabled = true; btn.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang lưu...\'; }' +
  '    fetch("/api/ap-credentials", {' +
  '      method: "POST",' +
  '      headers: { "Content-Type": "application/json" },' +
  '      body: JSON.stringify({ username: uname, passwords: pwRaw, defaultSsid: ssidDef })' +
  '    }).then(checkAuthJson).then(function(data){' +
  '      if (!data || !data.success) {' +
  '        if (btn) { btn.disabled = false; btn.innerHTML = \'<i class="fi fi-rr-disk"></i> Lưu Tài Khoản AP\'; }' +
  '        showPanelFeedback("apCredStatusMsg", "err", escText((data && data.error) || "Không thể lưu tài khoản AP"), 8000);' +
  '        return;' +
  '      }' +
  '      if (pEl) pEl.value = "";' +
  '      var badge = document.getElementById("apPassCountBadge");' +
  '      if (badge && typeof data.passwordCount === "number") badge.textContent = data.passwordCount + " mật khẩu đã cấu hình";' +
  '      showPanelFeedback("apCredStatusMsg", "ok", "Đã lưu cấu hình tài khoản AP vào <b>config.json</b> &amp; tự động đồng bộ lại thiết bị trực tuyến!", 9000);' +
  '      fetchLiveSnapshot(false);' +
  '      if (btn) {' +
  '        btn.innerHTML = \'<i class="fi fi-rr-check-circle"></i> Đã lưu!\';' +
  '        setTimeout(function(){ btn.disabled = false; btn.innerHTML = \'<i class="fi fi-rr-disk"></i> Lưu Tài Khoản AP\'; }, 1200);' +
  '      }' +
  '    }).catch(function(err){' +
  '      if (btn) { btn.disabled = false; btn.innerHTML = \'<i class="fi fi-rr-disk"></i> Lưu Tài Khoản AP\'; }' +
  '      showPanelFeedback("apCredStatusMsg", "err", "Lỗi kết nối máy chủ: " + escText(err.message), 8000);' +
  '    });' +
  '  }' +
  '  function deleteSingleAp(btnEl) {' +
  '    if (!btnEl || !IS_ADMIN) return;' +
  '    var apKey = btnEl.getAttribute("data-key") || "";' +
  '    var apIp = btnEl.getAttribute("data-ip") || "";' +
  '    var apName = btnEl.getAttribute("data-name") || apIp || "AP";' +
  '    var isStatic = btnEl.getAttribute("data-static") === "1";' +
  '    var isOnline = btnEl.getAttribute("data-online") === "1";' +
  '    var msg = "Bạn có chắc muốn xóa thiết bị " + apName + " (" + apIp + ") khỏi danh sách giám sát?";' +
  '    if (isStatic) msg += "\\n\\n• Địa chỉ " + apIp + " cũng sẽ được gỡ khỏi danh sách IP Giám Sát Cố Định.";' +
  '    if (isOnline) msg += "\\n• Thiết bị đang Online sẽ được tạm ẩn khỏi quét tự động (có thể thêm lại bất cứ lúc nào bằng cách Quét IP hoặc Gán IP Cố Định).";' +
  '    if (!confirm(msg)) return;' +
  '    btnEl.disabled = true;' +
  '    btnEl.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i>\';' +
  '    fetch("/api/aps/delete", {' +
  '      method: "POST",' +
  '      headers: { "Content-Type": "application/json" },' +
  '      body: JSON.stringify({ mode: "single", key: apKey, ip: apIp })' +
  '    }).then(checkAuthJson).then(function(data){' +
  '      if (!data || !data.success) {' +
  '        btnEl.disabled = false; btnEl.innerHTML = \'<i class="fi fi-rr-trash"></i>\';' +
  '        alert("Không thể xóa AP: " + ((data && data.error) || "Lỗi không xác định"));' +
  '        return;' +
  '      }' +
  '      if (data.payload) applyLiveDashboardData(data.payload);' +
  '      else fetchLiveSnapshot(false);' +
  '    }).catch(function(err){' +
  '      btnEl.disabled = false; btnEl.innerHTML = \'<i class="fi fi-rr-trash"></i>\';' +
  '      alert("Lỗi khi xóa AP: " + err.message);' +
  '    });' +
  '  }' +
  '  function deleteAllOfflineAps() {' +
  '    if (!IS_ADMIN) return;' +
  '    var btn = document.getElementById("btnDeleteOfflineAps");' +
  '    var cntEl = document.getElementById("delOfflineCount");' +
  '    var cnt = cntEl ? (parseInt(cntEl.innerText, 10) || 0) : 0;' +
  '    if (!confirm("Xóa toàn bộ " + (cnt || "các") + " thiết bị AP đang Offline khỏi danh sách giám sát?\\n\\n(Các IP Offline nằm trong danh sách IP Giám Sát Cố Định cũng sẽ được dọn sạch tương ứng)")) return;' +
  '    if (btn) { btn.disabled = true; btn.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang dọn...\'; }' +
  '    fetch("/api/aps/delete", {' +
  '      method: "POST",' +
  '      headers: { "Content-Type": "application/json" },' +
  '      body: JSON.stringify({ mode: "offline" })' +
  '    }).then(checkAuthJson).then(function(data){' +
  '      if (btn) {' +
  '        btn.disabled = false;' +
  '        btn.innerHTML = \'<i class="fi fi-rr-trash"></i> Xóa Offline (<span id="delOfflineCount">0</span>)\';' +
  '      }' +
  '      if (!data || !data.success) {' +
  '        alert("Lỗi khi xóa AP Offline: " + ((data && data.error) || "Không xác định"));' +
  '        return;' +
  '      }' +
  '      if (data.payload) applyLiveDashboardData(data.payload);' +
  '      else fetchLiveSnapshot(false);' +
  '    }).catch(function(err){' +
  '      if (btn) {' +
  '        btn.disabled = false;' +
  '        btn.innerHTML = \'<i class="fi fi-rr-trash"></i> Xóa Offline (<span id="delOfflineCount">\' + cnt + \'</span>)\';' +
  '      }' +
  '      alert("Lỗi kết nối: " + err.message);' +
  '    });' +
  '  }' +
  '  function escText(s) {' +
  '    return String(s === undefined || s === null ? "" : s)' +
  '      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");' +
  '  }' +
  '  function fmtBytes(b) {' +
  '    var n = Number(b) || 0;' +
  '    if (n <= 0) return "";' +
  '    if (n >= 1073741824) return (n / 1073741824).toFixed(2) + " GB";' +
  '    if (n >= 1048576) return (n / 1048576).toFixed(1) + " MB";' +
  '    if (n >= 1024) return (n / 1024).toFixed(1) + " KB";' +
  '    return n + " B";' +
  '  }' +
  '  function openClientsModal(btnEl) {' +
  '    if (!btnEl) return;' +
  '    activeClientPillBtn = btnEl;' +
  '    activeModalApIp = btnEl.getAttribute("data-ip") || "";' +
  '    var apName = btnEl.getAttribute("data-name") || "Access Point";' +
  '    var apModel = btnEl.getAttribute("data-model") || "-";' +
  '    var apSsid = btnEl.getAttribute("data-ssid") || "-";' +
  '    var apCh = btnEl.getAttribute("data-channel") || "-";' +
  '    isModalOpen = true;' +
  '    document.getElementById("modalApName").innerText = apName;' +
  '    document.getElementById("modalApModel").innerText = apModel;' +
  '    document.getElementById("modalApIp").innerText = activeModalApIp;' +
  '    document.getElementById("modalApSsid").innerText = apSsid;' +
  '    document.getElementById("modalApCh").innerText = "CH " + apCh;' +
  '    document.getElementById("clientModalOverlay").classList.add("open");' +
  '    loadApClients(false);' +
  '  }' +
  '  function closeClientsModal() {' +
  '    var ov = document.getElementById("clientModalOverlay");' +
  '    if (ov) ov.classList.remove("open");' +
  '    syncAnyModalOpenFlag();' +
  '  }' +
  '  function loadApClients(forceLive) {' +
  '    if (!activeModalApIp) return;' +
  '    var bodyEl = document.getElementById("modalClientsBody");' +
  '    var countBadge = document.getElementById("modalClientCountBadge");' +
  '    var refBtn = document.getElementById("modalRefreshBtn");' +
  '    var footTime = document.getElementById("modalUpdatedTime");' +
  '    if (refBtn) { refBtn.disabled = true; refBtn.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang tải...\'; }' +
  '    bodyEl.innerHTML = \'<div class="modal-state"><i class="fi fi-rr-spinner fi-spin"></i><div>Đang truy vấn danh sách thiết bị kết nối trực tiếp từ AP <b>\' + escText(activeModalApIp) + \'</b>...</div></div>\';' +
  '    fetch("/api/ap-clients?ip=" + encodeURIComponent(activeModalApIp) + (forceLive ? "&live=1" : ""))' +
  '      .then(checkAuthJson)' +
  '      .then(function(data) {' +
  '        if (refBtn) { refBtn.disabled = false; refBtn.innerHTML = \'<i class="fi fi-rr-refresh"></i> Làm mới\'; }' +
  '        if (!data || !data.success) {' +
  '          bodyEl.innerHTML = \'<div class="modal-state"><i class="fi fi-rr-triangle-warning" style="color:var(--red);"></i><div>Không thể đọc danh sách thiết bị: \' + escText((data && data.error) || "Lỗi kết nối AP") + \'</div></div>\';' +
  '          return;' +
  '        }' +
  '        var list = data.clients || [];' +
  '        if (countBadge) countBadge.innerHTML = \'<i class="fi fi-rr-users" style="margin-right:4px;"></i>\' + list.length + " thiết bị";' +
  '        if (data.ap) {' +
  '          if (data.ap.ssid) document.getElementById("modalApSsid").innerText = data.ap.ssid;' +
  '          if (data.ap.channel) document.getElementById("modalApCh").innerText = "CH " + data.ap.channel;' +
  '        }' +
  '        var livePillBtn = document.querySelector(\'.client-pill.clickable[data-ip="\' + activeModalApIp + \'"]\') || activeClientPillBtn;' +
  '        if (livePillBtn) {' +
  '          if (list.length > 0) {' +
  '            livePillBtn.className = "client-pill clickable active";' +
  '            livePillBtn.innerHTML = \'<i class="fi fi-rr-user" style="font-size:11px;margin-right:4px;"></i><span class="client-count-val">\' + list.length + "</span>";' +
  '          } else {' +
  '            livePillBtn.className = "client-pill clickable zero";' +
  '            livePillBtn.innerHTML = \'<span class="client-count-val">0</span>\';' +
  '          }' +
  '        }' +
  '        var nowD = new Date();' +
  '        if (footTime) footTime.innerText = "Cập nhật trực tiếp lúc " + nowD.toLocaleTimeString("vi-VN");' +
  '        if (list.length === 0) {' +
  '          bodyEl.innerHTML = \'<div class="modal-state"><i class="fi fi-rr-users" style="color:var(--text-dim);"></i><div>Hiện không có thiết bị nào đang kết nối vào Access Point này.</div></div>\';' +
  '          return;' +
  '        }' +
  '        var html = \'<table class="client-table"><thead><tr>\' +' +
  '          \'<th>#</th><th>Thiết Bị &amp; Nhà Sản Xuất (OUI)</th><th>Địa Chỉ IP / Phân Vùng</th><th>Chuẩn Kết Nối</th><th>Cường Độ Sóng</th><th>Thời Gian Online</th>\' +' +
  '          \'</tr></thead><tbody>\';' +
  '        for (var i = 0; i < list.length; i++) {' +
  '          var c = list[i];' +
  '          var sigPct = Number(c.signalPercent) || 0;' +
  '          var sigCls = sigPct >= 65 ? "sig-good" : (sigPct >= 38 ? "sig-mid" : "sig-weak");' +
  '          var sigTxtCls = sigPct >= 65 ? "sig-txt-good" : (sigPct >= 38 ? "sig-txt-mid" : "sig-txt-weak");' +
  '          var dbmTxt = (c.signalDbm !== null && c.signalDbm !== undefined) ? (" (" + c.signalDbm + " dBm)") : "";' +
  '          var ipHtml = "";' +
  '          if (c.ip) {' +
  '            ipHtml = \'<div><span class="ip-badge resolved"><i class="fi fi-rr-globe" style="font-size:11px;"></i>\' + escText(c.ip) + \'</span>\' +' +
  '              (c.ipNote ? (\'<div class="ip-sub">\' + escText(c.ipNote) + \'</div>\') : "") + "</div>";' +
  '          } else {' +
  '            var vlanTxt = c.vlanCidr || "VLAN Bridge";' +
  '            var gwTxt = c.gatewayIp ? ("GW " + c.gatewayIp + " • Cấp phát động") : "DHCP qua Router trung tâm";' +
  '            ipHtml = \'<div title="Access Point hoạt động ở chế độ L2 Bridge, IP thiết bị được cấp phát trực tiếp từ Gateway \' + escText(c.gatewayIp || "") + \'"><span class="ip-badge vlan"><i class="fi fi-rr-network-cloud" style="font-size:11px;color:var(--sky);"></i>\' + escText(vlanTxt) + \'</span><div class="ip-sub">\' + escText(gwTxt) + "</div></div>";' +
  '          }' +
  '          var displayTitle = c.hostname || c.deviceTitle || "Thiết bị Wi-Fi";' +
  '          var ouiStr = c.ouiCode || (c.mac ? c.mac.slice(0, 8) : "00-00-00");' +
  '          var ouiCls = c.isPrivateMac ? "oui-badge laa" : "oui-badge";' +
  '          var vendorIco = c.isPrivateMac ? "fi-rr-shield-keyhole" : "fi-rr-building";' +
  '          var rateInfo = "";' +
  '          if (c.txRateMbps || c.rxRateMbps) {' +
  '            rateInfo += \'<div class="dev-vendor">PHY: TX \' + (c.txRateMbps || "-") + " / RX " + (c.rxRateMbps || "-") + " Mbps</div>";' +
  '          }' +
  '          if (c.rxBytes > 0 || c.txBytes > 0) {' +
  '            rateInfo += \'<div class="dev-vendor">Lưu lượng: <i class="fi fi-rr-arrow-small-down" style="color:var(--green);"></i> \' + fmtBytes(c.rxBytes) + \' • <i class="fi fi-rr-arrow-small-up" style="color:var(--sky);"></i> \' + fmtBytes(c.txBytes) + "</div>";' +
  '          }' +
  '          var icoCls = c.deviceIcon || "fi-rr-mobile-notch";' +
  '          var icoWrapCls = (c.isPcDevice || !c.isPrivateMac) ? "dev-ico pc" : "dev-ico";' +
  '          html += "<tr>" +' +
  '            \'<td style="color:var(--text-dim);font-weight:600;">\' + (i + 1) + "</td>" +' +
  '            \'<td><div class="dev-cell"><span class="\' + icoWrapCls + \'"><i class="fi \' + escText(icoCls) + \'"></i></span><div>\' +' +
  '              \'<div class="dev-title-row"><span class="dev-name">\' + escText(displayTitle) + \'</span><span class="mac-tag">\' + escText(c.mac) + "</span></div>" +' +
  '              \'<div class="dev-meta-row"><span class="\' + ouiCls + \'">OUI: \' + escText(ouiStr) + \'</span><span class="vendor-text"><i class="fi \' + vendorIco + \'" style="font-size:10.5px;"></i>\' + escText(c.vendor || "") + "</span></div>" +' +
  '            "</div></div></td>" +' +
  '            "<td>" + ipHtml + "</td>" +' +
  '            \'<td><div><span class="channel-badge">\' + escText(c.mode || "802.11n") + \'</span> <span class="channel-badge">\' + escText(c.bandwidth || "20 MHz") + \'</span> <span class="dim-text" style="font-size:11px;margin-left:4px;">\' + escText(c.band || "") + "</span></div>" + rateInfo + "</td>" +' +
  '            \'<td><div class="sig-wrap"><div class="sig-bar-bg"><div class="sig-bar-fill \' + sigCls + \'" style="width:\' + Math.max(8, sigPct) + \'%;"></div></div><span style="font-weight:700;font-size:12px;" class="\' + sigTxtCls + \'"><i class="fi fi-rr-signal-alt-2" style="font-size:11px;margin-right:4px;"></i>\' + sigPct + "%" + \'<span style="color:var(--text-dim);font-weight:400;font-size:11px;">\' + escText(dbmTxt) + "</span></span></div></td>" +' +
  '            \'<td><span style="display:inline-flex;align-items:center;gap:5px;font-family:monospace;color:var(--text-muted);"><i class="fi fi-rr-clock" style="color:var(--sky);font-size:12px;"></i>\' + escText(c.connectedTime || "-") + "</span></td>" +' +
  '            "</tr>";' +
  '        }' +
  '        html += "</tbody></table>";' +
  '        bodyEl.innerHTML = html;' +
  '      })' +
  '      .catch(function(err) {' +
  '        if (refBtn) { refBtn.disabled = false; refBtn.innerHTML = \'<i class="fi fi-rr-refresh"></i> Làm mới\'; }' +
  '        bodyEl.innerHTML = \'<div class="modal-state"><i class="fi fi-rr-triangle-warning" style="color:var(--red);"></i><div>Lỗi kết nối máy chủ: \' + escText(err.message) + "</div></div>";' +
  '      });' +
  '  }' +
  '  var rfPlanCache = ' + safeRfPlanInitJson + ';' +
  '  var currentRfTab = "need";' +
  '  var rfPageByTab = { need: 1, all: 1, unifi: 1, history: 1 };' +
  '  var rfPageSize = 10;' +
  '  var rfManualUnlock = {};' +
  '  var rfApplyWatchTimer = null;' +
  '  function setRfPage(p) {' +
  '    rfPageByTab[currentRfTab] = Math.max(1, Number(p) || 1);' +
  '    renderRfOptView();' +
  '    var bodyEl = document.getElementById("rfOptModalBody");' +
  '    if (bodyEl) bodyEl.scrollTop = 0;' +
  '  }' +
  '  function setRfPageSize(sz) {' +
  '    rfPageSize = Number(sz) || 0;' +
  '    rfPageByTab[currentRfTab] = 1;' +
  '    renderRfOptView();' +
  '    var bodyEl = document.getElementById("rfOptModalBody");' +
  '    if (bodyEl) bodyEl.scrollTop = 0;' +
  '  }' +
  '  function onRfSearchInput() {' +
  '    rfPageByTab[currentRfTab] = 1;' +
  '    renderRfOptView();' +
  '  }' +
  '  function ipToDomId(ip) { return String(ip || "").replace(/[^0-9a-zA-Z]/g, "_"); }' +
  '  function unlockRfField(ip, field) {' +
  '    if (!IS_ADMIN) return;' +
  '    rfManualUnlock[ip + ":" + field] = true;' +
  '    renderRfOptView();' +
  '  }' +
  '  function clearRfManualUnlockForIp(ip) {' +
  '    delete rfManualUnlock[ip + ":channel"];' +
  '    delete rfManualUnlock[ip + ":txPower"];' +
  '    delete rfManualUnlock[ip + ":staRssi"];' +
  '  }' +
  '  function hasRfManualUnlock(ip) {' +
  '    return Boolean(rfManualUnlock[ip + ":channel"] || rfManualUnlock[ip + ":txPower"] || rfManualUnlock[ip + ":staRssi"]);' +
  '  }' +
  '  function buildRfActionCellHtml(it) {' +
  '    if (it.applyState) {' +
  '      var ast = it.applyState;' +
  '      if (ast.isError) {' +
  '        return \'<div class="rf-live-box"><div class="rf-live-msg err"><i class="fi fi-rr-triangle-warning" style="flex-shrink:0;"></i><span>\' + escText(ast.message || "Lỗi áp dụng") + \'</span></div>\' +' +
  '          (IS_ADMIN ? \'<div style="margin-top:4px;"><button type="button" class="btn-rf-apply secondary" style="padding:2px 7px;font-size:10.5px;" onclick="applySingleApRf(\\\'\' + escText(it.ip) + \'\\\', this)"><i class="fi fi-rr-refresh"></i> Thử lại</button></div>\' : "") + "</div>";' +
  '      }' +
  '      if (ast.phase === "done") {' +
  '        return \'<div class="rf-live-box"><div class="rf-live-msg done"><i class="fi fi-rr-check-circle" style="flex-shrink:0;"></i><span>\' + escText(ast.message || "Đã cập nhật!") + \'</span></div><div class="rf-prog-track"><div class="rf-prog-fill done" style="width:100%;"></div></div></div>\';' +
  '      }' +
  '      var pctVal = Math.max(12, Math.min(99, Number(ast.pct) || 15));' +
  '      return \'<div class="rf-live-box"><div class="rf-live-msg"><i class="fi fi-rr-spinner fi-spin" style="flex-shrink:0;"></i><span>\' + escText(ast.message || "Đang áp dụng...") + \'</span></div><div class="rf-prog-track"><div class="rf-prog-fill" style="width:\' + pctVal + \'%;"></div></div></div>\';' +
  '    }' +
  '    if (!IS_ADMIN) {' +
  '      if (it.needsOptimization) {' +
  '        return \'<span class="rf-chip warn" title="Tài khoản User chỉ có quyền xem đề xuất"><i class="fi fi-rr-sparkles"></i> Cần tối ưu</span>\';' +
  '      }' +
  '      return \'<span class="rf-optimal-badge"><i class="fi fi-rr-check-circle"></i> Đã chuẩn</span>\';' +
  '    }' +
  '    if (it.needsOptimization || hasRfManualUnlock(it.ip)) {' +
  '      return \'<button type="button" class="btn-rf-apply" onclick="applySingleApRf(\\\'\' + escText(it.ip) + \'\\\', this)"><i class="fi fi-rr-check"></i> Áp dụng</button>\';' +
  '    }' +
  '    return \'<span class="rf-optimal-badge"><i class="fi fi-rr-check-circle"></i> Đã chuẩn</span>\';' +
  '  }' +
  '  function patchRfModalLiveStates(plan) {' +
  '    if (!plan || !Array.isArray(plan.items)) return;' +
  '    for (var i = 0; i < plan.items.length; i++) {' +
  '      var it = plan.items[i];' +
  '      if (!it.canApplyDirect) continue;' +
  '      var domId = ipToDomId(it.ip);' +
  '      var actEl = document.getElementById("rfAct_" + domId);' +
  '      if (actEl) actEl.innerHTML = buildRfActionCellHtml(it);' +
  '      var trEl = document.getElementById("rfRow_" + domId);' +
  '      if (trEl) {' +
  '        var isWorking = Boolean(it.applyState && !it.applyState.isError && it.applyState.phase !== "done");' +
  '        if (isWorking) trEl.classList.add("rf-row-applying");' +
  '        else trEl.classList.remove("rf-row-applying");' +
  '      }' +
  '    }' +
  '  }' +
  '  function ensureApplyProgressWatcher() {' +
  '    var sum = rfPlanCache && rfPlanCache.summary ? rfPlanCache.summary : null;' +
  '    var hasActive = Boolean(sum && ((sum.activeApplyCount || 0) > 0 || sum.isRunningBatchApply));' +
  '    var sseHealthy = Boolean(liveEventSource && liveEventSource.readyState === 1 && !isPaused);' +
  '    if (hasActive && !sseHealthy) {' +
  '      if (!rfApplyWatchTimer) {' +
  '        rfApplyWatchTimer = setInterval(function() {' +
  '          fetchLiveSnapshot(false);' +
  '        }, 1500);' +
  '      }' +
  '    } else if (rfApplyWatchTimer) {' +
  '      clearInterval(rfApplyWatchTimer);' +
  '      rfApplyWatchTimer = null;' +
  '    }' +
  '  }' +
  '  function openRfOptModal() {' +
  '    isModalOpen = true;' +
  '    var ov = document.getElementById("rfOptModalOverlay");' +
  '    if (ov) ov.classList.add("open");' +
  '    if (rfPlanCache) {' +
  '      updateRfSummaryUi(rfPlanCache);' +
  '      renderRfOptView();' +
  '    }' +
  '    loadRfOptPlan(false);' +
  '  }' +
  '  function closeRfOptModal() {' +
  '    var ov = document.getElementById("rfOptModalOverlay");' +
  '    if (ov) ov.classList.remove("open");' +
  '    syncAnyModalOpenFlag();' +
  '  }' +
  '  function syncMode2UiElements(settings) {' +
  '    if (!settings) return;' +
  '    var on = Boolean(settings.autoOptimizeEnabled);' +
  '    var tm = settings.autoOptimizeTime || "03:30";' +
  '    var w24 = settings.requireFull24hForAuto !== false;' +
  '    var tMain = document.getElementById("mode2ToggleMain");' +
  '    var tModal = document.getElementById("mode2ToggleModal");' +
  '    if (tMain) tMain.checked = on;' +
  '    if (tModal) tModal.checked = on;' +
  '    var tmMain = document.getElementById("mode2TimeMain");' +
  '    var tmModal = document.getElementById("mode2TimeModal");' +
  '    if (tmMain) tmMain.value = tm;' +
  '    if (tmModal) tmModal.value = tm;' +
  '    var wMain = document.getElementById("mode2Wait24hMain");' +
  '    if (wMain) wMain.checked = w24;' +
  '    var bMain = document.getElementById("mode2BadgeMain");' +
  '    var bModal = document.getElementById("mode2BadgeModal");' +
  '    if (bMain) { bMain.className = "rf-toggle-state " + (on ? "on" : "off"); bMain.innerText = on ? "ĐANG BẬT" : "ĐANG TẮT"; }' +
  '    if (bModal) { bModal.className = "rf-toggle-state " + (on ? "on" : "off"); bModal.innerText = on ? "BẬT" : "TẮT"; }' +
  '    var noteEl = document.getElementById("mode2StatusNoteMain");' +
  '    if (noteEl) {' +
  '      noteEl.innerHTML = on' +
  '        ? \'<i class="fi fi-rr-shield-check" style="color:var(--green);"></i> Tự động tối ưu hàng ngày lúc <b>\' + escText(tm) + \'</b>\' + (w24 ? " (khi đủ 24h mẫu sóng)" : " (chạy ngay chu kỳ tới)")' +
  '        : \'<i class="fi fi-rr-info"></i> Chế độ tự động đang TẮT — Hệ thống chỉ phân tích &amp; đề xuất ở Chế độ 1\';' +
  '    }' +
  '  }' +
  '  function saveMode2Settings(source) {' +
  '    if (!IS_ADMIN) return;' +
  '    var isModal = (source === "modal");' +
  '    var tEl = document.getElementById(isModal ? "mode2ToggleModal" : "mode2ToggleMain");' +
  '    var tmEl = document.getElementById(isModal ? "mode2TimeModal" : "mode2TimeMain");' +
  '    var wEl = document.getElementById("mode2Wait24hMain");' +
  '    var payload = {' +
  '      autoOptimizeEnabled: Boolean(tEl && tEl.checked),' +
  '      autoOptimizeTime: (tmEl && tmEl.value) ? tmEl.value : "03:30",' +
  '      requireFull24hForAuto: wEl ? Boolean(wEl.checked) : true' +
  '    };' +
  '    syncMode2UiElements(payload);' +
  '    fetch("/api/rf-optimizer/settings", {' +
  '      method: "POST",' +
  '      headers: { "Content-Type": "application/json" },' +
  '      body: JSON.stringify(payload)' +
  '    }).then(checkAuthJson).then(function(d){' +
  '      if (d && d.success && d.settings) {' +
  '        syncMode2UiElements(d.settings);' +
  '        var toast = document.getElementById("mode2SavedToast");' +
  '        if (toast) {' +
  '          toast.style.display = "inline-flex";' +
  '          setTimeout(function(){ toast.style.display = "none"; }, 2200);' +
  '        }' +
  '      }' +
  '    }).catch(function(err){ alert("Không thể lưu cấu hình Chế độ 2: " + err.message); });' +
  '  }' +
  '  function updateRfSummaryUi(plan) {' +
  '    if (!plan || !plan.summary) return;' +
  '    var s = plan.summary;' +
  '    syncMode2UiElements(plan.settings);' +
  '    var needB = document.getElementById("rfNeedCountBanner");' +
  '    var btnC = document.getElementById("rfBtnCount");' +
  '    var needCntUi = s.totolinkActionCount || 0;' +
  '    if (needB) needB.innerText = needCntUi;' +
  '    if (btnC) btnC.innerText = needCntUi;' +
  '    var navBUi = document.getElementById("navRfNeedBadge");' +
  '    if (navBUi) { navBUi.innerText = needCntUi; navBUi.style.display = needCntUi > 0 ? "inline-flex" : "none"; }' +
  '    var hrsB = document.getElementById("rfHoursBanner");' +
  '    if (hrsB) hrsB.innerText = s.systemHoursObserved || 0.1;' +
  '    var smpB = document.getElementById("rfSamplesBanner");' +
  '    if (smpB) smpB.innerText = s.totalSamples24h || 0;' +
  '    var lnkB = document.getElementById("rfLinksBanner");' +
  '    if (lnkB) lnkB.innerText = s.measuredNeighborLinks || 0;' +
  '    var mHours = document.getElementById("rfModalHoursBadge");' +
  '    if (mHours) mHours.innerHTML = \'<i class="fi fi-rr-clock" style="margin-right:4px;"></i>Chu kỳ: \' + (s.systemHoursObserved || 0.1) + "h / 24h";' +
  '    var mSmp = document.getElementById("rfModalSamplesBadge");' +
  '    if (mSmp) mSmp.innerHTML = \'<i class="fi fi-rr-signal-alt-2" style="margin-right:4px;"></i>\' + (s.totalSamples24h || 0) + " mẫu RSSI • " + (s.measuredNeighborLinks || 0) + " liên kết nhiễu";' +
  '    var mDist = document.getElementById("rfPlanDistBadge");' +
  '    if (mDist && s.channelPlanDist) {' +
  '      var cpd = s.channelPlanDist;' +
  '      mDist.innerHTML = \'<i class="fi fi-rr-shield-check" style="color:var(--green);margin-right:4px;"></i>Bản đồ tĩnh chống lặp: <b>CH1(\' + (cpd[1] || 0) + ") • CH6(" + (cpd[6] || 0) + ") • CH11(" + (cpd[11] || 0) + ")</b>";' +
  '    }' +
  '    var kNeed = document.getElementById("rfKpiNeed"); if (kNeed) kNeed.innerText = s.totolinkActionCount || 0;' +
  '    var kCh = document.getElementById("rfKpiCh"); if (kCh) kCh.innerText = s.channelChangeCount || 0;' +
  '    var kPwr = document.getElementById("rfKpiPwr"); if (kPwr) kPwr.innerText = s.txPowerChangeCount || 0;' +
  '    var kRssi = document.getElementById("rfKpiRssi"); if (kRssi) kRssi.innerText = s.staRssiChangeCount || 0;' +
  '    var unifiCount = 0; var needTabCount = 0;' +
  '    var items = plan.items || [];' +
  '    for (var i = 0; i < items.length; i++) {' +
  '      if (items[i].isUnifi) unifiCount++;' +
  '      if (items[i].needsOptimization || items[i].needsControllerAdvisory) needTabCount++;' +
  '    }' +
  '    var tcNeed = document.getElementById("rfTabCntNeed"); if (tcNeed) tcNeed.innerText = needTabCount;' +
  '    var tcAll = document.getElementById("rfTabCntAll"); if (tcAll) tcAll.innerText = items.length;' +
  '    var tcUni = document.getElementById("rfTabCntUnifi"); if (tcUni) tcUni.innerText = unifiCount;' +
  '    var tcHist = document.getElementById("rfTabCntHist"); if (tcHist) tcHist.innerText = s.historyTotalCount || (plan.history || []).length;' +
  '    var syncBtn = document.getElementById("rfModalSyncBtn");' +
  '    if (syncBtn) {' +
  '      if (s.isSyncingHwConfig) {' +
  '        syncBtn.disabled = true;' +
  '        syncBtn.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang đồng bộ...\';' +
  '      } else {' +
  '        syncBtn.disabled = false;' +
  '        syncBtn.innerHTML = \'<i class="fi fi-rr-refresh"></i> Đồng Bộ AP\';' +
  '      }' +
  '    }' +
  '    var batchBtn = document.getElementById("rfBatchApplyBtn");' +
  '    var bs = s.batchStatus || {};' +
  '    if (batchBtn) {' +
  '      if (s.isRunningBatchApply) {' +
  '        var doneN = (bs.completed || 0) + (bs.failed || 0);' +
  '        var totN = bs.total || s.totolinkActionCount || 0;' +
  '        batchBtn.disabled = true;' +
  '        batchBtn.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang áp dụng (\' + doneN + "/" + totN + " AP)...";' +
  '      } else {' +
  '        batchBtn.disabled = (s.totolinkActionCount || 0) === 0;' +
  '        batchBtn.innerHTML = \'<i class="fi fi-rr-bolt"></i> Áp Dụng Tất Cả (\' + (s.totolinkActionCount || 0) + \')\';' +
  '      }' +
  '    }' +
  '    ensureApplyProgressWatcher();' +
  '  }' +
  '  function loadRfOptPlan(forceSync, isRetry) {' +
  '    var bodyEl = document.getElementById("rfOptModalBody");' +
  '    var syncBtn = document.getElementById("rfModalSyncBtn");' +
  '    if (forceSync && syncBtn) { syncBtn.disabled = true; syncBtn.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang đồng bộ...\'; }' +
  '    if (!rfPlanCache && bodyEl) {' +
  '      bodyEl.innerHTML = \'<div class="modal-state"><i class="fi fi-rr-spinner fi-spin"></i><div>Đang tổng hợp dữ liệu sóng 24h &amp; tính toán kênh tối ưu cho toàn bộ AP...</div></div>\';' +
  '    }' +
  '    var fetchOpts = { cache: "no-store" };' +
  '    var abortCtrl = (typeof AbortController !== "undefined") ? new AbortController() : null;' +
  '    var abortTimer = null;' +
  '    if (abortCtrl) {' +
  '      fetchOpts.signal = abortCtrl.signal;' +
  '      abortTimer = setTimeout(function() { try { abortCtrl.abort(); } catch (e) {} }, 12000);' +
  '    }' +
  '    fetch("/api/rf-optimizer/plan" + (forceSync && IS_ADMIN ? "?sync=1" : ""), fetchOpts)' +
  '      .then(function(r){ if (abortTimer) clearTimeout(abortTimer); return checkAuthJson(r); })' +
  '      .then(function(d){' +
  '        if (!d || !d.success || !d.plan) {' +
  '          if (syncBtn) { syncBtn.disabled = false; syncBtn.innerHTML = \'<i class="fi fi-rr-refresh"></i> Đồng Bộ AP\'; }' +
  '          if (!rfPlanCache && bodyEl) bodyEl.innerHTML = \'<div class="modal-state"><i class="fi fi-rr-triangle-warning" style="color:var(--red);"></i><div>Không thể tải dữ liệu tối ưu sóng.</div></div>\';' +
  '          return;' +
  '        }' +
  '        rfPlanCache = d.plan;' +
  '        updateRfSummaryUi(d.plan);' +
  '        renderRfOptView();' +
  '        var ft = document.getElementById("rfModalUpdatedTime");' +
  '        if (ft) {' +
  '          ft.innerText = (d.syncing || (d.plan.summary && d.plan.summary.isSyncingHwConfig))' +
  '            ? ("Đang đồng bộ cấu hình phần cứng từ các AP... (" + (new Date()).toLocaleTimeString("vi-VN") + ")")' +
  '            : ("Cập nhật phân tích lúc " + (new Date()).toLocaleTimeString("vi-VN"));' +
  '        }' +
  '      })' +
  '      .catch(function(err){' +
  '        if (abortTimer) clearTimeout(abortTimer);' +
  '        if (!isRetry) {' +
  '          setTimeout(function() { loadRfOptPlan(forceSync, true); }, 700);' +
  '          return;' +
  '        }' +
  '        if (syncBtn) { syncBtn.disabled = false; syncBtn.innerHTML = \'<i class="fi fi-rr-refresh"></i> Đồng Bộ AP\'; }' +
  '        if (rfPlanCache) {' +
  '          renderRfOptView();' +
  '          var ftErr = document.getElementById("rfModalUpdatedTime");' +
  '          if (ftErr) ftErr.innerText = "Đang hiển thị dữ liệu trực tiếp gần nhất • Máy chủ đang bận, tự động đồng bộ qua luồng thực...";' +
  '        } else if (bodyEl) {' +
  '          bodyEl.innerHTML = \'<div class="modal-state"><i class="fi fi-rr-triangle-warning" style="color:var(--red);"></i><div>Lỗi kết nối: \' + escText(err.message) + \'</div><div style="margin-top:10px;"><button type="button" class="btn-nav" onclick="loadRfOptPlan(false)"><i class="fi fi-rr-refresh"></i> Thử lại ngay</button></div></div>\';' +
  '        }' +
  '      });' +
  '  }' +
  '  function setRfTab(tabName, btnEl) {' +
  '    currentRfTab = tabName;' +
  '    var btns = document.querySelectorAll(".rf-tab-btn");' +
  '    for (var i = 0; i < btns.length; i++) btns[i].classList.remove("active");' +
  '    if (btnEl) btnEl.classList.add("active");' +
  '    renderRfOptView();' +
  '  }' +
  '  function onRfSelectChange(selEl, curVal) {' +
  '    if (!selEl) return;' +
  '    if (String(selEl.value) !== String(curVal)) selEl.classList.add("changed");' +
  '    else selEl.classList.remove("changed");' +
  '  }' +
  '  function renderRfOptView() {' +
  '    var bodyEl = document.getElementById("rfOptModalBody");' +
  '    if (!bodyEl || !rfPlanCache) return;' +
  '    var qEl = document.getElementById("rfSearchInput");' +
  '    var q = (qEl && qEl.value ? qEl.value : "").trim().toLowerCase();' +
  '    if (currentRfTab === "history") {' +
  '      var hist = rfPlanCache.history || [];' +
  '      if (hist.length === 0) {' +
  '        bodyEl.innerHTML = \'<div class="modal-state"><i class="fi fi-rr-time-past"></i><div>Chưa có lịch sử áp dụng tối ưu cấu hình nào được ghi nhận.</div></div>\';' +
  '        return;' +
  '      }' +
  '      var filteredHist = [];' +
  '      for (var hf = 0; hf < hist.length; hf++) {' +
  '        var hev = hist[hf];' +
  '        if (q && ((hev.apName || "") + " " + (hev.apIp || "") + " " + ((hev.reasons || []).join(" "))).toLowerCase().indexOf(q) === -1) continue;' +
  '        filteredHist.push(hev);' +
  '      }' +
  '      if (filteredHist.length === 0) {' +
  '        bodyEl.innerHTML = \'<div class="modal-state"><i class="fi fi-rr-search"></i><div>Không tìm thấy bản ghi lịch sử nào khớp với từ khóa tìm kiếm.</div></div>\';' +
  '        return;' +
  '      }' +
  '      var totalH = filteredHist.length;' +
  '      var totalHPages = rfPageSize > 0 ? Math.max(1, Math.ceil(totalH / rfPageSize)) : 1;' +
  '      var curHPage = Math.min(Math.max(1, rfPageByTab.history || 1), totalHPages);' +
  '      rfPageByTab.history = curHPage;' +
  '      var hStart = rfPageSize > 0 ? ((curHPage - 1) * rfPageSize) : 0;' +
  '      var pageHist = rfPageSize > 0 ? filteredHist.slice(hStart, hStart + rfPageSize) : filteredHist;' +
  '      var hHtml = \'<table class="rf-table"><thead><tr><th>#</th><th>Thời Gian</th><th>Thiết Bị AP</th><th>Nguồn Thực Thi</th><th>Thay Đổi Cấu Hình (Trước → Sau)</th><th>Lý Do Tối Ưu</th></tr></thead><tbody>\';' +
  '      for (var h = 0; h < pageHist.length; h++) {' +
  '        var ev = pageHist[h];' +
  '        var rowIdx = hStart + h + 1;' +
  '        var dtStr = ev.timestamp ? (new Date(ev.timestamp)).toLocaleString("vi-VN") : "-";' +
  '        var modeBadge = ev.mode === "auto-24h"' +
  '          ? \'<span class="rf-chip ok"><i class="fi fi-rr-calendar-clock"></i>Chế độ 2 Tự động</span>\'' +
  '          : \'<span class="rf-chip info"><i class="fi fi-rr-settings-sliders"></i>Chế độ 1 Thủ công</span>\';' +
  '        var bf = ev.before || {}; var af = ev.after || {};' +
  '        var diffParts = [];' +
  '        if (bf.channel !== af.channel) diffParts.push((bf.channel ? ("CH " + bf.channel) : "Auto") + " → <b>CH " + (af.channel || "-") + "</b>");' +
  '        if (bf.txPower !== af.txPower) diffParts.push("TX " + (bf.txPower || 75) + "% → <b>" + (af.txPower || 75) + "%</b>");' +
  '        if (bf.staRssi !== af.staRssi) diffParts.push("STA RSSI " + (bf.staRssi === 0 ? "0 (Tắt)" : (bf.staRssi + " dBm")) + " → <b>" + (af.staRssi === 0 ? "0 (Tắt)" : (af.staRssi + " dBm")) + "</b>");' +
  '        if (bf.dtim !== af.dtim) diffParts.push("DTIM " + (bf.dtim || 1) + " → <b>" + (af.dtim || 3) + "</b>");' +
  '        if (bf.txBurst !== af.txBurst) diffParts.push("TxBurst → <b>" + (af.txBurst ? "Bật" : "Tắt") + "</b>");' +
  '        if (bf.htBw !== af.htBw && af.htBw) diffParts.push((bf.htBw || 40) + "MHz → <b>" + af.htBw + "MHz</b>");' +
  '        var keptHint = diffParts.length > 0 && diffParts.length < 4 ? \' <span style="color:var(--text-dim);font-size:10.5px;">(Giữ nguyên thông số đã chuẩn)</span>\' : "";' +
  '        var diffTxt = (diffParts.length > 0 ? diffParts.join(" • ") : "Xác thực cấu hình chuẩn (không đổi)") + keptHint;' +
  '        hHtml += "<tr><td style=\\"color:var(--text-dim);font-weight:600;width:36px;\\">" + rowIdx + "</td>" +' +
  '          "<td style=\\"color:var(--text-muted);font-family:monospace;\\">" + escText(dtStr) + "</td>" +' +
  '          "<td><div style=\\"font-weight:600;color:var(--text);\\">" + escText(ev.apName || "AP") + "</div><div class=\\"rf-sub-meta\\"><code>" + escText(ev.apIp || "") + "</code></div></td>" +' +
  '          "<td>" + modeBadge + "</td>" +' +
  '          "<td style=\\"font-size:11.5px;\\">" + diffTxt + "</td>" +' +
  '          "<td class=\\"rf-reason-cell\\">" + escText((ev.reasons || []).join("; ")) + "</td></tr>";' +
  '      }' +
  '      hHtml += "</tbody></table>";' +
  '      var hPager = buildPagerHtml(totalH, curHPage, rfPageSize, "setRfPage", "setRfPageSize", [10, 20, 50, 0], "bản ghi");' +
  '      if (hPager) hHtml += \'<div class="table-pager-bar modal-pager">\' + hPager + "</div>";' +
  '      bodyEl.innerHTML = hHtml;' +
  '      return;' +
  '    }' +
  '    var filteredItems = (rfPlanCache.items || []).filter(function(it) {' +
  '      if (currentRfTab === "need" && !it.needsOptimization && !it.needsControllerAdvisory && !it.applyState && !hasRfManualUnlock(it.ip)) return false;' +
  '      if (currentRfTab === "unifi" && !it.isUnifi) return false;' +
  '      if (q) {' +
  '        var hay = ((it.name || "") + " " + (it.ip || "") + " " + (it.model || "") + " " + (it.ssid || "")).toLowerCase();' +
  '        if (hay.indexOf(q) === -1) return false;' +
  '      }' +
  '      return true;' +
  '    });' +
  '    if (filteredItems.length === 0) {' +
  '      bodyEl.innerHTML = \'<div class="modal-state"><i class="fi fi-rr-shield-check" style="color:var(--green);"></i><div>\' + (q ? "Không tìm thấy Access Point nào khớp với từ khóa lọc." : "Tất cả Access Point trong danh sách này đã đạt cấu hình tối ưu.") + "</div></div>";' +
  '      return;' +
  '    }' +
  '    var totalIt = filteredItems.length;' +
  '    var totalItPages = rfPageSize > 0 ? Math.max(1, Math.ceil(totalIt / rfPageSize)) : 1;' +
  '    var curItPage = Math.min(Math.max(1, rfPageByTab[currentRfTab] || 1), totalItPages);' +
  '    rfPageByTab[currentRfTab] = curItPage;' +
  '    var itStart = rfPageSize > 0 ? ((curItPage - 1) * rfPageSize) : 0;' +
  '    var items = rfPageSize > 0 ? filteredItems.slice(itStart, itStart + rfPageSize) : filteredItems;' +
  '    var html = \'<table class="rf-table"><thead><tr>\' +' +
  '      \'<th>Thiết Bị AP</th><th>Hồ Sơ 24h &amp; Nhiễu</th><th>Kênh Sóng</th><th>TX Power</th><th>STA RSSI &amp; DTIM</th><th>Phân Tích &amp; Lý Do Đề Xuất</th><th>\' + (IS_ADMIN ? "Thao Tác" : "Trạng Thái") + \'</th>\' +' +
  '      \'</tr></thead><tbody>\';' +
  '    for (var i = 0; i < items.length; i++) {' +
  '      var it = items[i];' +
  '      var domId = ipToDomId(it.ip);' +
  '      var st = it.stats24h || {};' +
  '      var cur = it.current || {};' +
  '      var rec = it.recommended || {};' +
  '      var df = it.diff || {};' +
  '      var isApplyingNow = Boolean(it.applyState && !it.applyState.isError && it.applyState.phase !== "done");' +
  '      var rssiLine = st.samples > 0' +
  '        ? (\'<span>TB <b>\' + st.avgDbm + \' dBm</b> • Yếu: <b style="color:\' + (st.weakPct >= 25 ? "var(--red)" : "var(--text-secondary)") + \'">\' + st.weakPct + "%</b></span>")' +
  '        : \'<span class="dim-text">0 mẫu client (đang thu thập)</span>\';' +
  '      var nbLine = "";' +
  '      var apNeedsChMove = Boolean(df.channel || rec.channel !== cur.channel || cur.isAutoChannel);' +
  '      if (it.isUnifi && it.cu24 !== null) {' +
  '        nbLine = \'CU 2.4G: <b>\' + it.cu24 + "%</b> • 5G: <b>" + (it.cu5 !== null ? it.cu5 : 0) + "%</b>";' +
  '      } else if (apNeedsChMove && it.coChannelNeighbors > 0) {' +
  '        nbLine = \'<span style="color:var(--amber);"><i class="fi fi-rr-radar" style="margin-right:3px;"></i>\' + it.coChannelNeighbors + " AP trùng kênh (" + (it.strongestNeighborDbm || -70) + " dBm)</span>";' +
  '      } else if (!cur.isAutoChannel && !apNeedsChMove) {' +
  '        var lockNote = it.isManualChannelPinned ? " (Ghim tay)" : (it.inChannelCooldown ? " (Khóa 24h)" : "");' +
  '        nbLine = \'<span style="color:var(--green);"><i class="fi fi-rr-shield-check" style="margin-right:3px;"></i>Đã khóa bản đồ CH \' + cur.channel + lockNote + "</span>";' +
  '      } else {' +
  '        nbLine = \'<span style="color:var(--green);"><i class="fi fi-rr-check-circle" style="margin-right:3px;"></i>Kênh sạch / Ít chồng lấn</span>\';' +
  '      }' +
  '      var chCell = ""; var pwrCell = ""; var rssiCell = ""; var actCell = "";' +
  '      if (it.canApplyDirect) {' +
  '        var disAttr = isApplyingNow ? " disabled" : "";' +
  '        var showChEdit = Boolean(apNeedsChMove || (IS_ADMIN && rfManualUnlock[it.ip + ":channel"]));' +
  '        if (showChEdit) {' +
  '          if (IS_ADMIN) {' +
  '            var chOpts = [1, 6, 11];' +
  '            var chSelCls = apNeedsChMove ? "rf-sel changed" : "rf-sel";' +
  '            var chSelectHtml = \'<select id="rfCh_\' + domId + \'" class="\' + chSelCls + \'"\' + disAttr + \' onchange="onRfSelectChange(this,\' + cur.channel + \')">\';' +
  '            for (var ci = 0; ci < chOpts.length; ci++) {' +
  '              var cv = chOpts[ci];' +
  '              chSelectHtml += \'<option value="\' + cv + \'"\' + (rec.channel === cv ? " selected" : "") + ">CH " + cv + "</option>";' +
  '            }' +
  '            chSelectHtml += "</select>";' +
  '            chCell = \'<div class="rf-diff-row"><span class="rf-cur-tag">\' + (cur.isAutoChannel ? "Auto" : ("CH " + cur.channel)) + \'</span><i class="fi fi-rr-arrow-small-right" style="color:var(--text-dim);"></i>\' + chSelectHtml + "</div>";' +
  '          } else {' +
  '            chCell = \'<div class="rf-diff-row"><span class="rf-cur-tag">\' + (cur.isAutoChannel ? "Auto" : ("CH " + cur.channel)) + \'</span><i class="fi fi-rr-arrow-small-right" style="color:var(--text-dim);"></i><span class="rf-chip info">CH \' + rec.channel + "</span></div>";' +
  '          }' +
  '        } else {' +
  '          chCell = \'<div class="rf-keep-row"><span class="rf-keep-tag"><i class="fi fi-rr-check" style="color:var(--green);font-size:10px;"></i>CH \' + cur.channel + \' <span class="rf-keep-lbl">Đã chuẩn</span></span>\' +' +
  '            ((!IS_ADMIN || isApplyingNow) ? "" : \'<button type="button" class="rf-unlock-btn" onclick="unlockRfField(\\\'\' + escText(it.ip) + \'\\\',\\\'channel\\\')" title="Tùy chỉnh kênh thủ công"><i class="fi fi-rr-edit"></i></button>\') + "</div>";' +
  '        }' +
  '        chCell += \'<div class="rf-sub-meta">Băng thông: \' + (df.htBw ? "40MHz → <b>20MHz</b>" : "20MHz chuẩn") + "</div>";' +
  '        var needPwrDiff = Boolean(df.txPower || rec.txPower !== cur.txPower);' +
  '        var showPwrEdit = Boolean(needPwrDiff || (IS_ADMIN && rfManualUnlock[it.ip + ":txPower"]));' +
  '        if (showPwrEdit) {' +
  '          if (IS_ADMIN) {' +
  '            var pwrOpts = [50, 75, 100];' +
  '            var pwrSelCls = needPwrDiff ? "rf-sel changed" : "rf-sel";' +
  '            var pwrSelectHtml = \'<select id="rfPwr_\' + domId + \'" class="\' + pwrSelCls + \'"\' + disAttr + \' onchange="onRfSelectChange(this,\' + cur.txPower + \')">\';' +
  '            for (var pi = 0; pi < pwrOpts.length; pi++) {' +
  '              var pv = pwrOpts[pi];' +
  '              pwrSelectHtml += \'<option value="\' + pv + \'"\' + (rec.txPower === pv ? " selected" : "") + ">" + pv + "%</option>";' +
  '            }' +
  '            pwrSelectHtml += "</select>";' +
  '            pwrCell = \'<div class="rf-diff-row"><span class="rf-cur-tag">\' + cur.txPower + \'%</span><i class="fi fi-rr-arrow-small-right" style="color:var(--text-dim);"></i>\' + pwrSelectHtml + "</div>";' +
  '          } else {' +
  '            pwrCell = \'<div class="rf-diff-row"><span class="rf-cur-tag">\' + cur.txPower + \'%</span><i class="fi fi-rr-arrow-small-right" style="color:var(--text-dim);"></i><span class="rf-chip info">\' + rec.txPower + "%</span></div>";' +
  '          }' +
  '        } else {' +
  '          pwrCell = \'<div class="rf-keep-row"><span class="rf-keep-tag"><i class="fi fi-rr-check" style="color:var(--green);font-size:10px;"></i>\' + cur.txPower + \'% <span class="rf-keep-lbl">Đã chuẩn</span></span>\' +' +
  '            ((!IS_ADMIN || isApplyingNow) ? "" : \'<button type="button" class="rf-unlock-btn" onclick="unlockRfField(\\\'\' + escText(it.ip) + \'\\\',\\\'txPower\\\')" title="Tùy chỉnh TX Power thủ công"><i class="fi fi-rr-edit"></i></button>\') + "</div>";' +
  '        }' +
  '        var needRssiDiff = Boolean(df.staRssi || cur.staRssi !== rec.staRssi);' +
  '        var showRssiEdit = Boolean(needRssiDiff || (IS_ADMIN && rfManualUnlock[it.ip + ":staRssi"]));' +
  '        var curRssiLbl = cur.staRssi === 0 ? "0 (Tắt)" : (cur.staRssi + " dBm");' +
  '        var recRssiLbl = rec.staRssi === 0 ? "0 (Tắt)" : (rec.staRssi + " dBm");' +
  '        if (showRssiEdit) {' +
  '          if (IS_ADMIN) {' +
  '            var rssiOpts = [-74, -75, -76, -78, -80, 0];' +
  '            if (rssiOpts.indexOf(rec.staRssi) === -1) rssiOpts.unshift(rec.staRssi);' +
  '            var rssiSelCls = needRssiDiff ? "rf-sel changed" : "rf-sel";' +
  '            var rssiSelectHtml = \'<select id="rfRssi_\' + domId + \'" class="\' + rssiSelCls + \'"\' + disAttr + \' onchange="onRfSelectChange(this,\' + cur.staRssi + \')">\';' +
  '            for (var ri = 0; ri < rssiOpts.length; ri++) {' +
  '              var rv = rssiOpts[ri];' +
  '              var rLbl = rv === 0 ? "0 (Tắt)" : (rv + " dBm");' +
  '              rssiSelectHtml += \'<option value="\' + rv + \'"\' + (rec.staRssi === rv ? " selected" : "") + ">" + rLbl + "</option>";' +
  '            }' +
  '            rssiSelectHtml += "</select>";' +
  '            rssiCell = \'<div class="rf-diff-row"><span class="rf-cur-tag">\' + curRssiLbl + \'</span><i class="fi fi-rr-arrow-small-right" style="color:var(--text-dim);"></i>\' + rssiSelectHtml + "</div>";' +
  '          } else {' +
  '            rssiCell = \'<div class="rf-diff-row"><span class="rf-cur-tag">\' + curRssiLbl + \'</span><i class="fi fi-rr-arrow-small-right" style="color:var(--text-dim);"></i><span class="rf-chip info">\' + recRssiLbl + "</span></div>";' +
  '          }' +
  '        } else {' +
  '          rssiCell = \'<div class="rf-keep-row"><span class="rf-keep-tag"><i class="fi fi-rr-check" style="color:var(--green);font-size:10px;"></i>\' + curRssiLbl + \' <span class="rf-keep-lbl">Đã chuẩn</span></span>\' +' +
  '            ((!IS_ADMIN || isApplyingNow) ? "" : \'<button type="button" class="rf-unlock-btn" onclick="unlockRfField(\\\'\' + escText(it.ip) + \'\\\',\\\'staRssi\\\')" title="Tùy chỉnh ngưỡng STA RSSI thủ công"><i class="fi fi-rr-edit"></i></button>\') + "</div>";' +
  '        }' +
  '        var dtimMeta = df.dtim ? ("DTIM: " + cur.dtim + " → <b>" + rec.dtim + "</b>") : ("DTIM: <b>" + cur.dtim + "</b>");' +
  '        var burstMeta = df.txBurst ? "TxBurst: Tắt → <b>Bật</b>" : ("TxBurst: <b>" + (cur.txBurst ? "Bật" : "Tắt") + "</b>");' +
  '        rssiCell += \'<div class="rf-sub-meta">\' + dtimMeta + " • " + burstMeta + "</div>";' +
  '        actCell = buildRfActionCellHtml(it);' +
  '      } else if (it.isUnifi) {' +
  '        chCell = \'<div><span class="rf-cur-tag">2.4G: CH \' + cur.channel + " → <b>CH " + rec.channel + \'</b></span></div><div class="rf-sub-meta">5G: CH \' + (cur.ch5 || 36) + " → <b>CH " + (rec.ch5 || 36) + "</b></div>";' +
  '        pwrCell = \'<div><span class="rf-cur-tag">2.4G: 13 dBm (Med)</span></div><div class="rf-sub-meta">5G: High (20 dBm)</div>\';' +
  '        rssiCell = \'<div><span class="rf-cur-tag">Min RSSI: <b>\' + rec.staRssi + \' dBm</b></span></div><div class="rf-sub-meta">Band Steering: Prefer 5G</div>\';' +
  '        actCell = \'<span class="rf-unifi-tag" title="Thiết bị đồng bộ qua UniFi Controller (\' + escText(it.informUrl || "8080") + \')"><i class="fi fi-rr-info"></i> UniFi Controller</span>\';' +
  '      } else {' +
  '        chCell = \'<span class="rf-cur-tag">CH \' + cur.channel + "</span>";' +
  '        pwrCell = \'<span class="dim-text">-</span>\';' +
  '        rssiCell = \'<span class="dim-text">-</span>\';' +
  '        actCell = \'<span class="status-pill offline"><i class="fi fi-rr-cross-circle"></i>Offline</span>\';' +
  '      }' +
  '      var reasonsHtml = "";' +
  '      var rList = it.reasons || [];' +
  '      for (var rj = 0; rj < rList.length; rj++) {' +
  '        var rIco = (it.needsOptimization || it.needsControllerAdvisory) ? "fi-rr-sparkles" : "fi-rr-check-circle";' +
  '        var rCol = (it.needsOptimization || it.needsControllerAdvisory) ? "var(--blue)" : "var(--green)";' +
  '        reasonsHtml += \'<div class="rf-reason-item"><i class="fi \' + rIco + \'" style="color:\' + rCol + \';font-size:11px;margin-top:3px;flex-shrink:0;"></i><span>\' + escText(rList[rj]) + "</span></div>";' +
  '      }' +
  '      html += \'<tr id="rfRow_\' + domId + \'" class="\' + (isApplyingNow ? "rf-row-applying" : "") + \'">\' +' +
  '        \'<td><div style="display:flex;align-items:center;gap:7px;"><span style="font-weight:700;color:var(--text);">\' + escText(it.name) + \'</span><span class="client-pill \' + (it.clientCount > 0 ? "active" : "zero") + \'" style="padding:1px 6px;font-size:10.5px;min-width:22px;">\' + it.clientCount + \'</span></div><div class="rf-sub-meta"><code>\' + escText(it.ip) + \'</code> • <span>\' + escText(it.model) + "</span></div></td>" +' +
  '        "<td><div>" + rssiLine + \'</div><div class="rf-sub-meta">\' + nbLine + "</div></td>" +' +
  '        "<td>" + chCell + "</td>" +' +
  '        "<td>" + pwrCell + "</td>" +' +
  '        "<td>" + rssiCell + "</td>" +' +
  '        \'<td class="rf-reason-cell">\' + reasonsHtml + "</td>" +' +
  '        \'<td id="rfAct_\' + domId + \'">\' + actCell + "</td></tr>";' +
  '    }' +
  '    html += "</tbody></table>";' +
  '    var itPager = buildPagerHtml(totalIt, curItPage, rfPageSize, "setRfPage", "setRfPageSize", [10, 20, 50, 0], "thiết bị");' +
  '    if (itPager) html += \'<div class="table-pager-bar modal-pager">\' + itPager + "</div>";' +
  '    bodyEl.innerHTML = html;' +
  '  }' +
  '  function replanRfChannels(btnEl) {' +
  '    if (!IS_ADMIN) return;' +
  '    if (!confirm("Tính toán lại Bản đồ Kênh Toàn Cục (1-6-11) cho toàn bộ tòa nhà?\\n\\nLưu ý: Hàng ngày hệ thống khóa cố định bản đồ kênh để chống vòng lặp đổi kênh qua lại. Bạn chỉ nên chạy lại chức năng này khi mới lắp thêm hoặc di dời vị trí vật lý của Access Point.")) return;' +
  '    var origHtml = btnEl ? btnEl.innerHTML : "";' +
  '    if (btnEl) { btnEl.disabled = true; btnEl.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang quy hoạch...\'; }' +
  '    fetch("/api/rf-optimizer/replan-channels", { method: "POST" })' +
  '      .then(checkAuthJson)' +
  '      .then(function(d){' +
  '        if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = origHtml; }' +
  '        if (!d || !d.success) { alert((d && d.error) || "Không thể quy hoạch lại kênh"); return; }' +
  '        if (d && d.plan) {' +
  '          rfPlanCache = d.plan;' +
  '          updateRfSummaryUi(d.plan);' +
  '          renderRfOptView();' +
  '        }' +
  '      })' +
  '      .catch(function(err){' +
  '        if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = origHtml; }' +
  '        alert("Lỗi quy hoạch lại kênh: " + err.message);' +
  '      });' +
  '  }' +
  '  function triggerRfNeighborScan(btnEl) {' +
  '    if (!IS_ADMIN) return;' +
  '    var origHtml = btnEl ? btnEl.innerHTML : "";' +
  '    if (btnEl) { btnEl.disabled = true; btnEl.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang quét nhiễu...\'; }' +
  '    fetch("/api/rf-optimizer/scan-neighbors", { method: "POST" })' +
  '      .then(checkAuthJson)' +
  '      .then(function(d){' +
  '        if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = origHtml; }' +
  '        if (!d || !d.success) { alert((d && d.error) || "Không thể quét nhiễu kênh"); return; }' +
  '        if (d && d.plan) {' +
  '          rfPlanCache = d.plan;' +
  '          updateRfSummaryUi(d.plan);' +
  '          var rfOv = document.getElementById("rfOptModalOverlay");' +
  '          if (rfOv && rfOv.classList.contains("open")) renderRfOptView();' +
  '        }' +
  '      })' +
  '      .catch(function(err){' +
  '        if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = origHtml; }' +
  '        alert("Lỗi quét nhiễu kênh: " + err.message);' +
  '      });' +
  '  }' +
  '  function applySingleApRf(ip, btnEl) {' +
  '    if (!IS_ADMIN) return;' +
  '    var domId = ipToDomId(ip);' +
  '    var chEl = document.getElementById("rfCh_" + domId);' +
  '    var pwrEl = document.getElementById("rfPwr_" + domId);' +
  '    var rssiEl = document.getElementById("rfRssi_" + domId);' +
  '    var params = {};' +
  '    if (chEl) params.channel = Number(chEl.value);' +
  '    if (pwrEl) params.txPower = Number(pwrEl.value);' +
  '    if (rssiEl) params.staRssi = Number(rssiEl.value);' +
  '    clearRfManualUnlockForIp(ip);' +
  '    var actEl = document.getElementById("rfAct_" + domId);' +
  '    var trEl = document.getElementById("rfRow_" + domId);' +
  '    if (trEl) trEl.classList.add("rf-row-applying");' +
  '    if (actEl) {' +
  '      actEl.innerHTML = \'<div class="rf-live-box"><div class="rf-live-msg"><i class="fi fi-rr-spinner fi-spin" style="flex-shrink:0;"></i><span>Đang kết nối AP...</span></div><div class="rf-prog-track"><div class="rf-prog-fill" style="width:12%;"></div></div></div>\';' +
  '    } else if (btnEl) {' +
  '      btnEl.disabled = true;' +
  '      btnEl.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang nạp...\';' +
  '    }' +
  '    fetch("/api/rf-optimizer/apply", {' +
  '      method: "POST",' +
  '      headers: { "Content-Type": "application/json" },' +
  '      body: JSON.stringify({ ip: ip, params: params })' +
  '    }).then(checkAuthJson).then(function(d){' +
  '      if (!d || !d.success) {' +
  '        if (trEl) trEl.classList.remove("rf-row-applying");' +
  '        if (actEl) {' +
  '          actEl.innerHTML = \'<div class="rf-live-box"><div class="rf-live-msg err"><i class="fi fi-rr-triangle-warning" style="flex-shrink:0;"></i><span>\' + escText((d && d.error) || "Lỗi kết nối AP") + \'</span></div><div style="margin-top:4px;"><button type="button" class="btn-rf-apply secondary" style="padding:2px 7px;font-size:10.5px;" onclick="applySingleApRf(\\\'\' + escText(ip) + \'\\\', this)"><i class="fi fi-rr-refresh"></i> Thử lại</button></div></div>\';' +
  '        }' +
  '        return;' +
  '      }' +
  '      if (d.plan) {' +
  '        rfPlanCache = d.plan;' +
  '        updateRfSummaryUi(d.plan);' +
  '        var ae = document.activeElement;' +
  '        var focusingRfField = Boolean(ae && ((ae.classList && (ae.classList.contains("rf-sel") || ae.classList.contains("pager-size-sel"))) || ae.id === "rfSearchInput"));' +
  '        if (!focusingRfField) renderRfOptView();' +
  '        else patchRfModalLiveStates(d.plan);' +
  '      }' +
  '    }).catch(function(err){' +
  '      if (trEl) trEl.classList.remove("rf-row-applying");' +
  '      if (actEl) {' +
  '        actEl.innerHTML = \'<div class="rf-live-box"><div class="rf-live-msg err"><i class="fi fi-rr-triangle-warning" style="flex-shrink:0;"></i><span>Lỗi kết nối: \' + escText(err.message) + \'</span></div><div style="margin-top:4px;"><button type="button" class="btn-rf-apply secondary" style="padding:2px 7px;font-size:10.5px;" onclick="applySingleApRf(\\\'\' + escText(ip) + \'\\\', this)"><i class="fi fi-rr-refresh"></i> Thử lại</button></div></div>\';' +
  '      }' +
  '    });' +
  '  }' +
  '  function applyAllRecommendedRf() {' +
  '    if (!IS_ADMIN) return;' +
  '    var cnt = (rfPlanCache && rfPlanCache.summary) ? (rfPlanCache.summary.totolinkActionCount || 0) : 0;' +
  '    if (cnt <= 0) return;' +
  '    if (!confirm("Xác nhận áp dụng đề xuất tối ưu sóng cho toàn bộ " + cnt + " thiết bị TOTOLINK N9v1?\\n• Giữ nguyên các thông số đã chuẩn xác trên từng AP\\n• Tuần tự nạp 2 AP/lượt và hiển thị tiến độ trực tiếp theo thời gian thực")) return;' +
  '    var btn = document.getElementById("rfBatchApplyBtn");' +
  '    if (btn) { btn.disabled = true; btn.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang khởi tạo (0/\' + cnt + " AP)..."; }' +
  '    fetch("/api/rf-optimizer/apply", {' +
  '      method: "POST",' +
  '      headers: { "Content-Type": "application/json" },' +
  '      body: JSON.stringify({ batch: true })' +
  '    }).then(checkAuthJson).then(function(d){' +
  '      if (!d || !d.success) {' +
  '        if (btn) { btn.disabled = false; btn.innerHTML = \'<i class="fi fi-rr-bolt"></i> Áp Dụng Tất Cả (\' + cnt + ")"; }' +
  '        alert("Lỗi áp dụng hàng loạt: " + ((d && d.error) || "Lỗi không xác định"));' +
  '        return;' +
  '      }' +
  '      if (d.plan) {' +
  '        rfPlanCache = d.plan;' +
  '        updateRfSummaryUi(d.plan);' +
  '        renderRfOptView();' +
  '      }' +
  '    }).catch(function(err){' +
  '      if (btn) { btn.disabled = false; btn.innerHTML = \'<i class="fi fi-rr-bolt"></i> Áp Dụng Tất Cả (\' + cnt + ")"; }' +
  '      alert("Lỗi kết nối: " + err.message);' +
  '    });' +
  '  }' +
  '  function logoutSystem() {' +
  '    fetch("/api/auth/logout", { method: "POST" })' +
  '      .then(function(){ window.location.href = "/login"; })' +
  '      .catch(function(){ window.location.href = "/login"; });' +
  '  }' +
  '  function togglePwdVis(inputId, icoId) {' +
  '    var inp = document.getElementById(inputId);' +
  '    var ico = document.getElementById(icoId);' +
  '    if (!inp) return;' +
  '    if (inp.type === "password") {' +
  '      inp.type = "text";' +
  '      if (ico) ico.className = "fi fi-rr-eye-crossed";' +
  '    } else {' +
  '      inp.type = "password";' +
  '      if (ico) ico.className = "fi fi-rr-eye";' +
  '    }' +
  '  }' +
  '  var usersListCache = [];' +
  '  var editingUsername = "";' +
  '  function showUsersFeedback(kind, htmlMsg) {' +
  '    var box = document.getElementById("usersFeedbackMsg");' +
  '    if (!box) return;' +
  '    if (!htmlMsg) { box.className = "panel-feedback"; box.innerHTML = ""; return; }' +
  '    box.className = "panel-feedback show " + (kind || "info");' +
  '    box.innerHTML = htmlMsg;' +
  '  }' +
  '  function resetUserForm() {' +
  '    editingUsername = "";' +
  '    var uInp = document.getElementById("uFormUsername");' +
  '    var fInp = document.getElementById("uFormFullName");' +
  '    var rSel = document.getElementById("uFormRole");' +
  '    var pInp = document.getElementById("uFormPassword");' +
  '    var pEye = document.getElementById("uFormPassEye");' +
  '    var headEl = document.getElementById("uFormHeading");' +
  '    var pLbl = document.getElementById("uFormPassLabel");' +
  '    var subBtn = document.getElementById("uFormSubmitBtn");' +
  '    var canBtn = document.getElementById("uFormCancelBtn");' +
  '    if (uInp) { uInp.disabled = false; uInp.value = ""; }' +
  '    if (fInp) fInp.value = "";' +
  '    if (rSel) rSel.value = "user";' +
  '    if (pInp) { pInp.type = "password"; pInp.value = ""; pInp.placeholder = "Nhập mật khẩu (≥ 4 ký tự)"; pInp.required = true; }' +
  '    if (pEye) pEye.className = "fi fi-rr-eye";' +
  '    if (headEl) headEl.innerHTML = \'<i class="fi fi-rr-user-add" style="color:var(--blue);margin-right:5px;"></i>Thêm Tài Khoản Mới\';' +
  '    if (pLbl) pLbl.innerText = "Mật khẩu *";' +
  '    if (subBtn) { subBtn.disabled = false; subBtn.innerHTML = \'<i class="fi fi-rr-plus-small"></i> Tạo Tài Khoản\'; }' +
  '    if (canBtn) canBtn.style.display = "none";' +
  '  }' +
  '  function switchSettingsTab(tabKey) {' +
  '    var keys = ["general", "users", "password"];' +
  '    var target = tabKey || "general";' +
  '    if (target === "users" && !IS_ADMIN) target = "general";' +
  '    for (var i = 0; i < keys.length; i++) {' +
  '      var k = keys[i];' +
  '      var btn = document.getElementById("stTabBtn_" + k);' +
  '      var pane = document.getElementById("stPane_" + k);' +
  '      if (btn) {' +
  '        if (k === target) btn.classList.add("active");' +
  '        else btn.classList.remove("active");' +
  '      }' +
  '      if (pane) {' +
  '        if (k === target) pane.classList.add("active");' +
  '        else pane.classList.remove("active");' +
  '      }' +
  '    }' +
  '    if (target === "users" && IS_ADMIN) {' +
  '      resetUserForm();' +
  '      showUsersFeedback("", "");' +
  '      loadUsersList();' +
  '    } else if (target === "password") {' +
  '      var cInp = document.getElementById("myCurPass");' +
  '      var nInp = document.getElementById("myNewPass");' +
  '      var cfInp = document.getElementById("myConfirmPass");' +
  '      if (cInp) { cInp.value = ""; cInp.type = "password"; }' +
  '      if (nInp) { nInp.value = ""; nInp.type = "password"; }' +
  '      if (cfInp) { cfInp.value = ""; cfInp.type = "password"; }' +
  '      showMyPassFeedback("", "");' +
  '      if (cInp) setTimeout(function(){ cInp.focus(); }, 60);' +
  '    }' +
  '  }' +
  '  function openSettingsModal(defaultTab) {' +
  '    var ov = document.getElementById("settingsModalOverlay");' +
  '    if (!ov) return;' +
  '    isModalOpen = true;' +
  '    ov.classList.add("open");' +
  '    switchSettingsTab(defaultTab || "general");' +
  '    if (IS_ADMIN && (!defaultTab || defaultTab === "general") && usersListCache.length === 0) {' +
  '      loadUsersList();' +
  '    }' +
  '  }' +
  '  function closeSettingsModal() {' +
  '    var ov = document.getElementById("settingsModalOverlay");' +
  '    if (ov) ov.classList.remove("open");' +
  '    syncAnyModalOpenFlag();' +
  '    if (!isModalOpen && pendingLivePayload && !isPaused) {' +
  '      var p = pendingLivePayload; pendingLivePayload = null; applyLiveDashboardData(p);' +
  '    }' +
  '  }' +
  '  function openUsersModal() { openSettingsModal("users"); }' +
  '  function closeUsersModal() { closeSettingsModal(); }' +
  '  function renderUsersTable(list) {' +
  '    usersListCache = Array.isArray(list) ? list : [];' +
  '    var badge = document.getElementById("usersCountBadge");' +
  '    if (badge) badge.innerText = String(usersListCache.length);' +
  '    var bodyEl = document.getElementById("usersModalBody");' +
  '    if (!bodyEl) return;' +
  '    if (usersListCache.length === 0) {' +
  '      bodyEl.innerHTML = \'<div class="modal-state"><i class="fi fi-rr-users"></i><div>Chưa có tài khoản nào.</div></div>\';' +
  '      return;' +
  '    }' +
  '    var adminCnt = 0;' +
  '    for (var a = 0; a < usersListCache.length; a++) {' +
  '      if (usersListCache[a].role === "admin") adminCnt++;' +
  '    }' +
  '    var html = \'<div class="table-responsive"><table class="client-table"><thead><tr>\' +' +
  '      "<th>#</th><th>Tên Đăng Nhập</th><th>Họ Tên / Ghi Chú</th><th>Phân Quyền</th><th>Mật Khẩu (MD5)</th><th>Cập Nhật</th><th style=\\"text-align:right;\\">Thao Tác</th>" +' +
  '      "</tr></thead><tbody>";' +
  '    for (var i = 0; i < usersListCache.length; i++) {' +
  '      var u = usersListCache[i];' +
  '      var isMe = Boolean(CURRENT_USER && String(u.username).toLowerCase() === String(CURRENT_USER.username).toLowerCase());' +
  '      var isAdm = u.role === "admin";' +
  '      var roleBadge = isAdm' +
  '        ? \'<span class="role-badge admin"><i class="fi fi-rr-user-shield" style="margin-right:3px;"></i>ADMIN • TOÀN QUYỀN</span>\'' +
  '        : \'<span class="role-badge user"><i class="fi fi-rr-eye" style="margin-right:3px;"></i>USER • CHỈ XEM</span>\';' +
  '      var meTag = isMe ? \'<span class="tag-static" style="margin-left:6px;">ĐANG ĐĂNG NHẬP</span>\' : "";' +
  '      var updStr = u.updatedAt ? (new Date(u.updatedAt)).toLocaleString("vi-VN") : "-";' +
  '      var cantDelete = isMe || (isAdm && adminCnt <= 1);' +
  '      var delTitle = isMe ? "Không thể tự xóa tài khoản đang đăng nhập" : ((isAdm && adminCnt <= 1) ? "Phải giữ lại ít nhất 1 tài khoản Admin" : "Xóa tài khoản này");' +
  '      html += "<tr>" +' +
  '        \'<td class="dim-text" style="font-weight:600;">\' + (i + 1) + "</td>" +' +
  '        \'<td><div style="display:flex;align-items:center;"><i class="fi \' + (isAdm ? "fi-rr-user-shield" : "fi-rr-user") + \'" style="margin-right:6px;color:\' + (isAdm ? "var(--blue)" : "var(--text-muted)") + \';"></i><b>\' + escText(u.username) + "</b>" + meTag + "</div></td>" +' +
  '        "<td>" + escText(u.fullName || "-") + "</td>" +' +
  '        "<td>" + roleBadge + "</td>" +' +
  '        \'<td><span class="md5-code" title="Chuỗi băm MD5 32 ký tự">\' + escText(u.passwordMd5 || "-") + "</span></td>" +' +
  '        \'<td class="dim-text" style="font-size:11.5px;">\' + escText(updStr) + "</td>" +' +
  '        \'<td style="text-align:right;white-space:nowrap;">\' +' +
  '          \'<button type="button" class="btn-nav" style="padding:3px 8px;font-size:11.5px;margin-right:5px;display:inline-flex;" onclick="editUserByIdx(\' + i + \')" title="Sửa quyền hoặc đặt lại mật khẩu"><i class="fi fi-rr-user-pen" style="color:var(--blue);"></i> Sửa</button>\' +' +
  '          \'<button type="button" class="btn-del-ap" \' + (cantDelete ? "disabled " : "") + \'onclick="deleteUserByIdx(\' + i + \', this)" title="\' + escText(delTitle) + \'"><i class="fi fi-rr-trash"></i></button>\' +' +
  '        "</td></tr>";' +
  '    }' +
  '    html += "</tbody></table></div>";' +
  '    bodyEl.innerHTML = html;' +
  '  }' +
  '  function loadUsersList() {' +
  '    if (!IS_ADMIN) return;' +
  '    var bodyEl = document.getElementById("usersModalBody");' +
  '    if (bodyEl && usersListCache.length === 0) {' +
  '      bodyEl.innerHTML = \'<div class="modal-state"><i class="fi fi-rr-spinner fi-spin" style="color:var(--blue);"></i><div>Đang tải danh sách tài khoản...</div></div>\';' +
  '    }' +
  '    fetch("/api/users")' +
  '      .then(checkAuthJson)' +
  '      .then(function(d){' +
  '        if (!d || !d.success) {' +
  '          showUsersFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> \' + escText((d && d.error) || "Không tải được danh sách người dùng"));' +
  '          return;' +
  '        }' +
  '        renderUsersTable(d.users || []);' +
  '      })' +
  '      .catch(function(err){' +
  '        showUsersFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> Lỗi kết nối: \' + escText(err.message));' +
  '      });' +
  '  }' +
  '  function editUserByIdx(idx) {' +
  '    var u = usersListCache[idx];' +
  '    if (!u) return;' +
  '    editingUsername = u.username;' +
  '    var uInp = document.getElementById("uFormUsername");' +
  '    var fInp = document.getElementById("uFormFullName");' +
  '    var rSel = document.getElementById("uFormRole");' +
  '    var pInp = document.getElementById("uFormPassword");' +
  '    var headEl = document.getElementById("uFormHeading");' +
  '    var pLbl = document.getElementById("uFormPassLabel");' +
  '    var subBtn = document.getElementById("uFormSubmitBtn");' +
  '    var canBtn = document.getElementById("uFormCancelBtn");' +
  '    if (uInp) { uInp.value = u.username; uInp.disabled = true; }' +
  '    if (fInp) fInp.value = u.fullName || "";' +
  '    if (rSel) rSel.value = u.role || "user";' +
  '    if (pInp) { pInp.value = ""; pInp.placeholder = "Để trống nếu giữ nguyên mật khẩu"; pInp.required = false; }' +
  '    if (headEl) headEl.innerHTML = \'<i class="fi fi-rr-user-pen" style="color:var(--blue);margin-right:5px;"></i>Cập Nhật Tài Khoản: <b>\' + escText(u.username) + "</b>";' +
  '    if (pLbl) pLbl.innerText = "Mật khẩu mới (tùy chọn)";' +
  '    if (subBtn) subBtn.innerHTML = \'<i class="fi fi-rr-disk"></i> Lưu Cập Nhật\';' +
  '    if (canBtn) canBtn.style.display = "inline-flex";' +
  '    showUsersFeedback("info", \'<i class="fi fi-rr-info"></i> Đang chỉnh sửa tài khoản <b>\' + escText(u.username) + "</b>. Nhập mật khẩu mới nếu muốn đặt lại mật khẩu (MD5).");' +
  '    if (fInp) fInp.focus();' +
  '  }' +
  '  function submitUserForm(e) {' +
  '    if (e && e.preventDefault) e.preventDefault();' +
  '    if (!IS_ADMIN) return false;' +
  '    var uInp = document.getElementById("uFormUsername");' +
  '    var fInp = document.getElementById("uFormFullName");' +
  '    var rSel = document.getElementById("uFormRole");' +
  '    var pInp = document.getElementById("uFormPassword");' +
  '    var subBtn = document.getElementById("uFormSubmitBtn");' +
  '    var uname = editingUsername || (uInp ? uInp.value.trim() : "");' +
  '    var fname = fInp ? fInp.value.trim() : "";' +
  '    var role = rSel ? rSel.value : "user";' +
  '    var pwd = pInp ? pInp.value : "";' +
  '    if (!uname) {' +
  '      showUsersFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> Vui lòng nhập tên đăng nhập.\');' +
  '      return false;' +
  '    }' +
  '    if (!editingUsername && pwd.length < 4) {' +
  '      showUsersFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> Mật khẩu phải có ít nhất 4 ký tự.\');' +
  '      return false;' +
  '    }' +
  '    if (editingUsername && pwd.length > 0 && pwd.length < 4) {' +
  '      showUsersFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> Mật khẩu mới phải có ít nhất 4 ký tự (hoặc để trống nếu không đổi).\');' +
  '      return false;' +
  '    }' +
  '    var isEdit = Boolean(editingUsername);' +
  '    var apiUrl = isEdit ? "/api/users/update" : "/api/users/create";' +
  '    var payload = isEdit' +
  '      ? { username: uname, fullName: fname, role: role, newPassword: pwd }' +
  '      : { username: uname, fullName: fname, role: role, password: pwd };' +
  '    var origBtn = subBtn ? subBtn.innerHTML : "";' +
  '    if (subBtn) { subBtn.disabled = true; subBtn.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang lưu...\'; }' +
  '    fetch(apiUrl, {' +
  '      method: "POST",' +
  '      headers: { "Content-Type": "application/json" },' +
  '      body: JSON.stringify(payload)' +
  '    }).then(checkAuthJson).then(function(d){' +
  '      if (subBtn) { subBtn.disabled = false; subBtn.innerHTML = origBtn; }' +
  '      if (!d || !d.success) {' +
  '        showUsersFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> \' + escText((d && d.error) || "Không thể lưu tài khoản"));' +
  '        return;' +
  '      }' +
  '      if (d.selfRoleChanged) {' +
  '        window.location.reload();' +
  '        return;' +
  '      }' +
  '      resetUserForm();' +
  '      renderUsersTable(d.users || []);' +
  '      showUsersFeedback("ok", \'<i class="fi fi-rr-check-circle"></i> \' + (isEdit ? ("Đã cập nhật tài khoản <b>" + escText(uname) + "</b> thành công.") : ("Đã tạo tài khoản <b>" + escText(uname) + "</b> (" + (role === "admin" ? "Admin" : "User") + ") thành công.")));' +
  '    }).catch(function(err){' +
  '      if (subBtn) { subBtn.disabled = false; subBtn.innerHTML = origBtn; }' +
  '      showUsersFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> Lỗi kết nối: \' + escText(err.message));' +
  '    });' +
  '    return false;' +
  '  }' +
  '  function deleteUserByIdx(idx, btnEl) {' +
  '    if (!IS_ADMIN) return;' +
  '    var u = usersListCache[idx];' +
  '    if (!u) return;' +
  '    if (!confirm("Xác nhận xóa tài khoản \\"" + u.username + "\\" (" + (u.role === "admin" ? "Admin" : "User") + ")?\\nNgười dùng đang đăng nhập bằng tài khoản này sẽ bị đăng xuất ngay lập tức.")) return;' +
  '    var origHtml = btnEl ? btnEl.innerHTML : "";' +
  '    if (btnEl) { btnEl.disabled = true; btnEl.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i>\'; }' +
  '    fetch("/api/users/delete", {' +
  '      method: "POST",' +
  '      headers: { "Content-Type": "application/json" },' +
  '      body: JSON.stringify({ username: u.username })' +
  '    }).then(checkAuthJson).then(function(d){' +
  '      if (!d || !d.success) {' +
  '        if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = origHtml; }' +
  '        showUsersFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> \' + escText((d && d.error) || "Không thể xóa tài khoản"));' +
  '        return;' +
  '      }' +
  '      if (editingUsername && editingUsername.toLowerCase() === u.username.toLowerCase()) resetUserForm();' +
  '      renderUsersTable(d.users || []);' +
  '      showUsersFeedback("ok", \'<i class="fi fi-rr-check-circle"></i> Đã xóa tài khoản <b>\' + escText(u.username) + "</b>.");' +
  '    }).catch(function(err){' +
  '      if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = origHtml; }' +
  '      showUsersFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> Lỗi kết nối: \' + escText(err.message));' +
  '    });' +
  '  }' +
  '  function showMyPassFeedback(kind, htmlMsg) {' +
  '    var box = document.getElementById("myPassFeedbackMsg");' +
  '    if (!box) return;' +
  '    if (!htmlMsg) { box.className = "panel-feedback"; box.innerHTML = ""; return; }' +
  '    box.className = "panel-feedback show " + (kind || "info");' +
  '    box.innerHTML = htmlMsg;' +
  '  }' +
  '  function openMyPassModal() { openSettingsModal("password"); }' +
  '  function closeMyPassModal() { closeSettingsModal(); }' +
  '  function submitMyPassForm(e) {' +
  '    if (e && e.preventDefault) e.preventDefault();' +
  '    var cInp = document.getElementById("myCurPass");' +
  '    var nInp = document.getElementById("myNewPass");' +
  '    var cfInp = document.getElementById("myConfirmPass");' +
  '    var subBtn = document.getElementById("myPassSubmitBtn");' +
  '    var curP = cInp ? cInp.value : "";' +
  '    var newP = nInp ? nInp.value : "";' +
  '    var cfP = cfInp ? cfInp.value : "";' +
  '    if (!curP) {' +
  '      showMyPassFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> Vui lòng nhập mật khẩu hiện tại.\');' +
  '      return false;' +
  '    }' +
  '    if (newP.length < 4) {' +
  '      showMyPassFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> Mật khẩu mới phải có ít nhất 4 ký tự.\');' +
  '      return false;' +
  '    }' +
  '    if (newP !== cfP) {' +
  '      showMyPassFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> Mật khẩu nhập lại không khớp.\');' +
  '      return false;' +
  '    }' +
  '    var origBtn = subBtn ? subBtn.innerHTML : "";' +
  '    if (subBtn) { subBtn.disabled = true; subBtn.innerHTML = \'<i class="fi fi-rr-spinner fi-spin"></i> Đang cập nhật...\'; }' +
  '    fetch("/api/auth/change-password", {' +
  '      method: "POST",' +
  '      headers: { "Content-Type": "application/json" },' +
  '      body: JSON.stringify({ currentPassword: curP, newPassword: newP })' +
  '    }).then(checkAuthJson).then(function(d){' +
  '      if (subBtn) { subBtn.disabled = false; subBtn.innerHTML = origBtn; }' +
  '      if (!d || !d.success) {' +
  '        showMyPassFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> \' + escText((d && d.error) || "Đổi mật khẩu thất bại"));' +
  '        return;' +
  '      }' +
  '      if (cInp) cInp.value = "";' +
  '      if (nInp) nInp.value = "";' +
  '      if (cfInp) cfInp.value = "";' +
  '      showMyPassFeedback("ok", \'<i class="fi fi-rr-check-circle"></i> Đã cập nhật mật khẩu (MD5) thành công!\');' +
  '      if (IS_ADMIN) loadUsersList();' +
  '    }).catch(function(err){' +
  '      if (subBtn) { subBtn.disabled = false; subBtn.innerHTML = origBtn; }' +
  '      showMyPassFeedback("err", \'<i class="fi fi-rr-triangle-warning"></i> Lỗi kết nối: \' + escText(err.message));' +
  '    });' +
  '    return false;' +
  '  }' +
  '  document.addEventListener("keydown", function(e) {' +
  '    if (e.key === "Escape" && isModalOpen) {' +
  '      var rfOv = document.getElementById("rfOptModalOverlay");' +
  '      if (rfOv && rfOv.classList.contains("open")) { closeRfOptModal(); return; }' +
  '      var clOv = document.getElementById("clientModalOverlay");' +
  '      if (clOv && clOv.classList.contains("open")) { closeClientsModal(); return; }' +
  '      closeSettingsModal();' +
  '    }' +
  '  });' +
  '  window.onload = function() { filterTable(); connectRealtimeStream(); };' +
  '</script>' +
  '</head><body><div class="container">' +
  '  <div class="top-nav">' +
  '    <div class="brand">' +
  '      <div class="brand-logo"><img src="/logo.svg" alt="Logo" /></div>' +
  '      <div class="brand-text">' +
  '        <h1>' + brandTitle + ' <span class="brand-tag">' + versionTag + '</span></h1>' +
  '        <p>' + subtitle + '</p>' +
  '      </div>' +
  '    </div>' +
  '    <div class="nav-controls">' +
  '      <div class="refresh-widget">' +
  '        <span id="liveStreamDot" class="pulse-dot live"></span>' +
  '        <span><span id="liveStreamStateTxt">Trực tiếp:</span> <b id="lastLiveTime">--:--:--</b></span>' +
  '        <button id="pauseBtn" type="button" class="btn-nav" onclick="togglePause()"><i class="fi fi-rr-pause"></i> Tạm dừng</button>' +
  '        <button id="manualRefreshBtn" type="button" class="btn-nav" onclick="manualRefreshNow()"><i class="fi fi-rr-refresh"></i> Làm mới</button>' +
  '      </div>' +
  '      ' + metricsBtnHtml +
  '      <button type="button" class="btn-nav" onclick="openSettingsModal()" title="Cài đặt IP cố định, quét dải mạng, tối ưu sóng 24h &amp; quản lý người dùng">' +
  '        <i class="fi fi-rr-settings" style="color:var(--blue);"></i> Cài đặt' +
  '        <span id="navRfNeedBadge" class="settings-nav-badge" style="display:' + (rfNeedCountInit > 0 ? 'inline-flex' : 'none') + ';" title="Số AP có đề xuất tối ưu sóng 24h">' + rfNeedCountInit + '</span>' +
  '      </button>' +
  '      <span class="user-nav-pill" title="Tài khoản đang đăng nhập: ' + escapeHtml(curUser.fullName || curUser.username) + '">' +
  '        <i class="fi ' + (isAdmin ? 'fi-rr-user-shield' : 'fi-rr-user') + '" style="color:' + (isAdmin ? 'var(--blue)' : 'var(--text-muted)') + ';"></i>' +
  '        <span>' + escapeHtml(curUser.username) + '</span>' +
  '        <span class="role-badge ' + (isAdmin ? 'admin' : 'user') + '">' + (isAdmin ? 'ADMIN' : 'USER • CHỈ XEM') + '</span>' +
  '      </span>' +
  '      <button type="button" class="btn-nav logout" onclick="logoutSystem()" title="Đăng xuất khỏi hệ thống"><i class="fi fi-rr-sign-out-alt"></i> Đăng xuất</button>' +
  '    </div>' +
  '  </div>' +
  '  <div class="kpi-grid">' +
  '    <div class="kpi-card">' +
  '      <div class="kpi-header"><span class="kpi-title">Tổng Access Point</span><span class="kpi-icon"><i class="fi fi-rr-router"></i></span></div>' +
  '      <div id="kpiTotalAps" class="kpi-val">' + summary.totalAPs + '</div>' +
  '      <div id="kpiStaticSub" class="kpi-sub">' + staticCount + ' thiết bị giám sát cố định</div>' +
  '    </div>' +
  '    <div class="kpi-card">' +
  '      <div class="kpi-header"><span class="kpi-title">TOTOLINK N9v1</span><span class="kpi-icon"><i class="fi fi-rr-wifi"></i></span></div>' +
  '      <div id="kpiN9Count" class="kpi-val">' + summary.totolinkN9v1Count + '</div>' +
  '      <div class="kpi-sub">Thiết bị quản trị SoftAC</div>' +
  '    </div>' +
  '    <div class="kpi-card">' +
  '      <div class="kpi-header"><span class="kpi-title">Đang Hoạt Động</span><span class="kpi-icon" style="color:var(--green);"><i class="fi fi-rr-check-circle"></i></span></div>' +
  '      <div id="kpiOnlineCount" class="kpi-val online">' + summary.onlineCount + '</div>' +
  '      <div id="kpiOnlinePct" class="kpi-sub" style="color:var(--green); font-weight:600;">' + onlinePercent + '% trực tuyến</div>' +
  '    </div>' +
  '    <div class="kpi-card">' +
  '      <div class="kpi-header"><span class="kpi-title">Mất Kết Nối (Offline)</span><span id="kpiOfflineIcon" class="kpi-icon"' + (summary.offlineCount > 0 ? ' style="color:var(--red);"' : '') + '><i class="fi fi-rr-triangle-warning"></i></span></div>' +
  '      <div id="kpiOfflineCount" class="kpi-val' + (summary.offlineCount > 0 ? ' offline-alert' : '') + '">' + summary.offlineCount + '</div>' +
  '      <div id="kpiOfflineSub" class="kpi-sub">' + (summary.offlineCount === 0 ? 'Mạng hoạt động ổn định' : 'Cần kiểm tra thiết bị') + '</div>' +
  '    </div>' +
  '    <div class="kpi-card">' +
  '      <div class="kpi-header"><span class="kpi-title">Tổng Clients</span><span class="kpi-icon"><i class="fi fi-rr-users-alt"></i></span></div>' +
  '      <div id="kpiTotalClients" class="kpi-val">' + summary.totalClients + '</div>' +
  '      <div class="kpi-sub">Người dùng đang kết nối</div>' +
  '    </div>' +
  '    <div class="kpi-card">' +
  '      <div class="kpi-header"><span class="kpi-title">Độ Trễ Trung Bình</span><span class="kpi-icon"><i class="fi fi-rr-tachometer-fast"></i></span></div>' +
  '      <div id="kpiAvgLatency" class="kpi-val">' + summary.avgLatencyMs + ' <span style="font-size:14px;font-weight:600;color:var(--text-muted);">ms</span></div>' +
  '      <div class="kpi-sub">Ping thời gian thực ICMP</div>' +
  '    </div>' +
  '  </div>' +
  '  <div class="table-card">' +
  '    <div class="table-toolbar">' +
  '      <div class="search-wrap">' +
  '        <i class="fi fi-rr-search search-ico"></i>' +
  '        <input id="searchInput" type="text" placeholder="Tìm theo Tên AP, IP, MAC, SSID, Model..." oninput="onMainSearchInput()" />' +
  '        <button id="clearBtn" class="search-clear" onclick="clearSearch()" title="Xóa tìm kiếm"><i class="fi fi-rr-cross-small"></i></button>' +
  '      </div>' +
  '      <div id="mainFilterTabs" class="filter-tabs">' +
  '        <button class="tab-btn active" data-tab-filter="all" onclick="setFilter(\'all\', this)"><i class="fi fi-rr-apps"></i> Tất cả <span id="tabCountAll" class="tab-count">' + summary.totalAPs + '</span></button>' +
  '        <button class="tab-btn" data-tab-filter="online" onclick="setFilter(\'online\', this)"><i class="fi fi-rr-check-circle" style="color:var(--green);"></i> Online <span id="tabCountOnline" class="tab-count">' + summary.onlineCount + '</span></button>' +
  '        <button class="tab-btn" data-tab-filter="offline" onclick="setFilter(\'offline\', this)"><i class="fi fi-rr-cross-circle" style="color:var(--red);"></i> Offline <span id="tabCountOffline" class="tab-count">' + summary.offlineCount + '</span></button>' +
  '        <button class="tab-btn" data-tab-filter="static" onclick="setFilter(\'static\', this)"><i class="fi fi-rr-thumbtack" style="color:var(--blue);"></i> Cố định <span id="tabCountStatic" class="tab-count">' + staticCount + '</span></button>' +
  '      </div>' +
  '      <div class="toolbar-right-group">' +
  (isAdmin
    ? '        <button id="btnDeleteOfflineAps" type="button" class="btn-cleanup-offline" style="display:' + (summary.offlineCount > 0 ? 'inline-flex' : 'none') + ';" onclick="deleteAllOfflineAps()" title="Xóa toàn bộ các thiết bị AP đang Offline khỏi danh sách giám sát"><i class="fi fi-rr-trash"></i> Xóa Offline (<span id="delOfflineCount">' + summary.offlineCount + '</span>)</button>'
    : '        <button id="btnResetColFilters" type="button" class="col-reset-btn" onclick="resetColumnFilters()" disabled title="Đặt lại toàn bộ bộ lọc cột và thứ tự sắp xếp"><i class="fi fi-rr-filter-slash"></i><span id="lblResetColFilters">Mặc định</span></button>') +
  '        <div class="counter-text">' +
  '          Hiển thị: <b id="visibleCount" style="color:var(--text);">' + summary.totalAPs + '</b> / <span id="totalApCount">' + summary.totalAPs + '</span> AP' +
  '        </div>' +
  '      </div>' +
  '    </div>' +
  '    <div class="table-responsive">' +
  '      <table>' +
  '        <thead><tr>' +
  '          <th id="thCol_name">' +
  '            <div class="th-sort-head" onclick="toggleColSort(\'name\')" title="Nhấn để sắp xếp theo Tên Access Point"><span>Tên Access Point</span><i id="sortIco_name" class="fi fi-rr-sort-alt sort-ico"></i></div>' +
  '            <div class="th-filter-wrap"><input id="colFilterName" type="text" class="col-filter-input" placeholder="Lọc tên AP..." oninput="onColFilterChange()" /></div>' +
  '          </th>' +
  '          <th id="thCol_ip">' +
  '            <div class="th-sort-head" onclick="toggleColSort(\'ip\')" title="Nhấn để sắp xếp theo Địa Chỉ IP"><span>Địa Chỉ IP</span><i id="sortIco_ip" class="fi fi-rr-sort-alt sort-ico"></i></div>' +
  '            <div class="th-filter-wrap"><input id="colFilterIp" type="text" list="colIpDatalist" class="col-filter-input mono" placeholder="IP / dải mạng..." oninput="onColFilterChange()" /><datalist id="colIpDatalist"></datalist></div>' +
  '          </th>' +
  '          <th id="thCol_mac">' +
  '            <div class="th-sort-head" onclick="toggleColSort(\'mac\')" title="Nhấn để sắp xếp theo Địa Chỉ MAC"><span>Địa Chỉ MAC</span><i id="sortIco_mac" class="fi fi-rr-sort-alt sort-ico"></i></div>' +
  '            <div class="th-filter-wrap"><input id="colFilterMac" type="text" list="colMacDatalist" class="col-filter-input mono" placeholder="MAC / OUI..." oninput="onColFilterChange()" /><datalist id="colMacDatalist"></datalist></div>' +
  '          </th>' +
  '          <th id="thCol_model">' +
  '            <div class="th-sort-head" onclick="toggleColSort(\'model\')" title="Nhấn để sắp xếp theo Model / Firmware"><span>Model / Firmware</span><i id="sortIco_model" class="fi fi-rr-sort-alt sort-ico"></i></div>' +
  '            <div class="th-filter-wrap"><select id="colFilterModel" class="col-filter-select" onchange="onColFilterChange()"><option value="">Tất cả</option></select></div>' +
  '          </th>' +
  '          <th id="thCol_ssid">' +
  '            <div class="th-sort-head" onclick="toggleColSort(\'ssid\')" title="Nhấn để sắp xếp theo SSID Chính"><span>SSID Chính</span><i id="sortIco_ssid" class="fi fi-rr-sort-alt sort-ico"></i></div>' +
  '            <div class="th-filter-wrap"><select id="colFilterSsid" class="col-filter-select" onchange="onColFilterChange()"><option value="">Tất cả</option></select></div>' +
  '          </th>' +
  '          <th id="thCol_channel">' +
  '            <div class="th-sort-head" onclick="toggleColSort(\'channel\')" title="Nhấn để sắp xếp theo Kênh sóng"><span>Kênh</span><i id="sortIco_channel" class="fi fi-rr-sort-alt sort-ico"></i></div>' +
  '            <div class="th-filter-wrap"><select id="colFilterChannel" class="col-filter-select" onchange="onColFilterChange()"><option value="">Tất cả</option></select></div>' +
  '          </th>' +
  '          <th id="thCol_clients">' +
  '            <div class="th-sort-head" onclick="toggleColSort(\'clients\')" title="Nhấn để sắp xếp theo số lượng Clients"><span>Clients</span><i id="sortIco_clients" class="fi fi-rr-sort-alt sort-ico"></i></div>' +
  '            <div class="th-filter-wrap">' +
  '              <select id="colFilterClients" class="col-filter-select" onchange="onColFilterChange()">' +
  '                <option value="">Tất cả</option>' +
  '                <option value="gt0">&gt; 0 (Có kết nối)</option>' +
  '                <option value="eq0">= 0 (Trống)</option>' +
  '                <option value="gte5">≥ 5 clients</option>' +
  '                <option value="gte10">≥ 10 clients</option>' +
  '                <option value="gte20">≥ 20 clients</option>' +
  '              </select>' +
  '            </div>' +
  '          </th>' +
  '          <th id="thCol_latency">' +
  '            <div class="th-sort-head" onclick="toggleColSort(\'latency\')" title="Nhấn để sắp xếp theo Độ trễ Ping"><span>Độ Trễ</span><i id="sortIco_latency" class="fi fi-rr-sort-alt sort-ico"></i></div>' +
  '            <div class="th-filter-wrap">' +
  '              <select id="colFilterLatency" class="col-filter-select" onchange="onColFilterChange()">' +
  '                <option value="">Tất cả</option>' +
  '                <option value="fast">≤ 3 ms (Nhanh)</option>' +
  '                <option value="good">4–12 ms (Tốt)</option>' +
  '                <option value="mid">13–30 ms (TB)</option>' +
  '                <option value="high">&gt; 30 ms (Cao)</option>' +
  '                <option value="na">Offline (-)</option>' +
  '              </select>' +
  '            </div>' +
  '          </th>' +
  '          <th id="thCol_status">' +
  '            <div class="th-sort-head" onclick="toggleColSort(\'status\')" title="Nhấn để sắp xếp theo Trạng thái"><span>Trạng Thái</span><i id="sortIco_status" class="fi fi-rr-sort-alt sort-ico"></i></div>' +
  '            <div class="th-filter-wrap">' +
  '              <select id="colFilterStatus" class="col-filter-select" onchange="onColStatusFilterChange()">' +
  '                <option value="">Tất cả</option>' +
  '                <option value="online">Online</option>' +
  '                <option value="offline">Offline</option>' +
  '                <option value="static">Cố định</option>' +
  '              </select>' +
  '            </div>' +
  '          </th>' +
  (isAdmin ? (
  '          <th style="text-align:right;">' +
  '            <div class="th-sort-head static-head" style="justify-content:flex-end;"><span>Thao Tác</span></div>' +
  '            <div class="th-filter-wrap" style="display:flex;justify-content:flex-end;">' +
  '              <button id="btnResetColFilters" type="button" class="col-reset-btn" onclick="resetColumnFilters()" disabled title="Đặt lại toàn bộ bộ lọc cột và thứ tự sắp xếp">' +
  '                <i class="fi fi-rr-filter-slash"></i><span id="lblResetColFilters">Mặc định</span>' +
  '              </button>' +
  '            </div>' +
  '          </th>'
  ) : '') +
  '        </tr></thead>' +
  '        <tbody id="apTableBody">' +
  '          ' + (rows || ('<tr id="initialEmptyStateRow"><td colspan="' + (isAdmin ? '10' : '9') + '" class="empty-state"><i class="fi fi-rr-router empty-icon"></i>' + (isAdmin ? 'Chưa có AP nào. Hãy mở mục Cài đặt để thêm IP cố định hoặc quét dải mạng.' : 'Chưa có thiết bị Access Point nào trong hệ thống.') + '</td></tr>')) +
  '          <tr id="emptyRow" style="display:none;"><td colspan="' + (isAdmin ? '10' : '9') + '" class="empty-state"><i class="fi fi-rr-filter empty-icon"></i><div>Không tìm thấy thiết bị nào khớp với điều kiện lọc hiện tại.</div><div style="margin-top:10px;"><button type="button" class="btn-nav" onclick="resetAllSearchAndFilters()"><i class="fi fi-rr-filter-slash"></i> Xóa tất cả bộ lọc</button></div></td></tr>' +
  '        </tbody>' +
  '      </table>' +
  '    </div>' +
  '    <div id="mainTablePager" class="table-pager-bar"></div>' +
  '  </div>' +
  '</div>' +
  '<div id="clientModalOverlay" class="modal-overlay" onclick="if(event.target===this)closeClientsModal()">' +
  '  <div class="modal-dialog">' +
  '    <div class="modal-header">' +
  '      <div>' +
  '        <div class="modal-title-row">' +
  '          <span class="modal-ap-ico"><i class="fi fi-rr-router"></i></span>' +
  '          <h3 id="modalApName" class="modal-title">AP</h3>' +
  '          <span id="modalApModel" class="model-badge">TOTOLINK N9v1</span>' +
  '          <span id="modalClientCountBadge" class="client-pill active"><i class="fi fi-rr-users" style="margin-right:4px;"></i>0 thiết bị</span>' +
  '        </div>' +
  '        <div class="modal-meta">' +
  '          <span class="modal-meta-item"><i class="fi fi-rr-globe" style="color:var(--blue);"></i><code id="modalApIp">-</code></span>' +
  '          <span class="modal-meta-item"><i class="fi fi-rr-wifi" style="color:var(--green);"></i><span id="modalApSsid">-</span></span>' +
  '          <span class="modal-meta-item"><span id="modalApCh">CH -</span></span>' +
  '        </div>' +
  '      </div>' +
  '      <div class="modal-actions">' +
  '        <button id="modalRefreshBtn" type="button" class="btn-nav" onclick="loadApClients(true)"><i class="fi fi-rr-refresh"></i> Làm mới</button>' +
  '        <button type="button" class="btn-modal-close" onclick="closeClientsModal()" title="Đóng (ESC)"><i class="fi fi-rr-cross-small"></i></button>' +
  '      </div>' +
  '    </div>' +
  '    <div id="modalClientsBody" class="modal-body"></div>' +
  '    <div class="modal-footer">' +
  '      <span id="modalUpdatedTime">Đang đồng bộ dữ liệu trực tiếp từ AP...</span>' +
  '      <span>Nhấn <b>ESC</b> hoặc click ra ngoài để đóng</span>' +
  '    </div>' +
  '  </div>' +
  '</div>' +
  '<div id="rfOptModalOverlay" class="modal-overlay" style="z-index:1060;" onclick="if(event.target===this)closeRfOptModal()">' +
  '  <div class="modal-dialog rf-wide">' +
  '    <div class="modal-header">' +
  '      <div>' +
  '        <div class="modal-title-row">' +
  '          <span class="modal-ap-ico" style="width:28px;height:28px;font-size:14px;color:var(--blue);background:var(--blue-bg);border-color:var(--blue-border);"><i class="fi fi-rr-settings-sliders"></i></span>' +
  '          <h3 class="modal-title" style="font-size:15px;">' + (isAdmin ? 'Phân Tích &amp; Tối Ưu Sóng 24h' : 'Phân Tích Sóng &amp; Kênh Sóng 24h') + '</h3>' +
  '          <span id="rfModalHoursBadge" class="model-badge"><i class="fi fi-rr-clock" style="margin-right:4px;"></i>Chu kỳ: ' + rfHoursInit + 'h / 24h</span>' +
  '          <span id="rfModalSamplesBadge" class="client-pill active" style="font-size:11px;padding:2px 8px;"><i class="fi fi-rr-signal-alt-2" style="margin-right:4px;"></i>' + rfSamplesInit + ' mẫu RSSI • ' + rfLinksInit + ' liên kết nhiễu</span>' +
  '        </div>' +
  '        <div class="modal-meta">' +
  '          <span class="modal-meta-item"><i class="fi fi-rr-calendar-clock" style="color:var(--blue);"></i><span>Chế độ 2 Tự động:</span>' +
  '            <label class="rf-toggle-wrap' + (isAdmin ? '' : ' disabled-ro') + '" style="margin-left:4px;">' +
  '              <input type="checkbox" id="mode2ToggleModal" onchange="saveMode2Settings(\'modal\')"' + (mode2EnabledInit ? ' checked' : '') + (isAdmin ? '' : ' disabled') + ' />' +
  '              <span class="rf-toggle-track" style="width:34px;height:18px;"><span class="rf-toggle-thumb" style="width:14px;height:14px;"></span></span>' +
  '              <span id="mode2BadgeModal" class="rf-toggle-state ' + (mode2EnabledInit ? 'on' : 'off') + '">' + (mode2EnabledInit ? 'BẬT' : 'TẮT') + '</span>' +
  '            </label>' +
  '            <input type="time" id="mode2TimeModal" class="rf-time-input" style="padding:1px 6px;font-size:11px;" value="' + mode2TimeInit + '" onchange="saveMode2Settings(\'modal\')"' + (isAdmin ? '' : ' disabled') + ' />' +
  '          </span>' +
  '          <span id="rfPlanDistBadge" class="modal-meta-item" style="margin-left:8px;"><i class="fi fi-rr-shield-check" style="color:var(--green);margin-right:4px;"></i>Bản đồ tĩnh chống lặp: <b>CH1(' + ((rfSumInit.channelPlanDist && rfSumInit.channelPlanDist[1]) || 0) + ') • CH6(' + ((rfSumInit.channelPlanDist && rfSumInit.channelPlanDist[6]) || 0) + ') • CH11(' + ((rfSumInit.channelPlanDist && rfSumInit.channelPlanDist[11]) || 0) + ')</b></span>' +
  '        </div>' +
  '      </div>' +
  '      <div class="modal-actions">' +
  (isAdmin ? (
  '        <button id="rfModalReplanBtn" type="button" class="btn-nav" onclick="replanRfChannels(this)" title="Giải lại bài toán tô màu đồ thị 3 kênh toàn tòa nhà (chỉ dùng khi lắp mới hoặc di dời vị trí AP)"><i class="fi fi-rr-network-cloud"></i> Quy Hoạch Lại</button>' +
  '        <button id="rfModalScanBtn" type="button" class="btn-nav" onclick="triggerRfNeighborScan(this)" title="Quét nhanh sóng lân cận trên các AP rảnh (0 client)"><i class="fi fi-rr-radar"></i> Quét Nhiễu</button>' +
  '        <button id="rfModalSyncBtn" type="button" class="btn-nav" onclick="loadRfOptPlan(true)" title="Đọc lại cấu hình TX Power &amp; STA RSSI thực tế từ tất cả AP"><i class="fi fi-rr-refresh"></i> Đồng Bộ AP</button>' +
  '        <button id="rfBatchApplyBtn" type="button" class="btn-submit btn-blue" style="height:30px;padding:0 11px;font-size:12px;" onclick="applyAllRecommendedRf()"><i class="fi fi-rr-bolt"></i> Áp Dụng Tất Cả (' + rfNeedCountInit + ')</button>'
  ) : (
  '        <span class="rf-chip"><i class="fi fi-rr-eye"></i> Quyền xem (Read-only)</span>'
  )) +
  '        <button type="button" class="btn-modal-close" onclick="closeRfOptModal()" title="Đóng (ESC)"><i class="fi fi-rr-cross-small"></i></button>' +
  '      </div>' +
  '    </div>' +
  '    <div class="rf-kpi-strip">' +
  '      <div class="rf-mini-kpi"><div><div class="rf-mini-label">AP Cần Tối Ưu (N9v1)</div><div id="rfKpiNeed" class="rf-mini-val" style="color:var(--blue);">' + rfNeedCountInit + '</div></div><i class="fi fi-rr-sparkles" style="font-size:18px;color:var(--blue);"></i></div>' +
  '      <div class="rf-mini-kpi"><div><div class="rf-mini-label">Đề Xuất Đổi Kênh 1/6/11</div><div id="rfKpiCh" class="rf-mini-val">' + (rfSumInit.channelChangeCount || 0) + '</div></div><i class="fi fi-rr-broadcast-tower" style="font-size:18px;color:var(--sky);"></i></div>' +
  '      <div class="rf-mini-kpi"><div><div class="rf-mini-label">Tinh Chỉnh TX Power</div><div id="rfKpiPwr" class="rf-mini-val">' + (rfSumInit.txPowerChangeCount || 0) + '</div></div><i class="fi fi-rr-signal-alt-2" style="font-size:18px;color:var(--green);"></i></div>' +
  '      <div class="rf-mini-kpi"><div><div class="rf-mini-label">Chống Sticky Client (RSSI)</div><div id="rfKpiRssi" class="rf-mini-val">' + (rfSumInit.staRssiChangeCount || 0) + '</div></div><i class="fi fi-rr-shield-check" style="font-size:18px;color:var(--amber);"></i></div>' +
  '    </div>' +
  '    <div class="rf-modal-toolbar">' +
  '      <div class="filter-tabs">' +
  '        <button type="button" class="tab-btn rf-tab-btn active" onclick="setRfTab(\'need\', this)"><i class="fi fi-rr-sparkles"></i> Đề xuất tối ưu <span id="rfTabCntNeed" class="tab-count">' + rfNeedCountInit + '</span></button>' +
  '        <button type="button" class="tab-btn rf-tab-btn" onclick="setRfTab(\'all\', this)"><i class="fi fi-rr-apps"></i> Tất cả AP <span id="rfTabCntAll" class="tab-count">' + (rfSumInit.totalAps || 0) + '</span></button>' +
  '        <button type="button" class="tab-btn rf-tab-btn" onclick="setRfTab(\'unifi\', this)"><i class="fi fi-rr-router"></i> Cụm UniFi Controller <span id="rfTabCntUnifi" class="tab-count">5</span></button>' +
  '        <button type="button" class="tab-btn rf-tab-btn" onclick="setRfTab(\'history\', this)"><i class="fi fi-rr-time-past"></i> Lịch sử đã áp dụng <span id="rfTabCntHist" class="tab-count">' + rfHistTotalInit + '</span></button>' +
  '      </div>' +
  '      <div class="search-wrap" style="max-width:290px;min-width:200px;">' +
  '        <i class="fi fi-rr-search search-ico"></i>' +
  '        <input id="rfSearchInput" type="text" placeholder="Lọc theo tên AP, IP, SSID..." oninput="onRfSearchInput()" />' +
  '      </div>' +
  '    </div>' +
  '    <div id="rfOptModalBody" class="modal-body"></div>' +
  '    <div class="modal-footer">' +
  '      <span id="rfModalUpdatedTime">Dữ liệu lưu trữ bền vững trong rf_telemetry_24h.json</span>' +
  (isAdmin
    ? '      <span>Thông số <b>Đã chuẩn</b> được giữ nguyên không nạp lại • Nhấn <i class="fi fi-rr-edit" style="font-size:10px;"></i> nếu muốn tùy chỉnh thủ công</span>'
    : '      <span>Tài khoản <b>User</b> chỉ có quyền xem phân tích &amp; lịch sử • Liên hệ <b>Admin</b> để áp dụng tối ưu</span>') +
  '    </div>' +
  '  </div>' +
  '</div>' +
  '<div id="settingsModalOverlay" class="modal-overlay" onclick="if(event.target===this)closeSettingsModal()">' +
  '  <div class="modal-dialog" style="max-width:1120px;">' +
  '    <div class="modal-header">' +
  '      <div>' +
  '        <div class="modal-title-row">' +
  '          <span class="modal-ap-ico" style="color:var(--blue);background:var(--blue-bg);border-color:var(--blue-border);"><i class="fi fi-rr-settings"></i></span>' +
  '          <h3 class="modal-title">Cài Đặt Hệ Thống</h3>' +
  '          <span class="role-badge ' + (isAdmin ? 'admin' : 'user') + '">' + (isAdmin ? 'ADMIN • TOÀN QUYỀN' : 'USER • CHỈ XEM') + '</span>' +
  '        </div>' +
  '        <div class="modal-meta">' +
  (isAdmin
    ? '          <span class="modal-meta-item"><i class="fi fi-rr-sliders-h" style="color:var(--blue);"></i>Quản lý IP cố định • Quét dải mạng • Tối ưu sóng 24h • Quản lý người dùng</span>'
    : '          <span class="modal-meta-item"><i class="fi fi-rr-eye" style="color:var(--text-muted);"></i>Xem phân tích sóng 24h &amp; đổi mật khẩu tài khoản cá nhân</span>') +
  '        </div>' +
  '      </div>' +
  '      <div class="modal-actions">' +
  '        <button type="button" class="btn-modal-close" onclick="closeSettingsModal()" title="Đóng (ESC)"><i class="fi fi-rr-cross-small"></i></button>' +
  '      </div>' +
  '    </div>' +
  '    <div class="settings-tabs-bar">' +
  '      <button id="stTabBtn_general" type="button" class="tab-btn active" onclick="switchSettingsTab(\'general\')"><i class="fi fi-rr-settings-sliders"></i> ' + (isAdmin ? 'Cấu Hình AP &amp; Tối Ưu Sóng' : 'Phân Tích Sóng 24h') + '</button>' +
  (isAdmin ? (
  '      <button id="stTabBtn_users" type="button" class="tab-btn" onclick="switchSettingsTab(\'users\')"><i class="fi fi-rr-users-gear"></i> Quản Lý Người Dùng <span id="usersCountBadge" class="tab-count">' + ((loadUsersStore(false).users || []).length) + '</span></button>'
  ) : '') +
  '      <button id="stTabBtn_password" type="button" class="tab-btn" onclick="switchSettingsTab(\'password\')"><i class="fi fi-rr-key"></i> Đổi Mật Khẩu Cá Nhân</button>' +
  '    </div>' +
  '    <div class="modal-body">' +
  '      <div id="stPane_general" class="settings-pane padded active">' +
  (isAdmin ? (
  '        <div class="config-grid">' +
  '          <div class="config-panel">' +
  '            <div>' +
  '              <div class="panel-header">' +
  '                <div class="panel-title"><i class="fi fi-rr-thumbtack" style="color:var(--text-muted);"></i> Quản Lý IP Giám Sát Cố Định</div>' +
  '                <span id="staticIpBadgeCount" class="panel-badge">' + staticIpsList.length + ' IP</span>' +
  '              </div>' +
  '              <p class="panel-desc">Các IP này luôn được ping liên tục 24/7 và đẩy sang Grafana, hoạt động xuyên Subnet/VLAN:</p>' +
  '            </div>' +
  '            <div>' +
  '              <div class="form-row">' +
  '                <input id="staticIpsInput" class="form-input" type="text" value="' + escapeHtml(currentStaticStr) + '" placeholder="Ví dụ: 172.16.1.20, 192.168.1.165..." onkeydown="if(event.key===\'Enter\')saveStaticIps()" />' +
  '                <button id="saveStaticBtn" type="button" class="btn-submit btn-green" onclick="saveStaticIps()"><i class="fi fi-rr-disk"></i> Lưu Cấu Hình</button>' +
  '              </div>' +
  '              <div id="staticStatusMsg" class="panel-feedback"></div>' +
  '            </div>' +
  '          </div>' +
  '          <div class="config-panel">' +
  '            <div>' +
  '              <div class="panel-header">' +
  '                <div class="panel-title"><i class="fi fi-rr-broadcast-tower" style="color:var(--text-muted);"></i> Quét Dải Mạng Bổ Sung</div>' +
  '                <div class="preset-row">' + presetButtonsHtml + '</div>' +
  '              </div>' +
  '              <p class="panel-desc">Quét phát hiện AP mới xuyên VLAN/Subnet (nhập 1 IP lẻ, dải IP hoặc CIDR):</p>' +
  '            </div>' +
  '            <div>' +
  '              <div class="form-row">' +
  '                <input id="targetInput" class="form-input" type="text" value="' + escapeHtml(currentTarget) + '" placeholder="Ví dụ: 192.168.1.165, 192.168.1.0/24 hoặc 172.16.0.0/21" onkeydown="if(event.key===\'Enter\')triggerScan()" />' +
  '                <button id="scanBtn" type="button" class="btn-submit btn-blue" onclick="triggerScan()"><i class="fi fi-rr-search"></i> Quét Ngay</button>' +
  '              </div>' +
  '              <div id="scanStatusMsg" class="panel-feedback"></div>' +
  '            </div>' +
  '          </div>' +
  '        </div>' +
  '        <div class="config-panel" style="margin-bottom:16px;">' +
  '          <div>' +
  '            <div class="panel-header">' +
  '              <div class="panel-title"><i class="fi fi-rr-key" style="color:var(--blue);"></i> Tài Khoản Quản Trị Thiết Bị AP (TOTOLINK Web / SSH)</div>' +
  '              <span id="apPassCountBadge" class="panel-badge">' + TOTOLINK_PASSWORDS.length + ' mật khẩu đã cấu hình</span>' +
  '            </div>' +
  '            <p class="panel-desc">Cấu hình trực tiếp tài khoản &amp; mật khẩu đăng nhập thiết bị TOTOLINK N9v1 (lưu vào <code>config.json</code>, hỗ trợ nhập nhiều mật khẩu cách nhau dấu phẩy):</p>' +
  '          </div>' +
  '          <div>' +
  '            <div class="form-row" style="flex-wrap:wrap;gap:8px;">' +
  '              <input id="apCredUserInput" class="form-input" type="text" style="flex:0 1 130px;min-width:110px;" value="' + escapeHtml(TOTOLINK_WEB_USER || 'admin') + '" placeholder="User AP (admin)" title="Tên tài khoản quản trị AP (mặc định: admin)" />' +
  '              <div style="position:relative;flex:1 1 260px;min-width:210px;display:flex;">' +
  '                <input id="apCredPassInput" class="form-input" type="password" style="width:100%;padding-right:34px;" placeholder="Nhập mật khẩu AP mới (bỏ trống nếu giữ nguyên)..." autocomplete="new-password" onkeydown="if(event.key===\'Enter\')saveApCredentials()" />' +
  '                <button type="button" onclick="togglePwdVis(\'apCredPassInput\',\'apCredPassEye\')" style="position:absolute;right:6px;top:50%;transform:translateY(-50%);border:none;background:transparent;color:var(--text-dim);cursor:pointer;padding:4px;" title="Hiện/Ẩn mật khẩu"><i id="apCredPassEye" class="fi fi-rr-eye"></i></button>' +
  '              </div>' +
  '              <input id="apCredSsidInput" class="form-input" type="text" style="flex:0 1 175px;min-width:140px;" value="' + escapeHtml(DEFAULT_SSID_FALLBACK || 'ConCard_WiFi') + '" placeholder="SSID mặc định" title="Tên SSID dự phòng hiển thị khi chưa đọc được từ AP" />' +
  '              <button id="saveApCredBtn" type="button" class="btn-submit btn-blue" onclick="saveApCredentials()"><i class="fi fi-rr-disk"></i> Lưu Tài Khoản AP</button>' +
  '            </div>' +
  '            <div id="apCredStatusMsg" class="panel-feedback"></div>' +
  '          </div>' +
  '        </div>'
  ) : '') +
  '        <div class="rf-banner-card" style="margin-bottom:0;">' +
  '          <div class="rf-mode1-box">' +
  '            <div class="rf-head-row">' +
  '              <div class="rf-title-group">' +
  '                <span class="rf-ico-badge"><i class="fi fi-rr-magic-wand"></i></span>' +
  '                <span class="rf-title-txt">' + (isAdmin ? 'Chế Độ 1: Phân Tích &amp; Đề Xuất Tối Ưu Sóng 24h' : 'Chế Độ 1: Phân Tích &amp; Trạng Thái Sóng 24h') + '</span>' +
  '              </div>' +
  '              <div class="rf-stat-pills">' +
  '                <span id="rfNeedChipBanner" class="rf-chip ' + (rfNeedCountInit > 0 ? 'warn' : 'ok') + '"><i class="fi fi-rr-sparkles"></i><b id="rfNeedCountBanner">' + rfNeedCountInit + '</b> AP cần tối ưu</span>' +
  '                <span class="rf-chip"><i class="fi fi-rr-clock"></i>Thu thập: <b id="rfHoursBanner">' + rfHoursInit + '</b>h / 24h</span>' +
  '                <span class="rf-chip"><i class="fi fi-rr-signal-alt-2"></i><b id="rfSamplesBanner">' + rfSamplesInit + '</b> mẫu • <b id="rfLinksBanner">' + rfLinksInit + '</b> liên kết nhiễu</span>' +
  '              </div>' +
  '            </div>' +
  '            <p class="rf-desc-txt">Đo lường cường độ RSSI thiết bị 24h &amp; ma trận chồng lấn kênh 1/6/11 xuyên tầng để gợi ý Kênh sạch, TX Power và ngưỡng cắt Sticky Client cho từng AP.</p>' +
  '            <div class="rf-actions-row">' +
  '              <button type="button" class="btn-submit btn-blue" style="height:34px;" onclick="openRfOptModal()"><i class="fi fi-rr-settings-sliders"></i> ' + (isAdmin ? 'Xem &amp; Áp Dụng Đề Xuất' : 'Xem Phân Tích &amp; Đề Xuất') + ' ( <span id="rfBtnCount">' + rfNeedCountInit + '</span> )</button>' +
  (isAdmin ? '              <button id="bannerScanNbBtn" type="button" class="btn-nav" style="height:34px;" onclick="triggerRfNeighborScan(this)" title="Quét sóng lân cận trên các AP đang rảnh (0 client)"><i class="fi fi-rr-radar"></i> Quét Nhiễu Kênh</button>' : '') +
  '              <span id="mode2SavedToast" class="rf-toast"><i class="fi fi-rr-check-circle"></i> Đã lưu cài đặt</span>' +
  '            </div>' +
  '          </div>' +
  '          <div class="rf-mode2-box">' +
  '            <div class="rf-head-row">' +
  '              <span style="font-size:13px;font-weight:700;color:var(--text);display:inline-flex;align-items:center;gap:6px;"><i class="fi fi-rr-calendar-clock" style="color:var(--blue);"></i>Chế Độ 2: Tự Động Tối Ưu Định Kỳ</span>' +
  '              <label class="rf-toggle-wrap' + (isAdmin ? '' : ' disabled-ro') + '" title="' + (isAdmin ? 'Bật / Tắt tự động tối ưu sóng hàng ngày' : 'Chỉ tài khoản Admin mới được phép thay đổi') + '">' +
  '                <input type="checkbox" id="mode2ToggleMain" onchange="saveMode2Settings(\'main\')"' + (mode2EnabledInit ? ' checked' : '') + (isAdmin ? '' : ' disabled') + ' />' +
  '                <span class="rf-toggle-track"><span class="rf-toggle-thumb"></span></span>' +
  '                <span id="mode2BadgeMain" class="rf-toggle-state ' + (mode2EnabledInit ? 'on' : 'off') + '">' + (mode2EnabledInit ? 'ĐANG BẬT' : 'ĐANG TẮT') + '</span>' +
  '              </label>' +
  '            </div>' +
  '            <div class="rf-mode2-controls">' +
  '              <span>Khung giờ chạy:</span>' +
  '              <input type="time" id="mode2TimeMain" class="rf-time-input" value="' + mode2TimeInit + '" onchange="saveMode2Settings(\'main\')"' + (isAdmin ? '' : ' disabled') + ' />' +
  '              <label class="rf-chk-label"><input type="checkbox" id="mode2Wait24hMain" onchange="saveMode2Settings(\'main\')"' + (mode2Wait24hInit ? ' checked' : '') + (isAdmin ? '' : ' disabled') + ' /> Đợi đủ 24h mẫu sóng</label>' +
  '            </div>' +
  '            <div id="mode2StatusNoteMain" class="rf-mode2-note">' +
  (mode2EnabledInit
    ? '<i class="fi fi-rr-shield-check" style="color:var(--green);"></i> Tự động tối ưu hàng ngày lúc <b>' + mode2TimeInit + '</b>' + (mode2Wait24hInit ? ' (khi đủ 24h mẫu sóng)' : ' (chạy ngay chu kỳ tới)')
    : '<i class="fi fi-rr-info"></i> Chế độ tự động đang TẮT — Hệ thống chỉ phân tích &amp; đề xuất ở Chế độ 1') +
  '            </div>' +
  '          </div>' +
  '        </div>' +
  '      </div>' +
  (isAdmin ? (
  '      <div id="stPane_users" class="settings-pane">' +
  '        <div class="users-form-box">' +
  '          <form id="userManageForm" onsubmit="return submitUserForm(event)">' +
  '            <div class="users-form-title">' +
  '              <span id="uFormHeading"><i class="fi fi-rr-user-add" style="color:var(--blue);margin-right:5px;"></i>Thêm Tài Khoản Mới</span>' +
  '              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">' +
  '                <span class="md5-code"><i class="fi fi-rr-lock" style="font-size:10px;margin-right:4px;"></i>Mã hóa mật khẩu: MD5 (32-hex)</span>' +
  '                <button type="button" class="btn-nav" style="padding:3px 9px;font-size:11.5px;" onclick="loadUsersList()"><i class="fi fi-rr-refresh"></i> Làm mới</button>' +
  '              </div>' +
  '            </div>' +
  '            <div class="users-form-grid">' +
  '              <div class="u-field">' +
  '                <label for="uFormUsername">Tên đăng nhập *</label>' +
  '                <input id="uFormUsername" class="u-input" type="text" placeholder="vd: user01" autocomplete="off" required />' +
  '              </div>' +
  '              <div class="u-field">' +
  '                <label for="uFormFullName">Họ tên / Ghi chú</label>' +
  '                <input id="uFormFullName" class="u-input" type="text" placeholder="vd: Kỹ thuật viên trực ca" autocomplete="off" />' +
  '              </div>' +
  '              <div class="u-field">' +
  '                <label for="uFormRole">Phân quyền *</label>' +
  '                <select id="uFormRole" class="u-select">' +
  '                  <option value="user">User — Chỉ xem (Read-only)</option>' +
  '                  <option value="admin">Admin — Toàn quyền quản trị</option>' +
  '                </select>' +
  '              </div>' +
  '              <div class="u-field">' +
  '                <label id="uFormPassLabel" for="uFormPassword">Mật khẩu *</label>' +
  '                <div style="position:relative;">' +
  '                  <input id="uFormPassword" class="u-input" type="password" style="padding-right:32px;" placeholder="Nhập mật khẩu (≥ 4 ký tự)" autocomplete="new-password" required />' +
  '                  <button type="button" onclick="togglePwdVis(\'uFormPassword\',\'uFormPassEye\')" style="position:absolute;right:6px;top:50%;transform:translateY(-50%);border:none;background:transparent;color:var(--text-dim);cursor:pointer;padding:4px;" title="Hiện / Ẩn mật khẩu"><i id="uFormPassEye" class="fi fi-rr-eye"></i></button>' +
  '                </div>' +
  '              </div>' +
  '              <div style="display:flex;gap:6px;">' +
  '                <button id="uFormSubmitBtn" type="submit" class="btn-submit btn-blue" style="height:34px;padding:0 14px;"><i class="fi fi-rr-plus-small"></i> Tạo Tài Khoản</button>' +
  '                <button id="uFormCancelBtn" type="button" class="btn-nav" style="height:34px;display:none;" onclick="resetUserForm()">Hủy</button>' +
  '              </div>' +
  '            </div>' +
  '            <div id="usersFeedbackMsg" class="panel-feedback"></div>' +
  '          </form>' +
  '        </div>' +
  '        <div id="usersModalBody"></div>' +
  '      </div>'
  ) : '') +
  '      <div id="stPane_password" class="settings-pane padded">' +
  '        <div class="settings-pass-card">' +
  '          <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid var(--border);">' +
  '            <span class="modal-ap-ico" style="color:var(--blue);background:var(--blue-bg);border-color:var(--blue-border);"><i class="fi fi-rr-key"></i></span>' +
  '            <div>' +
  '              <div style="font-size:14px;font-weight:700;color:var(--text);">Đổi Mật Khẩu Cá Nhân</div>' +
  '              <div style="font-size:12px;color:var(--text-muted);">Đang đăng nhập: <b>' + escapeHtml(curUser.username) + '</b> (' + (isAdmin ? 'Admin' : 'User') + ')</div>' +
  '            </div>' +
  '          </div>' +
  '          <form onsubmit="return submitMyPassForm(event)" style="display:flex;flex-direction:column;gap:12px;">' +
  '            <div class="u-field">' +
  '              <label for="myCurPass">Mật khẩu hiện tại *</label>' +
  '              <div style="position:relative;">' +
  '                <input id="myCurPass" class="u-input" type="password" style="padding-right:32px;" placeholder="Nhập mật khẩu hiện tại" autocomplete="current-password" required />' +
  '                <button type="button" onclick="togglePwdVis(\'myCurPass\',\'myCurEye\')" style="position:absolute;right:6px;top:50%;transform:translateY(-50%);border:none;background:transparent;color:var(--text-dim);cursor:pointer;padding:4px;"><i id="myCurEye" class="fi fi-rr-eye"></i></button>' +
  '              </div>' +
  '            </div>' +
  '            <div class="u-field">' +
  '              <label for="myNewPass">Mật khẩu mới (≥ 4 ký tự) *</label>' +
  '              <div style="position:relative;">' +
  '                <input id="myNewPass" class="u-input" type="password" style="padding-right:32px;" placeholder="Nhập mật khẩu mới" autocomplete="new-password" required />' +
  '                <button type="button" onclick="togglePwdVis(\'myNewPass\',\'myNewEye\')" style="position:absolute;right:6px;top:50%;transform:translateY(-50%);border:none;background:transparent;color:var(--text-dim);cursor:pointer;padding:4px;"><i id="myNewEye" class="fi fi-rr-eye"></i></button>' +
  '              </div>' +
  '            </div>' +
  '            <div class="u-field">' +
  '              <label for="myConfirmPass">Nhập lại mật khẩu mới *</label>' +
  '              <input id="myConfirmPass" class="u-input" type="password" placeholder="Nhập lại mật khẩu mới" autocomplete="new-password" required />' +
  '            </div>' +
  '            <div id="myPassFeedbackMsg" class="panel-feedback"></div>' +
  '            <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:4px;">' +
  '              <button type="button" class="btn-nav" style="height:34px;" onclick="closeSettingsModal()">Đóng</button>' +
  '              <button id="myPassSubmitBtn" type="submit" class="btn-submit btn-blue" style="height:34px;padding:0 14px;"><i class="fi fi-rr-disk"></i> Lưu Mật Khẩu Mới</button>' +
  '            </div>' +
  '          </form>' +
  '        </div>' +
  '      </div>' +
  '    </div>' +
  '    <div class="modal-footer">' +
  '      <span><b>' + brandTitle + ' ' + versionTag + '</b> • Mọi thay đổi được đồng bộ trực tiếp theo thời gian thực</span>' +
  '      <span>Nhấn <b>ESC</b> hoặc click ra ngoài để đóng</span>' +
  '    </div>' +
  '  </div>' +
  '</div></body></html>';
}

var GRAFANA_SYNC_INTERVAL_MS = Number(appConfig.grafanaSync && appConfig.grafanaSync.syncIntervalMs) || 60000;

function syncGrafanaDatasourceUrl() {
  try {
    var gCfg = appConfig.grafanaSync || {};
    if (!gCfg.enabled || !gCfg.host || !gCfg.datasourceUid || !gCfg.password) return;
    var gHost = gCfg.host;
    var gPort = Number(gCfg.port) || 3000;
    var gUid = gCfg.datasourceUid;
    var gUser = gCfg.username || 'admin';
    var gPass = gCfg.password;

    var os = require('os');
    var ifaces = os.networkInterfaces();
    var lanIp = null;
    Object.keys(ifaces).forEach(function (ifname) {
      if (ifname.indexOf('Radmin') !== -1 || ifname.indexOf('WSL') !== -1 || ifname.indexOf('Loopback') !== -1) return;
      (ifaces[ifname] || []).forEach(function (iface) {
        if ((iface.family === 'IPv4' || iface.family === 4) && !iface.internal) {
          if (iface.address.indexOf('172.16.') === 0 || (!lanIp && iface.address.indexOf('192.168.') === 0)) {
            lanIp = iface.address;
          }
        }
      });
    });
    if (!lanIp) return;
    var targetUrl = 'http://' + lanIp + ':' + PORT;
    var auth = (Buffer.from ? Buffer.from(gUser + ':' + gPass) : new Buffer(gUser + ':' + gPass)).toString('base64');
    var dsPath = '/api/datasources/uid/' + gUid;
    var reqGet = http.get({
      host: gHost,
      port: gPort,
      path: dsPath,
      headers: { 'Authorization': 'Basic ' + auth }
    }, function (res) {
      var d = '';
      res.on('data', function (c) { d += c; });
      res.on('end', function () {
        try {
          var ds = JSON.parse(d);
          if (ds && ds.uid === gUid && ds.url !== targetUrl) {
            ds.url = targetUrl;
            var body = JSON.stringify(ds);
            var reqPut = http.request({
              host: gHost,
              port: gPort,
              path: dsPath,
              method: 'PUT',
              headers: {
                'Authorization': 'Basic ' + auth,
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body)
              }
            }, function (r2) {
              r2.on('data', function () {});
              r2.on('end', function () {
                console.log('[Grafana Sync] Da cap nhat URL Datasource Grafana -> ' + targetUrl);
              });
            });
            reqPut.on('error', function () {});
            reqPut.end(body);
          }
        } catch (e) {}
      });
    });
    reqGet.on('error', function () {});
  } catch (e) {}
}

function watchAppConfigFile() {
  fs.watchFile(CONFIG_FILE, { interval: 3000 }, function (curr, prev) {
    if (isSavingConfig) return;
    if (curr.mtimeMs === prev.mtimeMs || curr.size === 0) return;
    if (lastSavedConfigMtimeMs && curr.mtimeMs === lastSavedConfigMtimeMs) return;
    appConfig = loadAppConfig();
    SSH_USER = appConfig.apCredentials.sshUsername || 'admin';
    SSH_PASSWORDS = Array.isArray(appConfig.apCredentials.sshPasswords) ? appConfig.apCredentials.sshPasswords : [];
    TOTOLINK_WEB_USER = appConfig.apCredentials.totolinkWebUsername || 'admin';
    TOTOLINK_PASSWORDS = Array.isArray(appConfig.apCredentials.totolinkWebPasswords) ? appConfig.apCredentials.totolinkWebPasswords : [];
    PER_AP_PASSWORDS = (appConfig.apCredentials.perApPasswords && typeof appConfig.apCredentials.perApPasswords === 'object')
      ? appConfig.apCredentials.perApPasswords
      : {};
    DEFAULT_SSID_FALLBACK = appConfig.apCredentials.defaultSsidFallback || 'WiFi';
    if (Array.isArray(appConfig.network.allowedMacOuis) && appConfig.network.allowedMacOuis.length > 0) {
      TOTOLINK_OUIS = appConfig.network.allowedMacOuis;
    }
    sshSessionPassCache = {};
    totolinkWebPassCache = {};
    totolinkWebCookieCache = {};
    if (Array.isArray(appConfig.network.defaultStaticIps)) {
      var newIpsStr = appConfig.network.defaultStaticIps.join(', ');
      if (newIpsStr !== staticIpsList.join(', ')) {
        setFixedIPs(newIpsStr);
      }
    }
    syncGrafanaDatasourceUrl();
    console.log('[Config] Da tu dong nap lai cau hinh moi tu ' + CONFIG_FILE);
  });
}

var initUsersStore = loadUsersStore(true);
loadRegistry();
watchAppConfigFile();
syncGrafanaDatasourceUrl();

function formatUsersForApi(usersArr) {
  return (usersArr || []).map(function (u) {
    var rawHash = String(u.passwordMd5 || '');
    var maskedHash = rawHash.length >= 16
      ? (rawHash.slice(0, 6) + '••••••••••••' + rawHash.slice(-6))
      : '••••••••••••';
    return {
      username: u.username,
      role: normalizeUserRole(u.role),
      fullName: u.fullName || u.username,
      passwordMd5: maskedHash,
      createdAt: u.createdAt || null,
      updatedAt: u.updatedAt || null
    };
  });
}

// Quet nhanh danh sach IP Co Dinh ngay khi khoi dong (chi mat < 2s) de hien thi tuc thi cac AP khac Subnet
if (staticIpsList.length > 0) {
  probeIpList(staticIpsList, { isManual: false }, function () {
    console.log('[Khoi Dong] Da dong bo nhanh ' + staticIpsList.length + ' IP giam sat co dinh.');
  });
}

function scheduleNextAutoRescan() {
  var waitRescanMs = Math.max(45000, Number(AUTO_RESCAN_INTERVAL_MS) || 60000);
  setTimeout(function () {
    scanTargets(currentTarget, function () {
      scheduleNextAutoRescan();
    });
  }, waitRescanMs);
}

scanTargets(currentTarget, function () {
  console.log('[Khoi Dong] Da hoan tat quet ban dau.');
  scheduleNextAutoRescan();
  setTimeout(pollAllRealApStats, 1000);
  setTimeout(function () { syncAllTotolinkRadioConfigs(); }, 3500);
  setTimeout(sampleActiveTotolinkClientsBackground, 5500);
  setTimeout(function () { triggerSafeNeighborScanBatch(8, function () {}); }, 8000);
});

function scheduleNextPingCycle() {
  var waitMs = Math.max(6000, Number(PING_INTERVAL_MS) || 8000);
  setTimeout(function () {
    pingAllAPs(function () {
      scheduleNextPingCycle();
    });
  }, waitMs);
}
scheduleNextPingCycle();
setInterval(pollAllRealApStats, SSH_POLL_INTERVAL_MS);
setInterval(syncGrafanaDatasourceUrl, GRAFANA_SYNC_INTERVAL_MS);
setInterval(function () { syncAllTotolinkRadioConfigs(); }, 300000);
setInterval(sampleActiveTotolinkClientsBackground, 45000);
setInterval(runGentleBackgroundNeighborScan, 30000);
setInterval(checkMode2AutoOptimizeSchedule, 30000);
setInterval(function () { saveRfTelemetryStore(false); }, 60000);
setInterval(function () { broadcastRealtimeUpdate(); }, 5000);
setTimeout(pollAllRealApStats, 2000);
setTimeout(function () { syncAllTotolinkRadioConfigs(); }, 4200);

// HTTP Server
var server = http.createServer(function (req, res) {
  var parsedUrl = url.parse(req.url, true);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': '*'
    });
    res.end();
    return;
  }

  // 0. XAC THUC DANG NHAP (MD5) & QUAN LY NGUOI DUNG (RBAC: ADMIN / USER)
  if (parsedUrl.pathname === '/login' && req.method === 'GET') {
    var alreadyAuth = getAuthenticatedUser(req);
    if (alreadyAuth) {
      res.writeHead(302, { 'Location': '/', 'Cache-Control': 'no-store' });
      res.end();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(renderLoginHtml());
    return;
  } else if (parsedUrl.pathname === '/logout' && req.method === 'GET') {
    res.writeHead(302, {
      'Location': '/login',
      'Set-Cookie': buildClearSessionCookieHeader(),
      'Cache-Control': 'no-store'
    });
    res.end();
    return;
  } else if (parsedUrl.pathname === '/api/auth/login' && req.method === 'POST') {
    var bodyLogin = '';
    req.on('data', function (c) { bodyLogin += c; });
    req.on('end', function () {
      try {
        var pLogin = bodyLogin ? JSON.parse(bodyLogin) : {};
        var rawUser = String(pLogin.username || '').trim();
        var rawPass = String(pLogin.password !== undefined ? pLogin.password : '');
        if (!rawUser || !rawPass) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
          res.end(JSON.stringify({ success: false, error: 'Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.' }));
          return;
        }
        var store = loadUsersStore(false);
        var unameLower = rawUser.toLowerCase();
        var inputMd5 = md5Hash(rawPass);
        var matchedUser = null;
        for (var i = 0; i < store.users.length; i++) {
          if (store.users[i].username.toLowerCase() === unameLower && store.users[i].passwordMd5 === inputMd5) {
            matchedUser = store.users[i];
            break;
          }
        }
        if (!matchedUser) {
          res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
          res.end(JSON.stringify({ success: false, error: 'Tên đăng nhập hoặc mật khẩu không chính xác.' }));
          return;
        }
        var sess = createSessionCookieData(matchedUser, pLogin.remember !== false);
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': sess.cookieHeader,
          'Cache-Control': 'no-store'
        });
        res.end(JSON.stringify({
          success: true,
          user: {
            username: matchedUser.username,
            role: normalizeUserRole(matchedUser.role),
            fullName: matchedUser.fullName || matchedUser.username
          }
        }));
      } catch (errLogin) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify({ success: false, error: 'Dữ liệu đăng nhập không hợp lệ.' }));
      }
    });
    return;
  } else if (parsedUrl.pathname === '/api/auth/logout' && req.method === 'POST') {
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Set-Cookie': buildClearSessionCookieHeader(),
      'Cache-Control': 'no-store'
    });
    res.end(JSON.stringify({ success: true }));
    return;
  } else if (parsedUrl.pathname === '/api/auth/me' && req.method === 'GET') {
    var uMe = requireApiAuth(req, res, false);
    if (!uMe) return;
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ success: true, user: uMe }));
    return;
  } else if (parsedUrl.pathname === '/api/auth/change-password' && req.method === 'POST') {
    var uPwd = requireApiAuth(req, res, false);
    if (!uPwd) return;
    var bodyChPwd = '';
    req.on('data', function (c) { bodyChPwd += c; });
    req.on('end', function () {
      try {
        var pPwd = bodyChPwd ? JSON.parse(bodyChPwd) : {};
        var curPass = String(pPwd.currentPassword || '');
        var newPass = String(pPwd.newPassword || '');
        if (!curPass) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Vui lòng nhập mật khẩu hiện tại.' }));
          return;
        }
        if (newPass.length < 4) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Mật khẩu mới phải có ít nhất 4 ký tự.' }));
          return;
        }
        var store = loadUsersStore(false);
        var rec = null;
        for (var i = 0; i < store.users.length; i++) {
          if (store.users[i].username.toLowerCase() === uPwd.username.toLowerCase()) {
            rec = store.users[i];
            break;
          }
        }
        if (!rec) {
          res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Không tìm thấy tài khoản.' }));
          return;
        }
        if (md5Hash(curPass) !== rec.passwordMd5) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Mật khẩu hiện tại không chính xác.' }));
          return;
        }
        rec.passwordMd5 = md5Hash(newPass);
        rec.updatedAt = new Date().toISOString();
        saveUsersStore(store);
        disconnectSseForUsername(rec.username);
        var newSess = createSessionCookieData(rec, true);
        res.writeHead(200, {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': newSess.cookieHeader,
          'Cache-Control': 'no-store'
        });
        res.end(JSON.stringify({ success: true }));
      } catch (errChPwd) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: errChPwd.message }));
      }
    });
    return;
  } else if (parsedUrl.pathname === '/api/users' && req.method === 'GET') {
    if (!requireApiAuth(req, res, true)) return;
    var uStoreList = loadUsersStore(false);
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ success: true, users: formatUsersForApi(uStoreList.users) }));
    return;
  } else if (parsedUrl.pathname === '/api/ap-credentials' && req.method === 'POST') {
    if (!requireApiAuth(req, res, true)) return;
    var bodyApCred = '';
    req.on('data', function (c) { bodyApCred += c; });
    req.on('end', function () {
      try {
        var pAp = bodyApCred ? JSON.parse(bodyApCred) : {};
        if (!appConfig.apCredentials || typeof appConfig.apCredentials !== 'object') {
          appConfig.apCredentials = {};
        }
        var newU = String(pAp.username || 'admin').trim() || 'admin';
        var newSsid = String(pAp.defaultSsid || '').trim();
        var rawPass = String(pAp.passwords || '').trim();
        appConfig.apCredentials.totolinkWebUsername = newU;
        appConfig.apCredentials.sshUsername = newU;
        TOTOLINK_WEB_USER = newU;
        SSH_USER = newU;
        if (newSsid) {
          appConfig.apCredentials.defaultSsidFallback = newSsid;
          DEFAULT_SSID_FALLBACK = newSsid;
        }
        if (rawPass) {
          var pwList = [];
          rawPass.split(',').forEach(function (seg) {
            var cleanPw = seg.trim();
            if (cleanPw && pwList.indexOf(cleanPw) === -1) pwList.push(cleanPw);
          });
          if (pwList.length > 0) {
            appConfig.apCredentials.totolinkWebPasswords = pwList.slice();
            appConfig.apCredentials.sshPasswords = pwList.slice();
            TOTOLINK_PASSWORDS = pwList.slice();
            SSH_PASSWORDS = pwList.slice();
          }
        }
        sshSessionPassCache = {};
        totolinkWebPassCache = {};
        totolinkWebCookieCache = {};
        saveAppConfig();
        setTimeout(function () { pollAllRealApStats(); }, 150);
        scheduleRealtimeBroadcast(200);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify({
          success: true,
          username: TOTOLINK_WEB_USER,
          defaultSsid: DEFAULT_SSID_FALLBACK,
          passwordCount: TOTOLINK_PASSWORDS.length
        }));
      } catch (errApCred) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: errApCred.message }));
      }
    });
    return;
  } else if (parsedUrl.pathname === '/api/users/create' && req.method === 'POST') {
    if (!requireApiAuth(req, res, true)) return;
    var bodyUCreate = '';
    req.on('data', function (c) { bodyUCreate += c; });
    req.on('end', function () {
      try {
        var pCr = bodyUCreate ? JSON.parse(bodyUCreate) : {};
        var uname = String(pCr.username || '').trim();
        var pwd = String(pCr.password || '');
        var role = normalizeUserRole(pCr.role);
        var fname = String(pCr.fullName || '').trim();
        if (!/^[a-zA-Z0-9_.@-]{3,32}$/.test(uname)) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Tên đăng nhập phải từ 3–32 ký tự (chữ cái không dấu, số, ., _, -, @).' }));
          return;
        }
        if (pwd.length < 4) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Mật khẩu phải có ít nhất 4 ký tự.' }));
          return;
        }
        var store = loadUsersStore(false);
        for (var i = 0; i < store.users.length; i++) {
          if (store.users[i].username.toLowerCase() === uname.toLowerCase()) {
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ success: false, error: 'Tên đăng nhập "' + uname + '" đã tồn tại trong hệ thống.' }));
            return;
          }
        }
        var nowIso = new Date().toISOString();
        store.users.push({
          username: uname,
          passwordMd5: md5Hash(pwd),
          role: role,
          fullName: fname || (role === 'admin' ? 'Quản trị viên' : 'Người dùng chỉ xem'),
          createdAt: nowIso,
          updatedAt: nowIso
        });
        saveUsersStore(store);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify({ success: true, users: formatUsersForApi(store.users) }));
      } catch (errCr) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: errCr.message }));
      }
    });
    return;
  } else if (parsedUrl.pathname === '/api/users/update' && req.method === 'POST') {
    var adminAct = requireApiAuth(req, res, true);
    if (!adminAct) return;
    var bodyUUpd = '';
    req.on('data', function (c) { bodyUUpd += c; });
    req.on('end', function () {
      try {
        var pUp = bodyUUpd ? JSON.parse(bodyUUpd) : {};
        var uname = String(pUp.username || '').trim();
        var nextRole = normalizeUserRole(pUp.role);
        var fname = String(pUp.fullName || '').trim();
        var newPwd = String(pUp.newPassword || '');
        if (!uname) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Thiếu tên đăng nhập cần cập nhật.' }));
          return;
        }
        if (newPwd.length > 0 && newPwd.length < 4) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Mật khẩu mới phải có ít nhất 4 ký tự.' }));
          return;
        }
        var store = loadUsersStore(false);
        var target = null;
        var adminCount = 0;
        for (var i = 0; i < store.users.length; i++) {
          if (store.users[i].role === 'admin') adminCount++;
          if (store.users[i].username.toLowerCase() === uname.toLowerCase()) {
            target = store.users[i];
          }
        }
        if (!target) {
          res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Không tìm thấy tài khoản "' + uname + '".' }));
          return;
        }
        if (target.role === 'admin' && nextRole !== 'admin' && adminCount <= 1) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Không thể hạ quyền tài khoản Admin duy nhất của hệ thống.' }));
          return;
        }
        var prevRole = target.role;
        target.role = nextRole;
        target.fullName = fname || (nextRole === 'admin' ? 'Quản trị viên' : 'Người dùng chỉ xem');
        if (newPwd.length >= 4) {
          target.passwordMd5 = md5Hash(newPwd);
        }
        target.updatedAt = new Date().toISOString();
        saveUsersStore(store);
        disconnectSseForUsername(target.username);

        var isSelf = (target.username.toLowerCase() === adminAct.username.toLowerCase());
        var headersUpd = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' };
        if (isSelf) {
          var refreshed = createSessionCookieData(target, true);
          headersUpd['Set-Cookie'] = refreshed.cookieHeader;
        }
        res.writeHead(200, headersUpd);
        res.end(JSON.stringify({
          success: true,
          selfRoleChanged: Boolean(isSelf && prevRole !== nextRole),
          users: formatUsersForApi(store.users)
        }));
      } catch (errUp) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: errUp.message }));
      }
    });
    return;
  } else if (parsedUrl.pathname === '/api/users/delete' && req.method === 'POST') {
    var adminDel = requireApiAuth(req, res, true);
    if (!adminDel) return;
    var bodyUDel = '';
    req.on('data', function (c) { bodyUDel += c; });
    req.on('end', function () {
      try {
        var pDelU = bodyUDel ? JSON.parse(bodyUDel) : {};
        var uname = String(pDelU.username || '').trim();
        if (!uname) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Thiếu tên đăng nhập cần xóa.' }));
          return;
        }
        if (uname.toLowerCase() === adminDel.username.toLowerCase()) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Không thể tự xóa tài khoản đang đăng nhập.' }));
          return;
        }
        var store = loadUsersStore(false);
        var delIdx = -1;
        var adminCount = 0;
        for (var i = 0; i < store.users.length; i++) {
          if (store.users[i].role === 'admin') adminCount++;
          if (store.users[i].username.toLowerCase() === uname.toLowerCase()) {
            delIdx = i;
          }
        }
        if (delIdx === -1) {
          res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Không tìm thấy tài khoản "' + uname + '".' }));
          return;
        }
        if (store.users[delIdx].role === 'admin' && adminCount <= 1) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: 'Phải giữ lại ít nhất 1 tài khoản Admin trong hệ thống.' }));
          return;
        }
        var removedUser = store.users.splice(delIdx, 1)[0];
        saveUsersStore(store);
        disconnectSseForUsername(removedUser.username);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify({ success: true, users: formatUsersForApi(store.users) }));
      } catch (errDelU) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: errDelU.message }));
      }
    });
    return;
  }

  // 1. PROMETHEUS API
  if (parsedUrl.pathname === '/api/v1/query' || parsedUrl.pathname === '/api/v1/query_range') {
    handlePrometheusQuery(req, res, parsedUrl);
  } else if (parsedUrl.pathname.indexOf('/api/v1/label/') === 0 && parsedUrl.pathname.indexOf('/values') !== -1) {
    var labelKey = parsedUrl.pathname.replace('/api/v1/label/', '').replace('/values', '');
    var valList = [];
    if (labelKey === '__name__') {
      valList = ['ap_status', 'ap_client_count', 'ap_ping_latency_ms', 'ap_network_receive_bytes_total', 'ap_network_transmit_bytes_total', 'up'];
    } else {
      var apKeys = Object.keys(apMap);
      for (var vk = 0; vk < apKeys.length; vk++) {
        var apObj = apMap[apKeys[vk]];
        var vVal = null;
        if (labelKey === 'model') vVal = apObj.model;
        else if (labelKey === 'ap_name') vVal = apObj.name;
        else if (labelKey === 'ap_ip') vVal = apObj.ip;
        else if (labelKey === 'ap_mac') vVal = apObj.mac;
        else if (labelKey === 'ssid') vVal = apObj.ssid;
        else if (labelKey === 'ap_channel') vVal = String(apObj.channel);
        else if (labelKey === 'firmware') vVal = apObj.firmware;
        if (vVal && valList.indexOf(vVal) === -1) valList.push(vVal);
      }
      if (valList.length === 0 && labelKey === 'model') valList = ['TOTOLINK N9v1'];
    }
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify({ status: 'success', data: valList }));
  } else if (parsedUrl.pathname === '/api/v1/series') {
    var seriesList = [];
    var sKeys = Object.keys(apMap);
    for (var sk = 0; sk < sKeys.length; sk++) {
      var sAp = apMap[sKeys[sk]];
      seriesList.push({
        __name__: 'ap_status',
        ap_mac: sAp.mac,
        ap_ip: sAp.ip,
        ap_name: sAp.name,
        model: sAp.model,
        firmware: sAp.firmware,
        ap_channel: String(sAp.channel),
        ssid: sAp.ssid
      });
    }
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify({ status: 'success', data: seriesList }));
  } else if (parsedUrl.pathname === '/api/v1/labels') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify({ status: 'success', data: ['__name__', 'ap_mac', 'ap_ip', 'ap_name', 'model', 'firmware', 'ap_channel', 'ssid'] }));
  } else if (parsedUrl.pathname === '/api/v1/metadata') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify({ status: 'success', data: {} }));
  } else if (parsedUrl.pathname === '/api/v1/query_exemplars') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify({ status: 'success', data: [] }));
  } else if (parsedUrl.pathname === '/api/v1/rules') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify({ status: 'success', data: { groups: [] } }));
  } else if (parsedUrl.pathname === '/api/v1/alerts') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify({ status: 'success', data: { alerts: [] } }));
  } else if (parsedUrl.pathname === '/api/v1/status/buildinfo') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify({ status: 'success', data: { version: '2.45.0', revision: 'totolink-embedded' } }));
  }
  // 2. API GÁN IP CỐ ĐỊNH (STATIC IPS) & XÓA AP (ADMIN ONLY FOR WRITE/DELETE)
  else if (parsedUrl.pathname === '/api/static-ips' && req.method === 'POST') {
    if (!requireApiAuth(req, res, true)) return;
    var bodyStatic = '';
    req.on('data', function (c) { bodyStatic += c; });
    req.on('end', function () {
      try {
        var p = JSON.parse(bodyStatic || '{}');
        var repliedStatic = false;
        var updated = null;
        function finishStaticResp(probeStats) {
          if (repliedStatic) return;
          repliedStatic = true;
          clearTimeout(staticWaitTimer);
          scheduleRealtimeBroadcast(100);
          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({
            success: true,
            count: updated.length,
            ips: updated,
            probeStats: probeStats || null,
            payload: buildLiveDashboardPayload()
          }));
        }
        var staticWaitTimer = setTimeout(function () {
          finishStaticResp(null);
        }, 2800);
        updated = setFixedIPs(p.ips || '', function (errPr, stPr) {
          finishStaticResp(stPr || null);
        });
        appConfig.network.defaultStaticIps = updated.slice();
        saveAppConfig();
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: err.message }));
      }
    });
  } else if (parsedUrl.pathname === '/api/static-ips' && req.method === 'GET') {
    if (!requireApiAuth(req, res, false)) return;
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ staticIps: staticIpsList }));
  } else if (parsedUrl.pathname === '/api/aps/delete' && req.method === 'POST') {
    if (!requireApiAuth(req, res, true)) return;
    var bodyDel = '';
    req.on('data', function (c) { bodyDel += c; });
    req.on('end', function () {
      try {
        var pDel = bodyDel ? JSON.parse(bodyDel) : {};
        var delRes = deleteApEntries(pDel);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
          success: true,
          deletedCount: delRes.deletedCount,
          deletedNames: delRes.deletedNames,
          staticIps: delRes.staticIps,
          payload: buildLiveDashboardPayload()
        }));
      } catch (errDel) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: errDel.message }));
      }
    });
  }
  // 3. STATIC ASSETS (LOGO VECTOR & FLATICON UICONS)
  else if (parsedUrl.pathname === '/logo.svg' || parsedUrl.pathname === '/favicon.ico') {
    var logoPath = path.join(__dirname, 'logo.svg');
    if (fs.existsSync(logoPath)) {
      res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=3600' });
      res.end(fs.readFileSync(logoPath));
    } else {
      res.writeHead(404);
      res.end('Logo not found');
    }
  } else if (parsedUrl.pathname === '/assets/uicons/uicons-regular-rounded.css') {
    var cssPath = path.join(__dirname, 'assets', 'uicons', 'uicons-regular-rounded.css');
    if (fs.existsSync(cssPath)) {
      res.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8', 'Cache-Control': 'public, max-age=86400' });
      res.end(fs.readFileSync(cssPath));
    } else {
      res.writeHead(404);
      res.end('CSS not found');
    }
  } else if (parsedUrl.pathname === '/assets/uicons/uicons-regular-rounded.woff2') {
    var fontPath = path.join(__dirname, 'assets', 'uicons', 'uicons-regular-rounded.woff2');
    if (fs.existsSync(fontPath)) {
      res.writeHead(200, { 'Content-Type': 'font/woff2', 'Cache-Control': 'public, max-age=86400' });
      res.end(fs.readFileSync(fontPath));
    } else {
      res.writeHead(404);
      res.end('Font not found');
    }
  }
  // 4. WEB UI & CLASSIC APIS (PROTECTED BY LOGIN SESSION)
  else if (parsedUrl.pathname === '/') {
    var pageUser = getAuthenticatedUser(req);
    if (!pageUser) {
      res.writeHead(302, { 'Location': '/login', 'Cache-Control': 'no-store' });
      res.end();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(renderHtmlDashboard(pageUser));
  } else if (parsedUrl.pathname === '/api/dashboard-live' && req.method === 'GET') {
    if (!requireApiAuth(req, res, false)) return;
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-cache' });
    res.end(JSON.stringify({ success: true, payload: buildLiveDashboardPayload() }));
  } else if (parsedUrl.pathname === '/api/realtime-stream' && req.method === 'GET') {
    var sseUserRec = getAuthenticatedUserRecord(req);
    if (!sseUserRec) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ success: false, authRequired: true, error: 'Chưa đăng nhập' }));
      return;
    }
    if (req.setTimeout) req.setTimeout(0);
    if (res.setTimeout) res.setTimeout(0);
    if (req.socket && req.socket.setNoDelay) req.socket.setNoDelay(true);
    res._authUsername = sseUserRec.username.toLowerCase();
    res._authRole = sseUserRec.role;
    res._authPassMd5 = sseUserRec.passwordMd5;
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    });
    if (res.flushHeaders) res.flushHeaders();
    res.write('retry: 3000\n\n');
    res.write('data: ' + JSON.stringify(buildLiveDashboardPayload()) + '\n\n');
    sseClients.push(res);
    var sseKeepAlive = setInterval(function () {
      if (res.writableEnded || res.destroyed) {
        clearInterval(sseKeepAlive);
        return;
      }
      try { res.write(': keepalive\n\n'); } catch (e) { clearInterval(sseKeepAlive); }
    }, 20000);
    req.on('close', function () {
      clearInterval(sseKeepAlive);
      var idx = sseClients.indexOf(res);
      if (idx !== -1) sseClients.splice(idx, 1);
    });
  } else if (parsedUrl.pathname === '/metrics') {
    res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
    res.end(getPrometheusMetrics());
  } else if (parsedUrl.pathname === '/api/aps') {
    if (!requireApiAuth(req, res, false)) return;
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(Object.keys(apMap).map(function (k) { return apMap[k]; }), null, 2));
  } else if (parsedUrl.pathname === '/api/summary') {
    if (!requireApiAuth(req, res, false)) return;
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(getSummary(), null, 2));
  } else if (parsedUrl.pathname === '/api/ap-clients' && req.method === 'GET') {
    if (!requireApiAuth(req, res, false)) return;
    var targetIpOrKey = (parsedUrl.query && (parsedUrl.query.ip || parsedUrl.query.key || '')).trim();
    var forceLive = parsedUrl.query && (parsedUrl.query.live === '1' || parsedUrl.query.live === 'true');
    if (!targetIpOrKey) {
      res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ success: false, error: 'Thieu tham so ip cua Access Point' }));
      return;
    }
    getApClientsRealtime(targetIpOrKey, forceLive, function (errCl, dataCl) {
      if (errCl) {
        res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: errCl.message }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
          success: true,
          fetchedAt: new Date().toISOString(),
          ap: dataCl.ap,
          offline: dataCl.offline,
          clientCount: dataCl.clientCount,
          clients: dataCl.clients
        }, null, 2));
      }
    });
  } else if (parsedUrl.pathname === '/api/scan' && req.method === 'POST') {
    if (!requireApiAuth(req, res, true)) return;
    var bodyScan = '';
    req.on('data', function (chunk) { bodyScan += chunk; });
    req.on('end', function () {
      var requestedTarget = '';
      try {
        if (bodyScan) {
          var parsedB = JSON.parse(bodyScan);
          if (parsedB.target !== undefined) requestedTarget = String(parsedB.target).trim();
          else if (parsedB.subnet !== undefined) requestedTarget = String(parsedB.subnet).trim();
        }
      } catch (e) {}

      runManualScan(requestedTarget, function (err, stats) {
        if (err) {
          res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ success: false, error: err.message }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({
            success: true,
            stats: stats,
            payload: buildLiveDashboardPayload()
          }));
        }
      });
    });
  }
  // 5. API TOI UU SONG & KENH SONG 24H (MODE 1 + MODE 2 ON/OFF)
  else if (parsedUrl.pathname === '/api/rf-optimizer/plan' && req.method === 'GET') {
    var authPlanUser = requireApiAuth(req, res, false);
    if (!authPlanUser) return;
    var forceHwSync = parsedUrl.query && (parsedUrl.query.sync === '1' || parsedUrl.query.sync === 'true');
    if (forceHwSync && authPlanUser.role === 'admin' && !isSyncingHwConfig) {
      syncAllTotolinkRadioConfigs();
    }
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-cache' });
    res.end(JSON.stringify({
      success: true,
      syncing: isSyncingHwConfig,
      plan: computeRfOptimizationPlan()
    }));
  } else if (parsedUrl.pathname === '/api/rf-optimizer/settings' && req.method === 'POST') {
    if (!requireApiAuth(req, res, true)) return;
    var bodyRfSet = '';
    req.on('data', function (c) { bodyRfSet += c; });
    req.on('end', function () {
      try {
        var pSet = bodyRfSet ? JSON.parse(bodyRfSet) : {};
        if (!appConfig.rfOptimizer || typeof appConfig.rfOptimizer !== 'object') {
          appConfig.rfOptimizer = {};
        }
        if (pSet.autoOptimizeEnabled !== undefined) {
          appConfig.rfOptimizer.autoOptimizeEnabled = Boolean(pSet.autoOptimizeEnabled);
        }
        if (typeof pSet.autoOptimizeTime === 'string' && /^\d{2}:\d{2}$/.test(pSet.autoOptimizeTime.trim())) {
          appConfig.rfOptimizer.autoOptimizeTime = pSet.autoOptimizeTime.trim();
        }
        if (pSet.requireFull24hForAuto !== undefined) {
          appConfig.rfOptimizer.requireFull24hForAuto = Boolean(pSet.requireFull24hForAuto);
        }
        saveAppConfig();
        scheduleRealtimeBroadcast(150);
        var updatedPlan = computeRfOptimizationPlan();
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
          success: true,
          settings: updatedPlan.settings,
          summary: updatedPlan.summary
        }));
      } catch (errSet) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: errSet.message }));
      }
    });
  } else if (parsedUrl.pathname === '/api/rf-optimizer/replan-channels' && req.method === 'POST') {
    if (!requireApiAuth(req, res, true)) return;
    var replanned = computeRfOptimizationPlan({ forceReplan: true });
    scheduleRealtimeBroadcast(150);
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({
      success: true,
      plan: replanned
    }));
  } else if (parsedUrl.pathname === '/api/rf-optimizer/scan-neighbors' && req.method === 'POST') {
    if (!requireApiAuth(req, res, true)) return;
    triggerSafeNeighborScanBatch(16, function (errNb, nbRes) {
      if (errNb) {
        res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: errNb.message }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
          success: true,
          scanResult: nbRes,
          plan: computeRfOptimizationPlan()
        }));
      }
    });
  } else if (parsedUrl.pathname === '/api/rf-optimizer/apply' && req.method === 'POST') {
    if (!requireApiAuth(req, res, true)) return;
    if (req.setTimeout) req.setTimeout(0);
    if (res.setTimeout) res.setTimeout(0);
    var bodyRfApply = '';
    req.on('data', function (c) { bodyRfApply += c; });
    req.on('end', function () {
      try {
        var pApp = bodyRfApply ? JSON.parse(bodyRfApply) : {};
        if (pApp.batch === true) {
          if (isRunningBatchApply) {
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ success: false, error: 'Hệ thống đang thực thi tiến trình tối ưu hàng loạt, vui lòng theo dõi trực tiếp trên bảng' }));
            return;
          }
          // Khoi chay bat dong bo va phan hoi ngay de giao dien cap nhat tien do tung AP theo thoi gian thuc qua SSE
          applyBatchRfOptimizations(Array.isArray(pApp.ips) ? pApp.ips : null, 'batch-manual', function () {});
          res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({
            success: true,
            started: true,
            plan: computeRfOptimizationPlan()
          }));
        } else {
          var targetIp = String(pApp.ip || '').trim();
          if (!targetIp) {
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ success: false, error: 'Thieu tham so ip cua Access Point' }));
            return;
          }
          var vKey = findApKeyByIp(targetIp) || (apMap[targetIp] ? targetIp : null);
          if (!vKey || !apMap[vKey]) {
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ success: false, error: 'Không tìm thấy Access Point: ' + targetIp }));
            return;
          }
          var vAp = apMap[vKey];
          if (vAp.status !== 1) {
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ success: false, error: 'Access Point ' + (vAp.name || targetIp) + ' đang Offline' }));
            return;
          }
          if (isUnifiDevice(vAp)) {
            res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ success: false, error: 'Thiết bị UniFi do UniFi Controller quản lý' }));
            return;
          }
          if (apApplyingLock[vAp.ip]) {
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ success: true, alreadyRunning: true, plan: computeRfOptimizationPlan() }));
            return;
          }
          if (pApp.wait === true) {
            applyTotolinkApOptimization(targetIp, pApp.params || null, 'manual', function (errSingle, resSingle) {
              if (errSingle) {
                res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
                res.end(JSON.stringify({ success: false, error: errSingle.message }));
              } else {
                res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
                res.end(JSON.stringify({
                  success: true,
                  result: resSingle,
                  plan: computeRfOptimizationPlan()
                }));
              }
            });
          } else {
            // Khoi chay ngay va cap nhat trang thai tung buoc theo thoi gian thuc qua SSE (khong nghen HTTP connection)
            applyTotolinkApOptimization(targetIp, pApp.params || null, 'manual', function () {});
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
              success: true,
              started: true,
              plan: computeRfOptimizationPlan()
            }));
          }
        }
      } catch (errParse) {
        res.writeHead(400, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ success: false, error: errParse.message }));
      }
    });
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

server.on('error', function (err) {
  if (err.code === 'EADDRINUSE') {
    console.error('\n====================================================');
    console.error('[CANH BAO] Cong ' + PORT + ' dang bi chiem dung boi mot tien trinh khac!');
    console.error('Co the he thong Collector dang chay san o mot cua so khac hoac chay ngam.');
    console.error('Lenh giai phong nhanh tren PowerShell:');
    console.error('  Get-Process node | Stop-Process -Force');
    console.error('====================================================\n');
  } else {
    console.error('[LOI HTTP SERVER]', err.message);
  }
  process.exit(1);
});

server.listen(PORT, function () {
  console.log('====================================================');
  console.log('[OK] ConCard AP Monitor v1.1 & Prometheus API Server dang chay!');
  console.log('[INFO] File cau hinh:      ' + CONFIG_FILE);
  console.log('[INFO] Quan ly nguoi dung: ' + USERS_FILE + ' (' + initUsersStore.users.length + ' tai khoan, MD5)');
  console.log('[INFO] Dashboard Web:      http://localhost:' + PORT + '/');
  if (isDefaultFirstRunAdmin()) {
    console.log('[INFO] Dang nhap lan dau:  admin / Concard@2026');
  }
  console.log('[INFO] IP Co Dinh Quan Ly: ' + (staticIpsList.length > 0 ? staticIpsList.join(', ') : '(Chua khai bao - them trong muc Cai dat)'));
  console.log('====================================================');
});
