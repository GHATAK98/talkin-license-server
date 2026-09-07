#!/usr/bin/env node
/**
 * TALKIN LIMITED EDITION — CUSTOM LICENSE SERVER (Zero Dependencies)
 * ================================================================
 * Ye server tumhare APK ke CRYPTO_API_URL ko serve karta hai.
 * Node.js 18+ required (Ed25519 + built-in fetch nahi chahiye, sirf node:crypto).
 * 
 * Chalane ka tarika:
 *   node license-server.js
 *   PORT=443 node license-server.js   (production)
 * 
 * Endpoints (APK inhe call karta hai):
 *   GET  /v1/sys/status          → server alive
 *   GET  /v1/sys/build           → build info (update gate control)
 *   GET  /v1/sys/announcement    → announcement banner
 *   GET  /v1/catalog/plans       → plans list
 *   GET  /v1/catalog/accounts    → accounts catalog
 *   GET  /v1/catalog/feature-prices → feature prices
 *   GET  /v1/session/entitlement → SIGNED entitlement (Ed25519)
 *   GET  /v1/session/key         → KeyInfo (key state)
 *   POST /v1/session/push        → profile push (no-op)
 *   POST /v1/session/accounts/sync → accounts sync (no-op)
 *   GET  /v1/device/profiles     → device list of key
 *   GET  /v1/device/issue        → device ID issue
 *   POST /v1/sec/enc/...         → AES-CBC encrypt (passthrough)
 *   POST /v1/sec/dec/...         → AES-CBC decrypt (passthrough)
 *
 * Sab kuch data.json me save hota hai (keys, devices, entitlements).
 * Admin CLI: node admin.js (keys banane/hatane/list karne ke liye)
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ================= CONFIG =================
const PORT = parseInt(process.env.PORT || '8080', 10);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_FILE = path.join(__dirname, 'data.json');

// ⚠️ YE TUMHARE HAI — gen_ed25519.py se generate kiya tha:
const ENTITLEMENT_PRIVATE_SEED_HEX = 'd43aea30efde2b7547593380cf87c666dc17308b6f81f913a6fac44e288e5965';
const ENTITLEMENT_PUBLIC_KEY_HEX = 'fa4fe3104d4e5858a55e8571ba012b27d3bc05e89fd5ab5206bb486e69934fba';

// NOTE: BuildConfig me APP_SIGNING_SECRET ko "" (empty) patch kar rahe hain.
// Decompiled code case 37 me hai: if(!signingSecret) return {} — client sign NAHI karega.
// Isliye server-side HMAC verify ki zaroorat nahi. Ye secret sirf ADMIN API ke liye hai:
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'MAHADEV@74651';

// APK request signature verify karna? (client ab sign nahi karta, to false hi rakhna safe hai)
const VERIFY_REQUEST_SIGNATURE = false;

// Payload version (client expects this 'v' in entitlement payload)
// VERIFIED from decompiled JS: r4 = 2 → v must === 2 (storage key bhi entitlement.v2 hai)
const PAYLOAD_VERSION = 2;

// Key prefix (nayi keys REX_ se start hoti hain; purani fool403_ keys bhi valid rahengi - full string match hota hai)
const KEY_PREFIX = 'REX_';

// ================= STORAGE =================
let DB = {
  keys: {},        // { key: {discord_id, key_type, description, is_active, max_devices, max_accounts, devices: [], plan: {...}, lock_until: 0, note} }
  devices: {},     // { deviceId: {key, last_seen, name} }
  announcement: null,
  initialized: false
};

function saveDb() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(DB, null, 2));
}
// IMPORTANT: admin CLI ke changes turant pick karne ke liye har request pe re-read karo
// (CLI aur server dono same data.json pe kaam karte hain — no restart needed)
function loadDb() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      DB = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
  } catch (e) {
    console.error('[db] load failed, using in-memory:', e.message);
  }
  if (!DB.keys) DB.keys = {};
  if (!DB.devices) DB.devices = {};
}

// ================= CRYPTO HELPERS =================
function sha256hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

// Client: keyFingerprint(key) = SHA256("tl-key:" + key).hex.slice(0,32)
function keyFingerprint(key) {
  return sha256hex('tl-key:' + (key || '')).slice(0, 32);
}
// Client: deviceFingerprint(id) = SHA256("tl-dev:" + id).hex.slice(0,32)
function deviceFingerprint(id) {
  return sha256hex('tl-dev:' + (id || '')).slice(0, 32);
}

// Ed25519 sign (node:crypto)
const seedBytes = Buffer.from(ENTITLEMENT_PRIVATE_SEED_HEX, 'hex');
const privObj = crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seedBytes]),
  format: 'der',
  type: 'pkcs8'
});
const pubObj = crypto.createPublicKey(privObj);

function signDetached(msgBytes) {
  return crypto.sign(null, msgBytes, privObj);  // Ed25519 detached
}
function verifyDetached(msgBytes, sigBytes) {
  try {
    return crypto.verify(null, msgBytes, pubObj, sigBytes);
  } catch { return false; }
}

// ================= REQUEST SIGNATURE VERIFY (HMAC) =================
// Client: sig = HMAC-SHA256(secret, [METHOD, path, body||'', ts, nonce, SHA256(body).hex].map(x => x.length+':+x).join('|'))
function verifyHmac(req, bodyBuf, headers) {
  if (!VERIFY_REQUEST_SIGNATURE) return { ok: true };
  const sig = headers['x-signature'];
  const ts = headers['x-timestamp'];
  const nonce = headers['x-nonce'];
  if (!sig || !ts || !nonce) return { ok: false, reason: 'missing_signature_headers' };
  const bodyStr = bodyBuf.length ? bodyBuf.toString('utf8') : '';
  // FIX: empty body pe bhi SHA256('') = e3b0c442... hona chahiye (client hamesha hash karta hai)
  const bodyHash = sha256hex(bodyStr);
  const parts = [
    req.method.toUpperCase(),
    req.url,               // path (+query) exactly as requested
    bodyStr,
    String(ts),
    String(nonce),
    bodyHash
  ];
  const msg = parts.map(x => x.length + ':' + x).join('|');
  const expect = crypto.createHmac('sha256', ADMIN_SECRET).update(msg).digest('hex');
  if (expect.length !== sig.length) return { ok: false, reason: 'sig_length' };
  const a = Buffer.from(expect, 'hex'); const b = Buffer.from(sig, 'hex');
  if (a.length !== b.length) return { ok: false, reason: 'sig_mismatch' };
  if (!crypto.timingSafeEqual(a, b)) return { ok: false, reason: 'sig_mismatch' };
  // Timestamp freshness (±5 min)
  const now = Math.floor(Date.now() / 1000);
  const tsNum = parseInt(ts, 10);
  if (Math.abs(now - tsNum) > 300) return { ok: false, reason: 'stale_timestamp' };
  return { ok: true };
}

// ================= ENTITLEMENT BUILDER =================
// NOTE (decompiled se verified):
//  - v: 2 expected
//  - exp: SECONDS epoch (client: Date.now()/1000 > exp → expired)
//    string "12345" bhejo → typeof !== 'bigint' → expiry check skip (client quirk)
//    Hmm... actually string bhejne pe JSON.parse string dega, typeof 'string' → check skip.
//    SAFE approach: number in seconds bhejo (valid expiry enforce hota hai).
//  - voice_config me sab fields bigint-checked hain — JSON me bigint impossible,
//    client Number.isFinite check karta hai aur defaults (1000000/70/70/400) use karta hai.
//    Isliye voice_config payload me OMIT karo — client defaults apply kar dega.
function buildEntitlementPayload(keyRec, deviceId) {
  const now = Date.now();
  const plan = keyRec.plan || null;
  // Key expiry (plan.expires_at) se entitlement exp derive karo (min 1h buffer)
  const planExpMs = plan && plan.expires_at ? plan.expires_at : (now + 365 * 24 * 60 * 60 * 1000);
  // Entitlement exp = min(plan expiry, now+24h refresh cycle)
  const expMs = Math.min(planExpMs, now + 24 * 60 * 60 * 1000);
  const expSec = Math.floor(expMs / 1000);
  const features = plan && plan.features ? plan.features : {
    prank: true, boost: true, antidelete: true, antimicmute: true, antimicremove: true,
    antivoiceroomleave: true, isvoiceeffect: true, issoundbox: true,
    isimgprank: true, isstickerprank: true, ismusicbot: true, isantiban: true
  };
  return {
    v: PAYLOAD_VERSION,
    kf: keyFingerprint(keyRec.key),
    df: deviceFingerprint(deviceId),
    exp: String(expSec),   // SECONDS (client Date.now()/1000 se compare)
    features: features,
    max_accounts: keyRec.max_accounts || 3,
    max_accounts_ceiling: keyRec.max_accounts || 3,
    use_device_id: true,
    devices: (keyRec.devices || []).map(d => (typeof d === 'string' ? { id: d } : d)),
    max_devices: keyRec.max_devices || 2,
    max_devices_ceiling: keyRec.max_devices || 2,
    hasKey: true,
    key_type: keyRec.key_type || 'standard',
    active_plan: plan ? {
      id: plan.id || 'plan_pro',
      name: plan.name || 'Pro',
      expires_at: plan.expires_at ? String(plan.expires_at) : null
    } : null,
    lock: keyRec.lock_until && keyRec.lock_until > now ? String(keyRec.lock_until) : null,
    issued_at: String(now)
  };
}

function signPayload(payloadObj) {
  const payloadStr = JSON.stringify(payloadObj);
  const msgBytes = Buffer.from(payloadStr, 'utf8');
  const sig = signDetached(msgBytes);
  return {
    ok: true,
    payload: msgBytes.toString('base64'),
    signature: sig.toString('base64')
  };
}

// ================= KEY RESOLUTION =================
function findKey(xApiKey) {
  if (!xApiKey) return null;
  return DB.keys[xApiKey] || null;
}

// ================= SERVER =================
const server = http.createServer((req, res) => {
  // ==== CORS PREFLIGHT (browser/admin-panel support) ====
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, x-admin-secret, x-api-key, x-device-id, x-app-version, x-signature, x-timestamp, x-nonce',
      'Access-Control-Max-Age': '86400'
    });
    return res.end();
  }
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    const bodyBuf = Buffer.concat(chunks);
    try { handle(req, res, bodyBuf); }
    catch (e) {
      console.error('[err]', e);
      sendJson(res, 500, { error: { status: 500, code: 'internal_error', message: e.message } });
    }
  });
});

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    'Access-Control-Allow-Origin': '*'
  });
  res.end(body);
}

function apiError(res, status, code, message, extra) {
  const err = { status, code, message: message || code };
  if (extra) Object.assign(err, extra);
  sendJson(res, status, { error: err });
}

function handle(req, res, bodyBuf) {
  loadDb();   // CLI changes turant (race-proof)
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  const headers = req.headers;
  const xApiKey = headers['x-api-key'];
  const deviceId = headers['x-device-id'];
  const appVersion = headers['x-app-version'];

  // ---- Global: request signature verify (only crypto api signed requests) ----
  if (VERIFY_REQUEST_SIGNATURE && headers['x-signature']) {
    const v = verifyHmac(req, bodyBuf, headers);
    if (!v.ok) {
      return sendJson(res, 401, { error: { status: 401, code: 'request_signing_mismatch', message: 'Invalid request signature' } });
    }
  }

  // ---- Version gate (optional) ----
  if (appVersion && appVersion !== '4.9.1') {
    // X-App-Version client me APP_BUILD_VERSION = "4.9.1" hai
    // Agar future me version force karna ho to yahan 426 bhejo
  }

  // ============ PUBLIC SYS ENDPOINTS ============
  if (p === '/v1/sys/status') {
    return sendJson(res, 200, { ok: true, status: 'ok', server: 'talkin-le-custom', time: Date.now() });
  }
  if (p === '/v1/sys/build') {
    return sendJson(res, 200, {
      server_version: '1.0.0-custom',
      latest: '1.12.0',
      min_supported: '1.12.0',
      changelog: 'Custom key system active. Apna key system ab tumhare control me hai.',
      download_url: '',
      discord_url: DB.discord_url || '',
      notes: null,
      published_at: Date.now(),
      current: true,
      up_to_date: true,
      update_required: false
    });
  }
  if (p === '/v1/sys/announcement') {
    return sendJson(res, 200, DB.announcement || { id: null, text: '', published_at: Date.now() });
  }

  // ============ CATALOG ============
  if (p === '/v1/catalog/plans') {
    return sendJson(res, 200, { plans: (DB.plans || defaultPlans()) });
  }
  if (p === '/v1/catalog/accounts') {
    return sendJson(res, 200, { accounts: [] });
  }
  if (p === '/v1/catalog/feature-prices') {
    return sendJson(res, 200, { prices: [] });
  }

  // ============ DEVICE ============
  if (p === '/v1/device/issue') {
    // Nayi device ID issue — POST {'register_device': false} body ke saath aata hai.
    // Defensive: device_id + id + deviceId teeno bhejo (client jo bhi uthaye).
    const id = 'dev-' + crypto.randomBytes(16).toString('hex');
    return sendJson(res, 200, { device_id: id, id: id, deviceId: id, issued_at: Date.now() });
  }
  if (p === '/v1/device/profiles') {
    if (!xApiKey) return apiError(res, 401, 'no_api_key', 'x-api-key required');
    const keyRec = findKey(xApiKey);
    if (!keyRec) return apiError(res, 403, 'invalid_key', 'Key not found');
    return sendJson(res, 200, {
      devices: (keyRec.devices || []).map(d => ({
        id: d, name: 'Device', last_seen: (DB.devices[d] && DB.devices[d].last_seen) || Date.now()
      }))
    });
  }

  // ============ SESSION: KEY STATE ============
  if (p === '/v1/session/key') {
    if (!xApiKey) return apiError(res, 401, 'no_api_key', 'x-api-key required');
    const keyRec = findKey(xApiKey);
    if (!keyRec) return apiError(res, 403, 'invalid_key', 'Key not found');
    if (keyRec.is_active === false) {
      return sendJson(res, 403, { error: { status: 403, code: 'key_disabled', message: 'This key has been disabled.' }, key: { key: keyRec.key, is_active: false } });
    }
    const now = Date.now();
    if (keyRec.lock_until && keyRec.lock_until > now) {
      return sendJson(res, 403, { error: { status: 403, code: 'admin_locked', message: 'Key locked by admin', retryAfterSeconds: Math.ceil((keyRec.lock_until - now) / 1000) } });
    }
    // Device binding enforce
    if (deviceId) {
      const devices = keyRec.devices = keyRec.devices || [];
      if (!devices.includes(deviceId)) {
        if (devices.length >= (keyRec.max_devices || 2)) {
          return apiError(res, 403, 'device_limit_reached', 'Max devices on this key', { retryAfterSeconds: 0 });
        }
        devices.push(deviceId);
        DB.devices[deviceId] = { key: keyRec.key, last_seen: now, name: 'Device' };
        saveDb();
      } else if (DB.devices[deviceId]) {
        DB.devices[deviceId].last_seen = now;
        saveDb();
      }
    }
    // Active plan check
    const plan = keyRec.plan;
    const planActive = plan && (!plan.expires_at || plan.expires_at > now);
    return sendJson(res, 200, {
      key: keyRec.key,
      discord_id: keyRec.discord_id || null,
      key_type: keyRec.key_type || 'standard',
      description: keyRec.description || '',
      is_active: keyRec.is_active !== false,
      max_devices: keyRec.max_devices || 2,
      max_accounts: keyRec.max_accounts || 3,
      devices: keyRec.devices || [],
      active_plan: planActive ? {
        id: plan.id, name: plan.name,
        expires_at: plan.expires_at ? String(plan.expires_at) : null,
        features: plan.features
      } : null,
      last_expired_plan: plan && plan.expires_at && plan.expires_at <= now ? { id: plan.id, name: plan.name } : null
    });
  }

  // ============ SESSION: ENTITLEMENT PUBLIC KEY (app fetches this to verify signatures) ============
  if (p === '/v1/session/entitlementPublicKeyHex' || p === '/v1/session/entitlement/publicKeyHex' || p === '/v1/session/publicKeyHex') {
    return sendJson(res, 200, {
      ok: true,
      hex: ENTITLEMENT_PUBLIC_KEY_HEX,
      publicKeyHex: ENTITLEMENT_PUBLIC_KEY_HEX,
      public_key_hex: ENTITLEMENT_PUBLIC_KEY_HEX,
      entitlementPublicKeyHex: ENTITLEMENT_PUBLIC_KEY_HEX
    });
  }

  // ============ SESSION: SIGNED ENTITLEMENT ============
  if (p === '/v1/session/entitlement') {
    if (!xApiKey) return apiError(res, 401, 'no_api_key', 'x-api-key required');
    const keyRec = findKey(xApiKey);
    if (!keyRec) return apiError(res, 403, 'invalid_key', 'Key not found');
    if (keyRec.is_active === false) {
      return apiError(res, 403, { error: { status: 403, code: 'key_disabled', message: 'This key has been disabled.' } });
    }
    const now = Date.now();
    if (keyRec.lock_until && keyRec.lock_until > now) {
      return apiError(res, 403, 'admin_locked', 'Key locked by admin', { retryAfterSeconds: Math.ceil((keyRec.lock_until - now) / 1000) });
    }
    if (!deviceId) return apiError(res, 400, 'device_id_required', 'X-Device-Id required');
    // Device binding: entitlement payload me df = deviceFingerprint(deviceId)
    const devices = keyRec.devices = keyRec.devices || [];
    if (!devices.includes(deviceId)) {
      if (devices.length >= (keyRec.max_devices || 2)) {
        return apiError(res, 403, 'device_limit_reached', 'Max devices on this key', { retryAfterSeconds: 0 });
      }
      devices.push(deviceId);
      DB.devices[deviceId] = { key: keyRec.key, last_seen: now, name: 'Device' };
      saveDb();
    }
    const payload = buildEntitlementPayload(keyRec, deviceId);
    const signed = signPayload(payload);
    return sendJson(res, 200, signed);
  }

  // ============ SESSION PUSH/SYNC (no-op) ============
  if (p === '/v1/session/push' || p === '/v1/session/accounts/sync') {
    return sendJson(res, 200, { ok: true });
  }

  // ============ SEC ENC/DEC (passthrough/local) ============
  if (p.startsWith('/v1/sec/enc/') || p.startsWith('/v1/sec/dec/')) {
    // App khud AES keys derive kar sakta hai (encKey/macKey) — passthrough with ok
    return sendJson(res, 200, { ok: true, mode: 'local' });
  }

  // ============ ADMIN API (tumhara control panel — SECRET HEADER se) ============
  const auth = headers['x-admin-secret'] || '';
  if (p.startsWith('/admin/') && auth === ADMIN_SECRET) {
    return handleAdmin(req, res, p, bodyBuf);
  }

  // ============ ADMIN WEB PANEL (browser — /admin pe) ============
  if (p === '/admin' || p === '/admin/') {
    const html = `<!DOCTYPE html>
<html lang="hi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Talkin LE — Admin Panel</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; }
  body { background: #0D0A0F; color: #fff; min-height: 100vh; padding: 20px; }
  .wrap { max-width: 520px; margin: 0 auto; }
  h1 { font-size: 26px; text-align: center; margin-bottom: 4px; }
  .sub { text-align: center; color: #FF7A18; letter-spacing: 3px; font-size: 12px; font-weight: bold; margin-bottom: 28px; }
  .card { background: linear-gradient(180deg,#17131C,#100D14); border: 1px solid #262030; border-radius: 18px; padding: 22px; margin-bottom: 16px; }
  label { display: block; font-size: 11px; color: #9A93A0; letter-spacing: 1.5px; font-weight: bold; margin-bottom: 8px; }
  input, select { width: 100%; background: #1C1723; border: 1px solid #332B40; border-radius: 12px; padding: 13px 14px; color: #fff; font-size: 15px; outline: none; }
  input:focus { border-color: #FF7A18; }
  .row { display: flex; gap: 10px; margin-bottom: 14px; }
  .row > div { flex: 1; }
  button { width: 100%; background: linear-gradient(90deg,#FF3D00,#FF7A18); border: none; border-radius: 27px; padding: 15px; color: #fff; font-size: 15px; font-weight: bold; letter-spacing: 1px; cursor: pointer; margin-top: 6px; }
  button:active { opacity: .8; }
  button.ghost { background: #241E2E; margin-top: 10px; }
  .msg { margin-top: 14px; font-size: 13px; color: #B6AFBC; text-align: center; min-height: 18px; }
  .newkey { background: #12251A; border: 1px solid #2E7D32; border-radius: 12px; padding: 14px; margin-top: 14px; display: none; }
  .newkey .k { word-break: break-all; font-family: monospace; font-size: 13px; color: #7CFC8F; user-select: all; }
  .list { margin-top: 10px; }
  .kitem { background: #1C1723; border: 1px solid #332B40; border-radius: 12px; padding: 12px 14px; margin-bottom: 8px; font-size: 12px; }
  .kitem .kk { word-break: break-all; font-family: monospace; color: #FFC46B; }
  .kitem .meta { color: #9A93A0; margin-top: 4px; }
  .kitem .act { margin-top: 8px; display: flex; gap: 8px; flex-wrap: wrap; }
  .kitem .act button { width: auto; padding: 7px 12px; font-size: 11px; border-radius: 16px; margin: 0; background: #241E2E; }
  .kitem .act button.danger { background: #3A1420; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: bold; }
  .b-prem { background: #3A2A08; color: #FFC46B; } .b-std { background: #12303A; color: #6BD7E8; }
  .b-off { background: #3A1420; color: #FF6B81; } .b-on { background: #12251A; color: #7CFC8F; }
  .secret-row { display: flex; gap: 10px; }
  .stat { display: flex; justify-content: space-around; margin-bottom: 16px; }
  .stat div { text-align: center; } .stat .n { font-size: 22px; font-weight: bold; color: #FF7A18; } .stat .l { font-size: 10px; color: #9A93A0; letter-spacing: 1px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>TALKIN</h1>
  <div class="sub">LICENSE ADMIN PANEL</div>

  <div class="card" id="loginCard">
    <label>ADMIN SECRET DAALO</label>
    <div class="secret-row">
      <input type="password" id="secret" placeholder="9c081f..." autocomplete="off">
      <button style="width:auto;margin:0;padding:13px 18px" onclick="login()">LOGIN</button>
    </div>
    <div class="msg" id="loginMsg"></div>
  </div>

  <div id="panel" style="display:none">
    <div class="stat">
      <div><div class="n" id="stTotal">0</div><div class="l">TOTAL KEYS</div></div>
      <div><div class="n" id="stActive">0</div><div class="l">ACTIVE</div></div>
      <div><div class="n" id="stDevices">0</div><div class="l">DEVICES</div></div>
    </div>

    <div class="card">
      <label>NAYI KEY GENERATE KARO</label>
      <div class="row">
        <div><label>KISKO (NAAM/ID)</label><input id="fDiscord" placeholder="RAM-BHAI" autocomplete="off"></div>
      </div>
      <div class="row">
        <div><label>TYPE</label>
          <select id="fType"><option value="premium">PREMIUM</option><option value="standard">STANDARD</option></select></div>
        <div><label>DEVICES</label>
          <select id="fDev"><option>1</option><option>2</option><option>3</option><option>5</option></select></div>
      </div>
      <div class="row">
        <div><label>ACCOUNTS</label>
          <select id="fAcc"><option>5</option><option>3</option><option>10</option><option>1</option></select></div>
        <div><label>DIN (VALIDITY)</label>
          <select id="fDays"><option value="9999">9999 (LIFETIME)</option><option value="365">365</option><option value="90">90</option><option value="30">30</option><option value="7">7</option><option value="3">3</option></select></div>
      </div>
      <button onclick="createKey()">🔑 GENERATE KARO</button>
      <div class="newkey" id="newKeyBox">
        <label>✅ NAYI KEY READY — COPY KARO:</label>
        <div class="k" id="newKey"></div>
      </div>
      <div class="msg" id="msg"></div>
    </div>

    <div class="card">
      <label>SAARI KEYS</label>
      <div class="list" id="keyList"><div class="msg">LOADING...</div></div>
      <button class="ghost" onclick="loadKeys()">🔄 REFRESH LIST</button>
    </div>
  </div>
</div>
<script>
const API = location.origin;
let S = sessionStorage.getItem('tladmin') || '';

function login() {
  S = document.getElementById('secret').value.trim();
  document.getElementById('loginMsg').textContent = 'CHECK KAR RAHA HU...';
  fetch(API + '/admin/keys/list', { headers: { 'x-admin-secret': S } })
    .then(r => r.json())
    .then(j => {
      if (j.keys) {
        sessionStorage.setItem('tladmin', S);
        document.getElementById('loginCard').style.display = 'none';
        document.getElementById('panel').style.display = 'block';
        loadKeys();
      } else {
        document.getElementById('loginMsg').textContent = '❌ GALAT SECRET HAI BHAI';
      }
    })
    .catch(() => document.getElementById('loginMsg').textContent = '⚠️ SERVER SE CONNECT NAHI HUA');
}

function loadKeys() {
  fetch(API + '/admin/keys/list', { headers: { 'x-admin-secret': S } })
    .then(r => r.json())
    .then(j => {
      if (!j.keys) return;
      const list = document.getElementById('keyList');
      let total = j.keys.length, active = 0, devs = 0;
      list.innerHTML = '';
      j.keys.forEach(k => {
        if (k.active) active++;
        devs += k.devices;
        const d = document.createElement('div');
        d.className = 'kitem';
        const prem = k.type === 'premium';
        const dleft = Math.max(0, k.max_devices - k.devices);
        const exp = k.plan && k.plan.expires_at ? new Date(k.plan.expires_at).toLocaleDateString('en-GB') : '—';
        d.innerHTML = '<span class="badge ' + (prem?'b-prem':'b-std') + '">' + k.type.toUpperCase() + '</span> ' +
          '<span class="badge ' + (k.active?'b-on':'b-off') + '">' + (k.active?'ACTIVE':'OFF') + '</span>' +
          (k.lock_until && k.lock_until > Date.now() ? ' <span class="badge b-off">LOCKED</span>' : '') +
          '<div class="kk" style="margin-top:6px">' + k.key + '</div>' +
          '<div class="meta">DEVICES: ' + k.devices + '/' + k.max_devices + ' · EXPIRE: ' + exp + '</div>' +
          '<div class="act"><button onclick="cp(\\''+k.key+'\\')">📋 COPY</button>' +
          '<button onclick="rst(\\''+k.key+'\\')">♻️ RESET DEV</button>' +
          '<button onclick="tgl(\\''+k.key+'\\','+(!k.active)+')">' + (k.active?'⏸ DISABLE':'▶ ENABLE') + '</button>' +
          '<button class="danger" onclick="del(\\''+k.key+'\\')">🗑 DELETE</button></div>';
        list.appendChild(d);
      });
      document.getElementById('stTotal').textContent = total;
      document.getElementById('stActive').textContent = active;
      document.getElementById('stDevices').textContent = devs;
    });
}

function createKey() {
  const msg = document.getElementById('msg');
  msg.textContent = '⏳ KEY BAN RAHI HAI...';
  const body = {
    discord_id: document.getElementById('fDiscord').value.trim() || 'BANDA',
    key_type: document.getElementById('fType').value,
    max_devices: parseInt(document.getElementById('fDev').value),
    max_accounts: parseInt(document.getElementById('fAcc').value),
    days: parseInt(document.getElementById('fDays').value),
    description: 'Admin panel se bani'
  };
  fetch(API + '/admin/keys/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-admin-secret': S },
    body: JSON.stringify(body)
  })
  .then(r => r.json())
  .then(j => {
    if (j.ok) {
      document.getElementById('newKeyBox').style.display = 'block';
      document.getElementById('newKey').textContent = j.key;
      msg.textContent = '✅ KEY BAN GAYI! Upar copy karke user ko de de.';
      loadKeys();
    } else {
      msg.textContent = '❌ ' + (j.error ? j.error.message : 'FAIL');
    }
  })
  .catch(() => msg.textContent = '⚠️ SERVER SE CONNECT NAHI HUA');
}

function cp(k) { navigator.clipboard ? navigator.clipboard.writeText(k) : prompt('Copy:', k); }
function rst(k) { if (confirm('Is key ke saare devices reset kare?')) post('/admin/keys/reset-devices', { key: k }); }
function tgl(k, on) { post('/admin/keys/toggle', { key: k, active: on }); }
function del(k) { if (confirm('PAKKA DELETE? Wapas nahi aayegi!')) post('/admin/keys/delete', { key: k }); }

function post(path, body) {
  fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-admin-secret': S },
    body: JSON.stringify(body)
  }).then(r => r.json()).then(j => { loadKeys(); });
}

if (S) {
  fetch(API + '/admin/keys/list', { headers: { 'x-admin-secret': S } })
    .then(r => r.json())
    .then(j => {
      if (j.keys) {
        document.getElementById('loginCard').style.display = 'none';
        document.getElementById('panel').style.display = 'block';
        loadKeys();
      }
    });
}
</script>
</body>
</html>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
    return res.end(html);
  }

  return sendJson(res, 404, { error: { status: 404, code: 'not_found', message: p } });
}

function defaultPlans() {
  return [
    { id: 'plan_pro', name: 'Pro', price: 0, duration_days: 30, features: 'ALL' },
    { id: 'plan_trial', name: 'Trial', price: 0, duration_days: 3, features: 'ALL' }
  ];
}

function handleAdmin(req, res, p, bodyBuf) {
  const body = bodyBuf.length ? JSON.parse(bodyBuf.toString('utf8') || '{}') : {};
  // CREATE KEY
  if (p === '/admin/keys/create' && req.method === 'POST') {
    const key = KEY_PREFIX + crypto.randomBytes(24).toString('hex');
    const days = body.days || 30;
    const rec = {
      key,
      discord_id: body.discord_id || null,
      key_type: body.key_type || 'standard',
      description: body.description || '',
      is_active: true,
      max_devices: body.max_devices || 2,
      max_accounts: body.max_accounts || 3,
      devices: [],
      plan: {
        id: 'plan_pro',
        name: 'Pro',
        expires_at: Date.now() + days * 24 * 60 * 60 * 1000,
        features: {
          prank: true, boost: true, antidelete: true, antimicmute: true, antimicremove: true,
          antivoiceroomleave: true, isvoiceeffect: true, issoundbox: true,
          isimgprank: true, isstickerprank: true, ismusicbot: true, isantiban: true
        }
      },
      lock_until: 0,
      note: body.note || ''
    };
    DB.keys[key] = rec;
    saveDb();
    return sendJson(res, 200, { ok: true, key, expires_at: rec.plan.expires_at, days });
  }
  // LIST KEYS
  if (p === '/admin/keys/list') {
    const list = Object.values(DB.keys).map(k => ({
      key: k.key, type: k.key_type, active: k.is_active !== false,
      devices: (k.devices || []).length, max_devices: k.max_devices,
      plan: k.plan ? { name: k.plan.name, expires_at: k.plan.expires_at } : null,
      lock_until: k.lock_until || 0
    }));
    return sendJson(res, 200, { count: list.length, keys: list });
  }
  // DISABLE/ENABLE KEY
  if (p === '/admin/keys/toggle' && req.method === 'POST') {
    const k = DB.keys[body.key];
    if (!k) return apiError(res, 404, 'key_not_found', 'Key not found');
    k.is_active = body.active !== false;
    saveDb();
    return sendJson(res, 200, { ok: true, key: k.key, is_active: k.is_active });
  }
  // DELETE KEY
  if (p === '/admin/keys/delete' && req.method === 'POST') {
    if (!DB.keys[body.key]) return apiError(res, 404, 'key_not_found', 'Key not found');
    delete DB.keys[body.key];
    saveDb();
    return sendJson(res, 200, { ok: true, deleted: body.key });
  }
  // RESET DEVICES
  if (p === '/admin/keys/reset-devices' && req.method === 'POST') {
    const k = DB.keys[body.key];
    if (!k) return apiError(res, 404, 'key_not_found', 'Key not found');
    k.devices = [];
    saveDb();
    return sendJson(res, 200, { ok: true, key: k.key, devices: [] });
  }
  // LOCK KEY (admin lock — app me LockGate dikhega)
  if (p === '/admin/keys/lock' && req.method === 'POST') {
    const k = DB.keys[body.key];
    if (!k) return apiError(res, 404, 'key_not_found', 'Key not found');
    k.lock_until = Date.now() + (body.minutes || 60) * 60 * 1000;
    saveDb();
    return sendJson(res, 200, { ok: true, key: k.key, lock_until: k.lock_until });
  }
  // ==== DB BACKUP (ephemeral hosts ke liye — Render/Koyeb pe data.json udh sakta hai) ====
  if (p === '/admin/db/export') {
    return sendJson(res, 200, { ok: true, exported_at: new Date().toISOString(), db: DB });
  }
  if (p === '/admin/db/import' && req.method === 'POST') {
    const incoming = body.db;
    if (!incoming || typeof incoming !== 'object' || !incoming.keys || typeof incoming.keys !== 'object') {
      return apiError(res, 400, 'bad_db', 'body.db me valid DB object bhejo (keys zaroori hai)');
    }
    DB = { keys: {}, devices: {}, announcement: null, ...incoming };
    saveDb();
    return sendJson(res, 200, {
      ok: true,
      keys_imported: Object.keys(DB.keys).length,
      devices_known: Object.keys(DB.devices || {}).length,
      saved_to: DATA_FILE
    });
  }
  return sendJson(res, 404, { error: { status: 404, code: 'unknown_admin', message: p } });
}

// ================= BOOT =================
loadDb();
server.listen(PORT, HOST, () => {
  console.log('==============================================');
  console.log('  TALKIN LE CUSTOM LICENSE SERVER');
  console.log('==============================================');
  console.log(`  Listening : http://${HOST}:${PORT}`);
  console.log(`  PubKey    : ${ENTITLEMENT_PUBLIC_KEY_HEX}`);
  console.log(`  KeyPrefix : ${KEY_PREFIX}...`);
  console.log(`  DataFile  : ${DATA_FILE}`);
  console.log('  Admin API : POST /admin/keys/create  (header: x-admin-secret: ADMIN_SECRET)');
  console.log('==============================================');
  console.log('  NOTE: HTTPS ke liye nginx/caddy reverse proxy lagao,');
  console.log('  ya Cloudflare tunnel use karo — APK https:// URL mangta hai!');
  console.log('==============================================');
});
