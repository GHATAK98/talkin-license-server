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
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'CHANGE-ME-ADMIN-SECRET-123';

// APK request signature verify karna? (client ab sign nahi karta, to false hi rakhna safe hai)
const VERIFY_REQUEST_SIGNATURE = false;

// Payload version (client expects this 'v' in entitlement payload)
// VERIFIED from decompiled JS: r4 = 2 → v must === 2 (storage key bhi entitlement.v2 hai)
const PAYLOAD_VERSION = 2;

// Key prefix (client fool403_ expect karta hai)
const KEY_PREFIX = 'fool403_';

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
