import { Buffer } from 'node:buffer';

const enc = new TextEncoder();
const PBKDF2_ITER = 20000;
const SESSION_DAYS = 30;
const MAX_FAILS = 5;
const LOCK_MIN = 15;

class HttpError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code; }
}
const fail = (status, message, code) => { throw new HttpError(status, message, code); };

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });

const now = () => Math.floor(Date.now() / 1000);

// ---------- helpers ----------
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

async function hashPassword(password, saltB64) {
  const salt = saltB64 ? fromB64u(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITER }, key, 256);
  return { hash: b64u(bits), salt: b64u(salt) };
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function hmacB64(secret, data) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64u(await crypto.subtle.sign('HMAC', k, enc.encode(data)));
}

function normMobile(m) {
  const d = String(m || '').replace(/\D/g, '');
  const ten = d.length > 10 ? d.slice(-10) : d;
  if (ten.length !== 10) fail(400, 'সঠিক মোবাইল নম্বর দিন (যেমন: 01712345678)');
  return ten;
}

// Stored as the last 10 digits; Bangladeshi numbers (01XXXXXXXXX) are shown with the leading 0 again.
const showMobile = (m) => (m && m.length === 10 && m[0] === '1' ? '0' + m : m);

function checkPassword(p) {
  if (typeof p !== 'string' || p.length < 4) fail(400, 'পাসওয়ার্ড অন্তত ৪ অক্ষরের হতে হবে');
  return p;
}

function getCookie(req, name) {
  const c = req.headers.get('cookie') || '';
  const m = c.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? m[1] : null;
}

// Session-signing key: SESSION_SECRET if set, otherwise generated once and kept in the database.
let cachedSecret = null;
async function sessionSecret(env) {
  if (env.SESSION_SECRET) return env.SESSION_SECRET;
  if (cachedSecret) return cachedSecret;
  let r = await env.DB.prepare("SELECT v FROM config WHERE k='session_secret'").first();
  if (!r) {
    await env.DB.prepare("INSERT OR IGNORE INTO config (k,v) VALUES ('session_secret', ?)").bind(b64u(crypto.getRandomValues(new Uint8Array(32)))).run();
    r = await env.DB.prepare("SELECT v FROM config WHERE k='session_secret'").first();
  }
  return (cachedSecret = r.v);
}

async function makeToken(env, user) {
  const payload = b64u(enc.encode(JSON.stringify({ u: user.id, v: user.token_ver, e: now() + SESSION_DAYS * 86400 })));
  return payload + '.' + (await hmacB64(await sessionSecret(env), payload));
}

function sessionCookie(value, maxAge) {
  return `sess=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

async function currentUser(req, env) {
  const tok = getCookie(req, 'sess');
  if (!tok || !tok.includes('.')) return null;
  const [payload, sig] = tok.split('.');
  if (!safeEqual(sig, await hmacB64(await sessionSecret(env), payload))) return null;
  let p;
  try { p = JSON.parse(new TextDecoder().decode(fromB64u(payload))); } catch { return null; }
  if (!p.e || p.e < now()) return null;
  const u = await env.DB.prepare('SELECT id,name,mobile,is_admin,active,allow_web,token_ver FROM users WHERE id=?').bind(p.u).first();
  if (!u || !u.active || u.token_ver !== p.v) return null;
  return u;
}

function isApp(req, env) {
  const ua = req.headers.get('user-agent') || '';
  return !!env.APP_KEY && ua.includes(`BiyeGalleryApp/`) && ua.includes(`k=${env.APP_KEY}`);
}

async function requireViewer(req, env) {
  const u = await currentUser(req, env);
  if (!u) fail(401, 'আগে লগইন করুন', 'login');
  if (env.REQUIRE_APP === '1' && !u.is_admin && !u.allow_web && !isApp(req, env))
    fail(403, 'এই অ্যালবাম শুধু অ্যাপে দেখা যাবে', 'app_required');
  return u;
}

async function requireAdmin(req, env) {
  const u = await currentUser(req, env);
  if (!u) fail(401, 'আগে লগইন করুন', 'login');
  if (!u.is_admin) fail(403, 'শুধু অ্যাডমিন এটা করতে পারবে');
  return u;
}

async function body(req) {
  try { return await req.json(); } catch { fail(400, 'ভুল রিকোয়েস্ট'); }
}

// ---------- storage: files split into chunks inside free D1 databases ----------
// Each shard database (SHARD1..SHARDn) holds rows of up to CHUNK raw bytes, stored as base64 text.
const CHUNK = 1_400_000;                 // raw bytes per row (≈1.87 MB as base64, D1 row limit is 2 MB)
const SHARD_CAP = 440_000_000;           // stored bytes allowed per shard (D1 free limit is 500 MB)
const shardCount = (env) => parseInt(env.SHARD_COUNT || '8');
const shardDb = (env, n) => { const d = env['SHARD' + n]; if (!d) fail(500, `SHARD${n} ডেটাবেস যুক্ত নেই`); return d; };
const storedSize = (size) => Math.ceil(size / 3) * 4 + 200;

async function blobStart(env, key, size, type) {
  const stored = storedSize(size);
  const parts = Math.max(1, Math.ceil(size / CHUNK));
  const row = await env.DB.prepare('SELECT n FROM shards WHERE n <= ? AND bytes + ? <= ? ORDER BY n LIMIT 1')
    .bind(shardCount(env), stored, SHARD_CAP).first();
  if (!row) fail(507, 'ফ্রি জায়গা শেষ — আর আপলোড করা যাবে না');
  await env.DB.batch([
    env.DB.prepare('UPDATE shards SET bytes = bytes + ? WHERE n=?').bind(stored, row.n),
    env.DB.prepare('INSERT INTO blobs (key,shard,size,parts,stored,type,created_at) VALUES (?,?,?,?,?,?,?)')
      .bind(key, row.n, size, parts, stored, type, now()),
  ]);
  return { parts };
}

async function blobPut(env, key, part, bytes) {
  const b = await env.DB.prepare('SELECT shard,size,parts,done FROM blobs WHERE key=?').bind(key).first();
  if (!b || b.done) fail(404, 'আপলোড পাওয়া যায়নি');
  if (part < 0 || part >= b.parts) fail(400, 'ভুল অংশ');
  const expect = part === b.parts - 1 ? b.size - part * CHUNK : CHUNK;
  if (bytes.byteLength !== expect) fail(400, `অংশের সাইজ মেলেনি (${bytes.byteLength}/${expect})`);
  await shardDb(env, b.shard).prepare('INSERT OR REPLACE INTO chunks (key,part,data) VALUES (?,?,?)')
    .bind(key, part, Buffer.from(bytes).toString('base64')).run();
}

async function blobFinish(env, key) {
  const b = await env.DB.prepare('SELECT shard,parts FROM blobs WHERE key=?').bind(key).first();
  if (!b) return false;
  const c = await shardDb(env, b.shard).prepare('SELECT COUNT(*) AS n FROM chunks WHERE key=?').bind(key).first();
  if (c.n !== b.parts) return false;
  await env.DB.prepare('UPDATE blobs SET done=1 WHERE key=?').bind(key).run();
  return true;
}

async function blobDelete(env, key) {
  const b = await env.DB.prepare('SELECT shard,stored FROM blobs WHERE key=?').bind(key).first();
  if (!b) return;
  await shardDb(env, b.shard).prepare('DELETE FROM chunks WHERE key=?').bind(key).run();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM blobs WHERE key=?').bind(key),
    env.DB.prepare('UPDATE shards SET bytes = MAX(0, bytes - ?) WHERE n=?').bind(b.stored, b.shard),
  ]);
}

/** Streams a stored file, honouring HTTP Range so videos can seek. */
async function serveBlob(req, env, key) {
  const b = await env.DB.prepare('SELECT shard,size,parts,type FROM blobs WHERE key=? AND done=1').bind(key).first();
  if (!b) return new Response('not found', { status: 404 });
  const db = shardDb(env, b.shard);
  const headers = {
    'content-type': b.type, 'accept-ranges': 'bytes',
    'cache-control': 'private, max-age=604800, immutable',
    'content-disposition': 'inline', 'x-content-type-options': 'nosniff',
  };
  const getPart = async (i) => {
    const r = await db.prepare('SELECT data FROM chunks WHERE key=? AND part=?').bind(key, i).first();
    if (!r) fail(500, 'ফাইলের অংশ পাওয়া যায়নি');
    return Buffer.from(r.data, 'base64');
  };
  const m = (req.headers.get('range') || '').match(/^bytes=(\d*)-(\d*)$/);
  if (m && (m[1] || m[2])) {
    let start, end;
    if (m[1] === '') { start = Math.max(0, b.size - parseInt(m[2])); end = b.size - 1; }
    else { start = parseInt(m[1]); end = m[2] ? Math.min(parseInt(m[2]), b.size - 1) : b.size - 1; }
    if (start >= b.size || start > end) return new Response(null, { status: 416, headers: { 'content-range': `bytes */${b.size}` } });
    const i = Math.floor(start / CHUNK);
    end = Math.min(end, (i + 1) * CHUNK - 1);        // answer at most one chunk per request
    const buf = await getPart(i);
    const slice = buf.subarray(start - i * CHUNK, end - i * CHUNK + 1);
    return new Response(slice, { status: 206, headers: { ...headers, 'content-range': `bytes ${start}-${end}/${b.size}`, 'content-length': String(slice.length) } });
  }
  if (b.parts > 40) return new Response(null, { status: 416, headers: { 'content-range': `bytes */${b.size}` } });
  const bufs = [];
  for (let i = 0; i < b.parts; i++) bufs.push(await getPart(i));
  const all = Buffer.concat(bufs);
  return new Response(all, { status: 200, headers: { ...headers, 'content-length': String(all.length) } });
}

const randId = () => b64u(crypto.getRandomValues(new Uint8Array(12)));
const EXT_OK = new Set(['webp', 'jpg', 'jpeg', 'png', 'mp4', 'webm', 'mov', 'm4v']);

// ---------- routes ----------
async function api(req, env, url) {
  const p = url.pathname;
  const m = req.method;

  if (p === '/api/config' && m === 'GET') {
    const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM users WHERE is_admin=1').first();
    return json({ title: env.SITE_TITLE || 'আমাদের বিয়ের অ্যালবাম', appUrl: env.APP_DOWNLOAD_URL || '', setupNeeded: !row || row.n === 0 });
  }

  if (p === '/api/setup' && m === 'POST') {
    const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM users WHERE is_admin=1').first();
    if (row && row.n > 0) fail(403, 'অ্যাডমিন আগেই তৈরি হয়ে গেছে');
    const b = await body(req);
    const mobile = normMobile(b.mobile);
    const h = await hashPassword(checkPassword(b.password));
    await env.DB.prepare('INSERT INTO users (name,mobile,pass_hash,salt,is_admin,allow_web,created_at) VALUES (?,?,?,?,1,1,?)')
      .bind(String(b.name || 'Admin').slice(0, 60), mobile, h.hash, h.salt, now()).run();
    return json({ ok: true });
  }

  if (p === '/api/login' && m === 'POST') {
    const b = await body(req);
    const mobile = normMobile(b.mobile);
    const lock = await env.DB.prepare('SELECT count,until FROM login_fail WHERE mobile=?').bind(mobile).first();
    if (lock && lock.count >= MAX_FAILS && lock.until > now())
      fail(429, `অনেকবার ভুল হয়েছে। ${Math.ceil((lock.until - now()) / 60)} মিনিট পরে চেষ্টা করুন`);
    const u = await env.DB.prepare('SELECT * FROM users WHERE mobile=?').bind(mobile).first();
    let ok = false;
    if (u) ok = safeEqual((await hashPassword(String(b.password || ''), u.salt)).hash, u.pass_hash);
    if (!ok) {
      const cnt = lock && lock.until > now() ? lock.count + 1 : 1;
      await env.DB.prepare('INSERT INTO login_fail (mobile,count,until) VALUES (?,?,?) ON CONFLICT(mobile) DO UPDATE SET count=excluded.count, until=excluded.until')
        .bind(mobile, cnt, now() + LOCK_MIN * 60).run();
      fail(401, 'মোবাইল নম্বর বা পাসওয়ার্ড ভুল');
    }
    if (!u.active) fail(403, 'আপনার অ্যাকাউন্ট বন্ধ করা আছে');
    await env.DB.batch([
      env.DB.prepare('DELETE FROM login_fail WHERE mobile=?').bind(mobile),
      env.DB.prepare('UPDATE users SET last_login=? WHERE id=?').bind(now(), u.id),
    ]);
    return json({ ok: true, is_admin: !!u.is_admin }, 200, { 'set-cookie': sessionCookie(await makeToken(env, u), SESSION_DAYS * 86400) });
  }

  if (p === '/api/logout' && m === 'POST') {
    return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
  }

  if (p === '/api/me' && m === 'GET') {
    const u = await currentUser(req, env);
    if (!u) fail(401, 'আগে লগইন করুন', 'login');
    const appOnly = env.REQUIRE_APP === '1' && !u.is_admin && !u.allow_web && !isApp(req, env);
    return json({ name: u.name, mobile: showMobile(u.mobile), is_admin: !!u.is_admin, app_required: appOnly, in_app: isApp(req, env) });
  }

  if (p === '/api/albums' && m === 'GET') {
    await requireViewer(req, env);
    const { results } = await env.DB.prepare("SELECT album, COUNT(*) AS n FROM media GROUP BY album ORDER BY MIN(COALESCE(taken,created_at))").all();
    const total = results.reduce((s, r) => s + r.n, 0);
    return json({ total, albums: results });
  }

  if (p === '/api/media' && m === 'GET') {
    await requireViewer(req, env);
    const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit')) || 60, 1), 100);
    const offset = Math.max(parseInt(url.searchParams.get('offset')) || 0, 0);
    const album = url.searchParams.get('album');
    const q = album !== null
      ? env.DB.prepare('SELECT * FROM media WHERE album=? ORDER BY COALESCE(taken,created_at), id LIMIT ? OFFSET ?').bind(album, limit + 1, offset)
      : env.DB.prepare('SELECT * FROM media ORDER BY COALESCE(taken,created_at), id LIMIT ? OFFSET ?').bind(limit + 1, offset);
    const { results } = await q.all();
    const more = results.length > limit;
    const items = results.slice(0, limit).map((r) => ({
      id: r.id, type: r.type, album: r.album, w: r.width, h: r.height, thumb: r.thumb, url: '/m/' + r.key,
    }));
    return json({ items, more, next: offset + items.length });
  }

  // ----- admin -----
  if (p === '/api/admin/stats' && m === 'GET') {
    await requireAdmin(req, env);
    const s = await env.DB.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS bytes, SUM(type='video') AS videos FROM media").first();
    const u = await env.DB.prepare('SELECT COUNT(*) AS n FROM users WHERE is_admin=0').first();
    const sh = await env.DB.prepare('SELECT COALESCE(SUM(bytes),0) AS used FROM shards WHERE n <= ?').bind(shardCount(env)).first();
    const cap = shardCount(env) * SHARD_CAP;
    // report in raw-file bytes (storage keeps base64, ~4/3 bigger)
    return json({ media: s.n, videos: s.videos || 0, bytes: Math.round(sh.used * 0.75), users: u.n, freeBytes: Math.round(cap * 0.75) });
  }

  if (p === '/api/admin/users' && m === 'GET') {
    await requireAdmin(req, env);
    const { results } = await env.DB.prepare('SELECT id,name,mobile,is_admin,active,allow_web,last_login,created_at FROM users ORDER BY is_admin DESC, id DESC').all();
    return json({ users: results.map((r) => ({ ...r, mobile: showMobile(r.mobile) })) });
  }

  if (p === '/api/admin/users' && m === 'POST') {
    await requireAdmin(req, env);
    const b = await body(req);
    const mobile = normMobile(b.mobile);
    const h = await hashPassword(checkPassword(b.password));
    const exists = await env.DB.prepare('SELECT id FROM users WHERE mobile=?').bind(mobile).first();
    if (exists) fail(409, 'এই নম্বরে আগেই ইউজার আছে');
    await env.DB.prepare('INSERT INTO users (name,mobile,pass_hash,salt,is_admin,allow_web,created_at) VALUES (?,?,?,?,?,?,?)')
      .bind(String(b.name || '').slice(0, 60), mobile, h.hash, h.salt, b.is_admin ? 1 : 0, b.allow_web ? 1 : 0, now()).run();
    return json({ ok: true });
  }

  let mm;
  if ((mm = p.match(/^\/api\/admin\/users\/(\d+)$/))) {
    const admin = await requireAdmin(req, env);
    const id = parseInt(mm[1]);
    if (m === 'DELETE') {
      if (id === admin.id) fail(400, 'নিজেকে ডিলিট করা যাবে না');
      await env.DB.prepare('DELETE FROM users WHERE id=?').bind(id).run();
      return json({ ok: true });
    }
    if (m === 'PATCH') {
      const b = await body(req);
      const stmts = [];
      if ('name' in b) stmts.push(env.DB.prepare('UPDATE users SET name=? WHERE id=?').bind(String(b.name).slice(0, 60), id));
      if ('active' in b) {
        if (id === admin.id && !b.active) fail(400, 'নিজেকে বন্ধ করা যাবে না');
        stmts.push(env.DB.prepare('UPDATE users SET active=?, token_ver=token_ver+1 WHERE id=?').bind(b.active ? 1 : 0, id));
      }
      if ('allow_web' in b) stmts.push(env.DB.prepare('UPDATE users SET allow_web=? WHERE id=?').bind(b.allow_web ? 1 : 0, id));
      if ('password' in b) {
        const h = await hashPassword(checkPassword(b.password));
        stmts.push(env.DB.prepare('UPDATE users SET pass_hash=?, salt=?, token_ver=token_ver+1 WHERE id=?').bind(h.hash, h.salt, id));
      }
      if (stmts.length) await env.DB.batch(stmts);
      return json({ ok: true });
    }
  }

  if (p === '/api/admin/blob' && m === 'POST') {
    await requireAdmin(req, env);
    const b = await body(req);
    const ext = String(b.ext || '').toLowerCase();
    if (!EXT_OK.has(ext)) fail(400, 'এই ফাইল টাইপ চলবে না: ' + ext);
    const size = parseInt(b.size);
    if (!(size > 0) || size > 2e9) fail(400, 'ফাইলের সাইজ ঠিক নেই');
    const key = `${b.kind === 'video' ? 'v' : 'p'}/${randId()}.${ext}`;
    const type = String(b.type || '').slice(0, 60) || 'application/octet-stream';
    const { parts } = await blobStart(env, key, size, type);
    return json({ key, parts, chunk: CHUNK });
  }

  if ((mm = p.match(/^\/api\/admin\/blob\/([pv]\/[\w-]+\.\w+)\/(\d+)$/)) && m === 'PUT') {
    await requireAdmin(req, env);
    await blobPut(env, mm[1], parseInt(mm[2]), await req.arrayBuffer());
    return json({ ok: true });
  }

  if (p === '/api/admin/media' && m === 'POST') {
    await requireAdmin(req, env);
    const it = await body(req);
    if (typeof it.thumb !== 'string' || !/^data:image\/(webp|jpeg);base64,/.test(it.thumb) || it.thumb.length > 120000) fail(400, 'থাম্বনেইল ঠিক নেই');
    if (!(await blobFinish(env, it.key))) fail(400, 'ফাইলের সব অংশ ওঠেনি, আবার চেষ্টা করুন');
    const size = (await env.DB.prepare('SELECT size FROM blobs WHERE key=?').bind(it.key).first()).size;
    await env.DB.prepare('INSERT OR IGNORE INTO media (key,thumb,type,album,width,height,size,src,taken,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .bind(it.key, it.thumb, it.type === 'video' ? 'video' : 'image', String(it.album || '').slice(0, 80),
        it.width | 0 || null, it.height | 0 || null, size, String(it.src || '').slice(0, 300), it.taken | 0 || null, now()).run();
    return json({ ok: true });
  }

  if (p === '/api/admin/blob-abort' && m === 'POST') {
    await requireAdmin(req, env);
    const b = await body(req);
    const row = await env.DB.prepare('SELECT done FROM blobs WHERE key=?').bind(String(b.key)).first();
    if (row && !row.done) await blobDelete(env, String(b.key));
    return json({ ok: true });
  }

  if (p === '/api/admin/srcs' && m === 'GET') {
    await requireAdmin(req, env);
    const { results } = await env.DB.prepare('SELECT src FROM media WHERE src IS NOT NULL').all();
    return json({ srcs: results.map((r) => r.src) });
  }

  if ((mm = p.match(/^\/api\/admin\/media\/(\d+)$/)) && m === 'DELETE') {
    await requireAdmin(req, env);
    const r = await env.DB.prepare('SELECT key FROM media WHERE id=?').bind(parseInt(mm[1])).first();
    if (r) {
      await blobDelete(env, r.key);
      await env.DB.prepare('DELETE FROM media WHERE id=?').bind(parseInt(mm[1])).run();
    }
    return json({ ok: true });
  }

  fail(404, 'পাওয়া যায়নি');
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/api/')) {
      try {
        return await api(req, env, url);
      } catch (e) {
        if (e instanceof HttpError) return json({ error: e.message, code: e.code }, e.status);
        console.error(e);
        return json({ error: 'সার্ভারে সমস্যা হয়েছে' }, 500);
      }
    }
    if (url.pathname.startsWith('/m/')) {
      try {
        await requireViewer(req, env);
        return await serveBlob(req, env, decodeURIComponent(url.pathname.slice(3)));
      } catch (e) {
        if (e instanceof HttpError) return new Response(e.message, { status: e.status });
        console.error(e);
        return new Response('error', { status: 500 });
      }
    }
    return env.ASSETS.fetch(req);
  },
};
