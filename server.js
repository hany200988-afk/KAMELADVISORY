'use strict';
/* خادم نظام إدارة المكتب — Kamel Advisory
   دخول بيوزر وباسورد، بيانات مشتركة بين الموظفين، تخزين الملفات، واستقبال إشعارات الساب. */
const express = require('express'), Database = require('better-sqlite3'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const PORT = +process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const FILES = path.join(DATA, 'files');
fs.mkdirSync(FILES, { recursive: true });
const db = new Database(path.join(DATA, 'office.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT, role TEXT NOT NULL, hash TEXT NOT NULL, active INTEGER DEFAULT 1, created TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT NOT NULL, version INTEGER NOT NULL, updated TEXT, by TEXT);
CREATE TABLE IF NOT EXISTS notifications(id TEXT PRIMARY KEY, data TEXT NOT NULL, source TEXT, ref TEXT, created TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS n_ref ON notifications(source, ref) WHERE ref <> '';
CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, name TEXT, type TEXT, size INTEGER, created TEXT);
`);

/* ---------- كلمات المرور والجلسات ---------- */
const hashPw = pw => { const s = crypto.randomBytes(16); return s.toString('hex') + ':' + crypto.scryptSync(pw, s, 64).toString('hex'); };
const checkPw = (pw, h) => { const [s, k] = String(h).split(':'); if (!s || !k) return false; const d = crypto.scryptSync(pw, Buffer.from(s, 'hex'), 64); return crypto.timingSafeEqual(d, Buffer.from(k, 'hex')); };
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const ROLES = ['مدير', 'محاسب', 'مراجع', 'إداري'];
const SESSION_DAYS = 14;

if (!db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  db.prepare('INSERT INTO users(username,name,role,hash,created) VALUES(?,?,?,?,?)').run('admin', 'المدير', 'مدير', hashPw(pw), new Date().toISOString());
  console.log('\n==============================================\n تم إنشاء المستخدم الأول\n اليوزر: admin\n الباسورد: ' + pw + '\n غيّره بعد أول دخول من صفحة /admin\n==============================================\n');
}

const app = express();
if (process.env.TRUST_PROXY) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'same-origin'); res.setHeader('X-Frame-Options', 'SAMEORIGIN'); next(); });
app.use(express.json({ limit: '60mb' }));

const cookies = req => Object.fromEntries(String(req.headers.cookie || '').split(';').map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(x => x[0]));
const secureCookie = req => process.env.COOKIE_SECURE === '1' || req.secure;
function setSid(req, res, token, maxAge) {
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}` + (secureCookie(req) ? '; Secure' : ''));
}
function auth(req, res, next) {
  const t = cookies(req).sid;
  const row = t && db.prepare('SELECT u.id,u.username,u.name,u.role,u.active,s.expires FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?').get(sha(t));
  if (!row || !row.active || row.expires < Date.now()) { req.user = null; } else req.user = row;
  next();
}
const needUser = (req, res, next) => req.user ? next() : (req.path.startsWith('/api/') ? res.status(401).json({ error: 'login' }) : res.redirect('/login'));
const needAdmin = (req, res, next) => req.user && req.user.role === 'مدير' ? next() : res.status(403).json({ error: 'admin only' });
// الاستقبال من إضافة المتصفح: محميّ برمز INGEST_TOKEN (لا كوكيز)، لذلك نسمح بـ CORS لهذا المسار فقط
app.use('/api/ingest', (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'content-type, x-ingest-token');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
// حماية CSRF: الطلبات المعدِّلة يجب أن تأتي من نفس الموقع
app.use((req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.path === '/api/ingest') return next();
  const o = req.headers.origin; if (o) { try { if (new URL(o).host !== req.headers.host) return res.status(403).json({ error: 'origin' }); } catch (e) { return res.status(403).json({ error: 'origin' }); } }
  next();
});
app.use(auth);

/* ---------- تسجيل الدخول ---------- */
const tries = new Map();
app.post('/api/login', (req, res) => {
  const ip = req.ip, now = Date.now(), t = (tries.get(ip) || []).filter(x => now - x < 600000);
  if (t.length >= 10) return res.status(429).json({ error: 'محاولات كثيرة — انتظر 10 دقائق' });
  const { username, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(username || '').trim().toLowerCase());
  if (!u || !u.active || !checkPw(String(password || ''), u.hash)) { t.push(now); tries.set(ip, t); return res.status(401).json({ error: 'اليوزر أو الباسورد غير صحيح' }); }
  tries.delete(ip);
  const tok = crypto.randomBytes(32).toString('hex');
  db.prepare('DELETE FROM sessions WHERE expires<?').run(now);
  db.prepare('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(sha(tok), u.id, now + SESSION_DAYS * 864e5);
  setSid(req, res, tok, SESSION_DAYS * 86400);
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => { const t = cookies(req).sid; if (t) db.prepare('DELETE FROM sessions WHERE token=?').run(sha(t)); setSid(req, res, '', 0); res.json({ ok: true }); });
app.get('/api/me', needUser, (req, res) => res.json({ username: req.user.username, name: req.user.name, role: req.user.role }));
app.post('/api/password', needUser, (req, res) => {
  const { old, pw } = req.body || {}; const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (!checkPw(String(old || ''), u.hash)) return res.status(400).json({ error: 'الباسورد الحالي غير صحيح' });
  if (String(pw || '').length < 8) return res.status(400).json({ error: 'الباسورد الجديد 8 أحرف على الأقل' });
  db.prepare('UPDATE users SET hash=? WHERE id=?').run(hashPw(pw), u.id); res.json({ ok: true });
});

/* ---------- إدارة المستخدمين (للمدير) ---------- */
app.get('/api/users', needUser, needAdmin, (req, res) => res.json(db.prepare('SELECT id,username,name,role,active,created FROM users ORDER BY id').all()));
app.post('/api/users', needUser, needAdmin, (req, res) => {
  const { username, name, role, password } = req.body || {}; const un = String(username || '').trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,30}$/.test(un)) return res.status(400).json({ error: 'اليوزر: 3–30 حرفًا إنجليزيًا أو أرقامًا' });
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'دور غير معروف' });
  if (String(password || '').length < 8) return res.status(400).json({ error: 'الباسورد 8 أحرف على الأقل' });
  try { db.prepare('INSERT INTO users(username,name,role,hash,created) VALUES(?,?,?,?,?)').run(un, String(name || un), role, hashPw(password), new Date().toISOString()); } catch (e) { return res.status(400).json({ error: 'اليوزر موجود بالفعل' }); }
  res.json({ ok: true });
});
app.patch('/api/users/:id', needUser, needAdmin, (req, res) => {
  const id = +req.params.id, { name, role, active, password } = req.body || {}; const u = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  if (!u) return res.status(404).json({ error: 'غير موجود' });
  if (id === req.user.id && (active === 0 || (role && role !== 'مدير'))) return res.status(400).json({ error: 'لا يمكنك إيقاف نفسك أو خفض دورك' });
  if (role && !ROLES.includes(role)) return res.status(400).json({ error: 'دور غير معروف' });
  if (password !== undefined) { if (String(password).length < 8) return res.status(400).json({ error: 'الباسورد 8 أحرف على الأقل' }); db.prepare('UPDATE users SET hash=? WHERE id=?').run(hashPw(password), id); db.prepare('DELETE FROM sessions WHERE user_id=?').run(id); }
  if (name !== undefined) db.prepare('UPDATE users SET name=? WHERE id=?').run(String(name), id);
  if (role) db.prepare('UPDATE users SET role=? WHERE id=?').run(role, id);
  if (active !== undefined) { db.prepare('UPDATE users SET active=? WHERE id=?').run(active ? 1 : 0, id); if (!active) db.prepare('DELETE FROM sessions WHERE user_id=?').run(id); }
  res.json({ ok: true });
});
app.delete('/api/users/:id', needUser, needAdmin, (req, res) => {
  const id = +req.params.id; if (id === req.user.id) return res.status(400).json({ error: 'لا يمكنك حذف نفسك' });
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(id); db.prepare('DELETE FROM users WHERE id=?').run(id); res.json({ ok: true });
});

/* ---------- البيانات المشتركة (key/value بنسخ للتحقق من التعارض) ---------- */
const KEYRE = /^(kamel_|auditdb::)[^\u0000]{0,300}$/;
app.get('/api/kv/versions', needUser, (req, res) => res.json(Object.fromEntries(db.prepare('SELECT key,version FROM kv').all().map(r => [r.key, r.version]))));
app.put('/api/kv/:key', needUser, (req, res) => {
  const k = req.params.key; if (!KEYRE.test(k)) return res.status(400).json({ error: 'مفتاح غير مسموح' });
  if (k === 'kamel_perms' && req.user.role !== 'مدير') return res.status(403).json({ error: 'للمدير فقط' });
  const { value, v } = req.body || {}; if (typeof value !== 'string') return res.status(400).json({ error: 'value' });
  const cur = db.prepare('SELECT version FROM kv WHERE key=?').get(k);
  if (cur && cur.version !== (+v || 0)) return res.status(409).json({ error: 'conflict', version: cur.version });
  if (!cur && (+v || 0) !== 0) return res.status(409).json({ error: 'conflict', version: 0 });
  const nv = (cur ? cur.version : 0) + 1;
  db.prepare('INSERT INTO kv(key,value,version,updated,by) VALUES(?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,version=excluded.version,updated=excluded.updated,by=excluded.by').run(k, value, nv, new Date().toISOString(), req.user.username);
  res.json({ version: nv });
});
app.delete('/api/kv/:key', needUser, (req, res) => { if (KEYRE.test(req.params.key)) db.prepare('DELETE FROM kv WHERE key=?').run(req.params.key); res.json({ ok: true }); });

/* ---------- الملفات ---------- */
const FID = /^[A-Za-z0-9._-]{1,80}$/;
const OKTYPE = /^(application\/pdf|image\/(png|jpe?g|webp|gif)|text\/(plain|csv)|application\/(zip|vnd\.openxmlformats-officedocument\.[\w.+-]+|msword|vnd\.ms-excel|vnd\.ms-powerpoint))$/;
const fpath = id => path.join(FILES, id);
app.put('/api/files/:id', needUser, express.raw({ type: () => true, limit: '60mb' }), (req, res) => {
  const id = req.params.id; if (!FID.test(id)) return res.status(400).json({ error: 'id' });
  const buf = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  const ty = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  let name = ''; try { name = decodeURIComponent(String(req.headers['x-file-name'] || '')); } catch (e) { }
  fs.writeFileSync(fpath(id), buf);
  db.prepare('INSERT INTO files(id,name,type,size,created) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,type=excluded.type,size=excluded.size').run(id, name.slice(0, 200), OKTYPE.test(ty) ? ty : 'application/octet-stream', buf.length, new Date().toISOString());
  res.json({ ok: true, size: buf.length });
});
app.get('/api/files/:id', needUser, (req, res) => {
  const id = req.params.id, m = FID.test(id) && db.prepare('SELECT * FROM files WHERE id=?').get(id);
  if (!m || !fs.existsSync(fpath(id))) return res.status(404).end();
  res.setHeader('Content-Type', m.type); res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox"); res.setHeader('Cache-Control', 'private, max-age=3600');
  fs.createReadStream(fpath(id)).pipe(res);
});
app.delete('/api/files/:id', needUser, (req, res) => { const id = req.params.id; if (FID.test(id)) { db.prepare('DELETE FROM files WHERE id=?').run(id); try { fs.unlinkSync(fpath(id)); } catch (e) { } } res.json({ ok: true }); });

/* ---------- إشعارات ومستندات الساب ---------- */
app.get('/api/notifications', needUser, (req, res) => res.json({ items: db.prepare('SELECT id,data FROM notifications ORDER BY created DESC').all().map(r => ({ ...JSON.parse(r.data), id: r.id })) }));
app.put('/api/notifications/:id', needUser, (req, res) => {
  const it = req.body || {}, id = String(req.params.id).slice(0, 80);
  if (typeof it !== 'object' || Array.isArray(it)) return res.status(400).json({ error: 'body' });
  const old = db.prepare('SELECT created FROM notifications WHERE id=?').get(id);
  db.prepare('INSERT INTO notifications(id,data,source,ref,created) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data').run(id, JSON.stringify({ ...it, id }), String(it.source || 'يدوي'), String(it.ref || ''), old ? old.created : new Date().toISOString());
  res.json({ ok: true });
});
app.delete('/api/notifications/:id', needUser, (req, res) => {
  const r = db.prepare('SELECT data FROM notifications WHERE id=?').get(req.params.id);
  if (r) { try { (JSON.parse(r.data).files || []).forEach(f => { if (FID.test(f.id)) { db.prepare('DELETE FROM files WHERE id=?').run(f.id); try { fs.unlinkSync(fpath(f.id)); } catch (e) { } } }); } catch (e) { } db.prepare('DELETE FROM notifications WHERE id=?').run(req.params.id); }
  res.json({ ok: true });
});
const nzs = s => String(s || '').replace(/\s+/g, '').replace(/[ىي]/g, 'ي').replace(/[ةه]/g, 'ه').replace(/[أإآ]/g, 'ا').toLowerCase();
// نقطة استقبال للربط الآلي (سكريبت أو خدمة وسيطة تدفع الإشعارات)
app.post('/api/ingest', (req, res) => {
  const tok = process.env.INGEST_TOKEN;
  if (!tok) return res.status(503).json({ error: 'INGEST_TOKEN غير مضبوط' });
  const given = String(req.headers['x-ingest-token'] || '');
  if (given.length !== tok.length || !crypto.timingSafeEqual(Buffer.from(given), Buffer.from(tok))) return res.status(401).json({ error: 'token' });
  const b = req.body || {}; if (!b.title) return res.status(400).json({ error: 'title مطلوب' });
  const ref = String(b.ref || '');
  if (ref && db.prepare("SELECT 1 FROM notifications WHERE source='الساب' AND ref=?").get(ref)) return res.json({ duplicate: true });
  let cid = '';
  try {
    const cl = JSON.parse((db.prepare("SELECT value FROM kv WHERE key='kamel_clients_v1'").get() || { value: '[]' }).value);
    const c = cl.find(x => (b.client_id && String(x.company_id) === String(b.client_id)) || (b.tax_registration_number && String(x.tax_registration_number || '').replace(/\D/g, '') === String(b.tax_registration_number).replace(/\D/g, '')) || (b.company_name && nzs(x.company_name) === nzs(b.company_name)));
    if (c) cid = String(c.company_id);
  } catch (e) { }
  const files = [];
  for (const f of (b.files || []).slice(0, 10)) {
    try {
      const buf = Buffer.from(String(f.base64 || ''), 'base64'); if (!buf.length) continue;
      const fid = 'in' + crypto.randomBytes(8).toString('hex'); fs.writeFileSync(fpath(fid), buf);
      const ty = String(f.type || '').toLowerCase();
      db.prepare('INSERT INTO files(id,name,type,size,created) VALUES(?,?,?,?,?)').run(fid, String(f.name || 'file').slice(0, 200), OKTYPE.test(ty) ? ty : 'application/octet-stream', buf.length, new Date().toISOString());
      files.push({ id: fid, name: String(f.name || 'file'), size: buf.length, type: OKTYPE.test(ty) ? ty : 'application/octet-stream' });
    } catch (e) { }
  }
  const id = 'sab' + crypto.randomBytes(8).toString('hex');
  const item = { id, client_id: cid, kind: b.kind || 'إشعار', title: String(b.title).slice(0, 300), received: b.received || new Date().toISOString().slice(0, 10), deadline: b.deadline || '', status: 'قيد المتابعة', ref, body: String(b.body || '').slice(0, 20000), files, source: 'الساب', read: false, unmatched: !cid };
  db.prepare('INSERT INTO notifications(id,data,source,ref,created) VALUES(?,?,?,?,?)').run(id, JSON.stringify(item), 'الساب', ref, new Date().toISOString());
  res.json({ ok: true, id, matched: !!cid });
});

/* ---------- حسابات بوابة الضرائب (للمدير فقط) — يستخدمها سكربت tools/sync_portal.py ---------- */
app.get('/api/portal-accounts', needUser, needAdmin, (req, res) => {
  let cl = []; try { cl = JSON.parse((db.prepare("SELECT value FROM kv WHERE key='kamel_clients_v1'").get() || { value: '[]' }).value); } catch (e) { }
  res.setHeader('Cache-Control', 'no-store');
  res.json({ accounts: cl.filter(c => c.status !== 'Inactive' && c.portal_user && c.portal_pass).map(c => ({ company_id: c.company_id, name: c.company_name, tax_registration_number: c.tax_registration_number || '', portal_user: c.portal_user, portal_pass: c.portal_pass })) });
});

/* ---------- وسيط التحليل بالذكاء الاصطناعي (اختياري) ---------- */
app.post('/api/ai', needUser, async (req, res) => {
  const key = process.env.ANTHROPIC_API_KEY; if (!key) return res.status(503).json({ error: 'التحليل الآلي غير مفعّل: ضع ANTHROPIC_API_KEY في إعدادات الخادم' });
  const { prompt, images } = req.body || {}; if (!prompt) return res.status(400).json({ error: 'prompt' });
  const content = [...(images || []).slice(0, 6).map(i => ({ type: 'image', source: { type: 'base64', media_type: i.type, data: i.data } })), { type: 'text', text: String(prompt) + '\n\nأعد كائن JSON صالحًا فقط بلا أي شرح أو علامات.' }];
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' }, body: JSON.stringify({ model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5', max_tokens: 4000, messages: [{ role: 'user', content }] }) });
    const j = await r.json(); if (!r.ok) return res.status(502).json({ error: (j.error && j.error.message) || ('http ' + r.status) });
    const txt = (j.content || []).map(c => c.text || '').join('');
    const a = txt.indexOf('{'), z = txt.lastIndexOf('}'); if (a < 0 || z < a) return res.status(502).json({ error: 'رد غير مفهوم من النموذج' });
    res.json({ json: JSON.parse(txt.slice(a, z + 1)) });
  } catch (e) { res.status(502).json({ error: 'تعذّر الاتصال بخدمة التحليل' }); }
});

/* ---------- الصفحات ---------- */
const PUB = path.join(__dirname, 'public');
app.get('/login', (req, res) => req.user ? res.redirect('/') : res.sendFile(path.join(PUB, 'login.html')));
app.get('/admin', needUser, (req, res) => req.user.role === 'مدير' ? res.sendFile(path.join(PUB, 'admin.html')) : res.status(403).send('للمدير فقط'));
const jsonJs = o => JSON.stringify(o).replace(/</g, '\\u003c').split(String.fromCharCode(8232)).join('\\u2028').split(String.fromCharCode(8233)).join('\\u2029');
app.get('/', needUser, (req, res) => {
  let html = fs.readFileSync(path.join(PUB, 'app.html'), 'utf8');
  const rows = db.prepare('SELECT key,value,version FROM kv').all();
  const D = {}, V = {}; rows.forEach(r => { D[r.key] = r.value; V[r.key] = r.version; });
  const S = { user: { username: req.user.username, name: req.user.name, role: req.user.role }, ai: !!process.env.ANTHROPIC_API_KEY, v: V, empty: !rows.length };
  const pre = `<script>window.__SRV=${jsonJs(S)};(function(){var D=${jsonJs(D)},S=window.__SRV;S.sent={};try{var del=[];for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);if(/^(kamel_|auditdb::)/.test(k)&&!(k in D)&&!S.empty)del.push(k)}del.forEach(function(k){localStorage.removeItem(k)});for(var k in D){localStorage.setItem(k,D[k]);S.sent[k]=D[k]}}catch(e){}})()</script>`;
  const post = fs.readFileSync(path.join(PUB, 'boot.js'), 'utf8');
  const t1 = html.indexOf('<div id="toast"></div>'); if (t1 >= 0) html = html.slice(0, t1) + '<div id="toast"></div>' + pre + html.slice(t1 + 22);
  const t2 = html.lastIndexOf('</body>'); html = html.slice(0, t2) + '<script>' + post.replace(/<\/script/gi, '<\\/script') + '</script>' + html.slice(t2);
  res.setHeader('Cache-Control', 'no-store'); res.type('html').send(html);
});
app.use((req, res) => res.status(404).send('غير موجود'));
app.listen(PORT, () => console.log('نظام إدارة المكتب يعمل على المنفذ ' + PORT));
