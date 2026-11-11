'use strict';
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const multer = require('multer');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/+$/, '');
if (!SESSION_SECRET || SESSION_SECRET.length < 32) { console.error('SESSION_SECRET is required (at least 32 characters)'); process.exit(1); }
if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is required'); process.exit(1); }
if (!ADMIN_KEY || ADMIN_KEY.length < 12) { console.error('ADMIN_KEY is required (at least 12 characters)'); process.exit(1); }

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false,
});

const MIME = {
  mp3: 'audio/mpeg',                                   // tracks: MP3 only
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif', // covers
};
const MAX_UPLOAD = 60 * 1024 * 1024;
const PLANS = ['free', 'plus', 'year'];
const FIELDS = {
  albums: ['title', 'artist', 'md', 'cover', 'coverId'],
  tracks: ['title', 'artist', 'md', 'genre', 'albumId', 'trackNo', 'audio', 'audioId', 'cover', 'coverId', 'bpm', 'scale', 'root', 'wave', 'g', 'e'],
};

const auth = require('./auth');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_UPLOAD } });
const app = express();
app.disable('x-powered-by');
// on Vercel, /files/:id arrives as /api/files/:id; map it back for the GET file route
app.use((req, res, next) => {
  if (req.method === 'GET' && req.url.startsWith('/api/files/')) req.url = req.url.slice(4);
  next();
});
app.use(express.json({ limit: '100kb' }));

/* ---------- auth ---------- */
const keyBuf = Buffer.from(ADMIN_KEY);
const ADMIN_COOKIE = 'imp_admin';
const adminSig = exp => crypto.createHmac('sha256', SESSION_SECRET).update('admin.' + exp).digest('base64url');
function sameKey(k) {
  const b = Buffer.from(String(k || ''));
  return b.length === keyBuf.length && crypto.timingSafeEqual(b, keyBuf);
}
function isAdmin(req) {
  if (sameKey(req.headers['x-admin-key'])) return true;
  const raw = String(req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(ADMIN_COOKIE + '='));
  if (!raw) return false;
  const [exp, sig] = decodeURIComponent(raw.slice(ADMIN_COOKIE.length + 1)).split('.');
  const want = adminSig(exp);
  return !!sig && want.length === sig.length && crypto.timingSafeEqual(Buffer.from(want), Buffer.from(sig)) && Date.now() < Number(exp);
}
function setAdminCookie(res, value, maxAge) {
  const secure = PUBLIC_URL.startsWith('https://') ? '; Secure' : '';
  res.append('Set-Cookie', `${ADMIN_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`);
}
app.post('/api/admin/login', (req, res) => {
  if (!sameKey((req.body || {}).key)) return res.status(401).json({ error: 'That admin key isn’t right' });
  const exp = Date.now() + 12 * 3600 * 1000;
  setAdminCookie(res, `${exp}.${adminSig(exp)}`, 12 * 3600);
  res.json({ admin: true });
});
app.post('/api/admin/logout', (req, res) => {
  setAdminCookie(res, '', 0);
  res.json({ admin: false });
});

/* names: remove the source-site tags from track, artist, album and director names */
const SOURCE_TAGS = /\s*-\s*(mass\s*tamilan|mp3\s*chetta|mp3\s*bhai)\b/ig;
const cleanName = v => (v == null ? null : String(v).replace(SOURCE_TAGS, '').replace(/\s+/g, ' ').trim());
function requireAdmin(req, res, next) {
  if (!isAdmin(req)) return res.status(401).json({ error: 'Admin key required' });
  next();
}

/* ---------- live sync: server-sent events ---------- */
const clients = new Set();
function notify(col) {
  for (const c of clients) c.write(`event: change\ndata: ${JSON.stringify({ col })}\n\n`);
}
app.get('/api/events', (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.flushHeaders();
  res.write('retry: 2000\n\n');
  clients.add(res);
  const ping = setInterval(() => res.write(': ping\n\n'), 25000);
  req.on('close', () => { clearInterval(ping); clients.delete(res); });
});

/* ---------- helpers ---------- */
const newId = () => crypto.randomUUID();
const clip = (v, n = 200) => (v == null ? null : String(v).trim().slice(0, n));
function pick(col, body, partial) {
  const out = {};
  for (const f of FIELDS[col]) {
    if (!(f in body)) continue;
    let v = body[f];
    if (['title', 'artist', 'md'].includes(f)) v = clip(cleanName(v), 200);
    else if (['genre', 'scale', 'wave', 'e'].includes(f)) v = clip(v, f === 'e' ? 8 : 200);
    else if (['cover', 'audio'].includes(f)) v = clip(v, 500);
    else if (['coverId', 'audioId', 'albumId'].includes(f)) v = clip(v, 64);
    else if (['trackNo', 'bpm', 'root', 'g'].includes(f)) v = Number.isFinite(+v) ? +v : 0;
    out[f] = v;
  }
  if (!partial) {
    if (col === 'albums' && !out.title) throw new Error('Album title is required');
    if (col === 'tracks' && !out.title) throw new Error('Track title is required');
  }
  return out;
}
async function fileIdsOf(col, id) {
  const r = await pool.query(`select data from ${col} where id=$1`, [id]);
  if (!r.rowCount) return [];
  const d = r.rows[0].data;
  return [d.audioId, d.coverId].filter(Boolean);
}
async function deleteFiles(ids) {
  if (ids.length) await pool.query('delete from files where id = any($1)', [ids]);
}

/* ---------- accounts: sign-up, log-in, Google, WhatsApp codes ---------- */
const A = auth.install(app, { pool, secret: SESSION_SECRET, publicUrl: PUBLIC_URL, isAdmin });

/* ---------- collections ---------- */
app.get('/api/me', (req, res) => res.json({ admin: isAdmin(req) }));

for (const col of ['albums', 'tracks']) {
  app.get(`/api/${col}`, A.needListener, async (req, res, next) => {
    try {
      const r = await pool.query(`select id, data from ${col} order by at desc`);
      res.json(r.rows.map(x => ({ id: x.id, ...x.data })));
    } catch (e) { next(e); }
  });

  app.post(`/api/${col}`, requireAdmin, async (req, res, next) => {
    try {
      const data = pick(col, req.body || {}, false);
      const id = newId();
      await pool.query(`insert into ${col} (id, data, at) values ($1, $2, $3)`, [id, data, Date.now()]);
      notify(col);
      res.status(201).json({ id });
    } catch (e) { if (e.message.includes('required')) return res.status(400).json({ error: e.message }); next(e); }
  });

  app.patch(`/api/${col}/:id`, requireAdmin, async (req, res, next) => {
    try {
      const data = pick(col, req.body || {}, true);
      const r = await pool.query(`update ${col} set data = data || $2::jsonb where id = $1`, [req.params.id, data]);
      if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
      notify(col);
      res.json({ ok: true });
    } catch (e) { next(e); }
  });

  app.delete(`/api/${col}/:id`, requireAdmin, async (req, res, next) => {
    try {
      const ids = await fileIdsOf(col, req.params.id);
      if (col === 'albums') {
        const kids = await pool.query('select id, data from tracks where data->>\'albumId\' = $1', [req.params.id]);
        for (const t of kids.rows) {
          ids.push(...[t.data.audioId, t.data.coverId].filter(Boolean));
        }
        await pool.query('delete from tracks where data->>\'albumId\' = $1', [req.params.id]);
        if (kids.rowCount) notify('tracks');
      }
      const r = await pool.query(`delete from ${col} where id = $1`, [req.params.id]);
      await deleteFiles(ids);
      if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
      notify(col);
      res.json({ ok: true });
    } catch (e) { next(e); }
  });
}

/* ---------- files: upload, stream, delete ---------- */
app.post('/api/upload', requireAdmin, upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file received' });
    let ext = (req.file.originalname.includes('.') ? req.file.originalname.split('.').pop() : '').toLowerCase();
    if (!MIME[ext]) {
      const byType = { 'audio/mpeg': 'mp3', 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif' };
      ext = byType[(req.file.mimetype || '').toLowerCase()] || ext;
    }
    const mime = MIME[ext];
    if (!mime) return res.status(415).json({ error: `Only MP3 audio and image files can be uploaded (got .${ext})` });
    const id = newId();
    await pool.query('insert into files (id, mime, bytes, size, created) values ($1,$2,$3,$4,$5)',
      [id, mime, req.file.buffer, req.file.size, Date.now()]);
    res.status(201).json({ id, url: `/files/${id}` });
  } catch (e) { next(e); }
});

app.get('/files/:id', A.needListener, async (req, res, next) => {
  try {
    if (!/^[0-9a-f-]{36}$/.test(req.params.id)) return res.sendStatus(404);
    const r = await pool.query('select mime, bytes from files where id=$1', [req.params.id]);
    if (!r.rowCount) return res.sendStatus(404);
    const buf = r.rows[0].bytes, total = buf.length;
    res.setHeader('Content-Type', r.rows[0].mime);
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    const m = /bytes=(\d*)-(\d*)/.exec(req.headers.range || '');
    if (m && (m[1] !== '' || m[2] !== '')) {
      let s, e;
      if (m[1] === '') { s = Math.max(0, total - parseInt(m[2], 10)); e = total - 1; }
      else { s = parseInt(m[1], 10); e = m[2] !== '' ? parseInt(m[2], 10) : total - 1; }
      if (s >= total || s > e) { res.setHeader('Content-Range', `bytes */${total}`); return res.sendStatus(416); }
      e = Math.min(e, total - 1);
      res.status(206);
      res.setHeader('Content-Range', `bytes ${s}-${e}/${total}`);
      res.setHeader('Content-Length', e - s + 1);
      return res.end(buf.subarray(s, e + 1));
    }
    res.setHeader('Content-Length', total);
    res.end(buf);
  } catch (e) { next(e); }
});

app.delete('/api/files/:id', requireAdmin, async (req, res, next) => {
  try {
    await pool.query('delete from files where id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- the app itself ---------- */
app.get('/studio', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(path.join(__dirname, 'public', 'studio.html'));
});
app.use(express.static(path.join(__dirname, 'public'), {
  index: 'index.html',
  setHeaders(res, p) { if (p.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache'); },
}));

app.use((err, req, res, next) => {
  if (err && err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'File is too large (max 60 MB)' });
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

async function migrate() {
  await pool.query(A.schema);
  await pool.query(`
    create table if not exists albums (id text primary key, data jsonb not null, at bigint not null default 0);
    create table if not exists tracks (id text primary key, data jsonb not null, at bigint not null default 0);
    create table if not exists files  (id text primary key, mime text not null, bytes bytea not null, size integer not null, created bigint not null);
    create table if not exists subs   (cid text primary key, data jsonb not null);
    create index if not exists tracks_album on tracks ((data->>'albumId'));
  `);
}

let ready = null;
function ensureReady() {
  if (!ready) ready = migrate().catch(e => { ready = null; throw e; });
  return ready;
}
app.use(async (req, res, next) => {
  try { await ensureReady(); next(); }
  catch (e) { console.error('Database setup failed:', e.message); res.status(503).json({ error: 'Database is not reachable right now' }); }
});

if (process.env.VERCEL) {
  // on Vercel the platform calls the app for each request (see api/[...all].js)
  module.exports = app;
} else {
  ensureReady().then(() => {
    app.listen(PORT, () => console.log(`Imposter listening on :${PORT}`));
  }).catch(e => { console.error('Database setup failed:', e.message); process.exit(1); });
}
