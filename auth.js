'use strict';
/*
  Accounts for Imposter:
  - email + password (scrypt, no extra packages)
  - Google sign-in (OpenID Connect, code flow)
  - WhatsApp one-time codes (Meta WhatsApp Cloud API template message)
  Sessions are signed, httpOnly cookies. Nothing secret is stored in the browser.
*/
const crypto = require('crypto');

const COOKIE = 'imp_sid';
const OAUTH_COOKIE = 'imp_oauth';
const THIRTY_DAYS = 30 * 24 * 3600;

function install(app, { pool, secret, publicUrl, isAdmin }) {
  const SECURE = publicUrl.startsWith('https://');
  const GOOGLE_ID = process.env.GOOGLE_CLIENT_ID || '';
  const GOOGLE_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
  const GOOGLE_ON = !!(GOOGLE_ID && GOOGLE_SECRET && publicUrl);
  const WA_ON = !!(process.env.WA_TOKEN && process.env.WA_PHONE_ID);
  const OTP_DEV = process.env.OTP_DEV === 'true' && process.env.NODE_ENV !== 'production';

  /* ---------- schema ---------- */
  const schema = `
    create table if not exists users (
      id text primary key,
      name text,
      email text unique,
      phone text unique,
      password text,
      google text unique,
      created bigint not null
    );
    create table if not exists otps (
      phone text primary key,
      code text not null,
      expires bigint not null,
      attempts integer not null default 0,
      sent_at bigint not null
    );`;

  /* ---------- helpers ---------- */
  const sign = v => crypto.createHmac('sha256', secret).update(v).digest('base64url');
  const sameSig = (a, b) => {
    const x = Buffer.from(a), y = Buffer.from(b);
    return x.length === y.length && crypto.timingSafeEqual(x, y);
  };
  function cookies(req) {
    const out = {};
    for (const part of String(req.headers.cookie || '').split(';')) {
      const i = part.indexOf('=');
      if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    }
    return out;
  }
  function setCookie(res, name, value, maxAge) {
    res.append('Set-Cookie', `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${SECURE ? '; Secure' : ''}`);
  }
  function startSession(res, uid) {
    const exp = Date.now() + THIRTY_DAYS * 1000;
    const v = `${uid}.${exp}`;
    setCookie(res, COOKIE, `${v}.${sign(v)}`, THIRTY_DAYS);
  }
  function readSession(req) {
    const c = cookies(req)[COOKIE];
    if (!c) return null;
    const parts = c.split('.');
    if (parts.length !== 3) return null;
    const [uid, exp, sig] = parts;
    if (!sameSig(sign(`${uid}.${exp}`), sig)) return null;
    if (Date.now() > Number(exp)) return null;
    return uid;
  }
  async function currentUser(req) {
    const uid = readSession(req);
    if (!uid) return null;
    const r = await pool.query('select id, name, email, phone from users where id=$1', [uid]);
    return r.rows[0] || null;
  }
  const hashPassword = pw => {
    const salt = crypto.randomBytes(16);
    const h = crypto.scryptSync(pw, salt, 64);
    return `scrypt$${salt.toString('base64')}$${h.toString('base64')}`;
  };
  const checkPassword = (pw, stored) => {
    const [alg, s, h] = String(stored || '').split('$');
    if (alg !== 'scrypt' || !s || !h) return false;
    const hh = crypto.scryptSync(pw, Buffer.from(s, 'base64'), 64);
    const b = Buffer.from(h, 'base64');
    return b.length === hh.length && crypto.timingSafeEqual(b, hh);
  };
  const otpHash = (phone, code) => crypto.createHmac('sha256', secret).update(`otp:${phone}:${code}`).digest('base64url');
  const normEmail = e => String(e || '').trim().toLowerCase().slice(0, 200);
  const emailOk = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
  const normPhone = p => {
    const d = String(p || '').replace(/[\s()-]/g, '');
    return /^\+?\d{8,15}$/.test(d) ? '+' + d.replace(/^\+/, '') : null;
  };

  /* simple rate limit per IP for sign-in endpoints */
  const hits = new Map();
  function limit(max, windowMs) {
    return (req, res, next) => {
      const key = req.ip + req.path;
      const now = Date.now();
      const h = hits.get(key) || { n: 0, reset: now + windowMs };
      if (now > h.reset) { h.n = 0; h.reset = now + windowMs; }
      h.n++;
      hits.set(key, h);
      if (h.n > max) return res.status(429).json({ error: 'Too many attempts. Please wait a few minutes.' });
      next();
    };
  }

  /* ---------- who am I ---------- */
  app.get('/api/auth/me', async (req, res, next) => {
    try {
      const user = await currentUser(req);
      res.json({ user, google: GOOGLE_ON, whatsapp: WA_ON || OTP_DEV });
    } catch (e) { next(e); }
  });

  /* ---------- email + password ---------- */
  app.post('/api/auth/signup', limit(10, 15 * 60e3), async (req, res, next) => {
    try {
      const name = String((req.body || {}).name || '').trim().slice(0, 60);
      const email = normEmail((req.body || {}).email);
      const password = String((req.body || {}).password || '');
      if (name.length < 2) return res.status(400).json({ error: 'Please enter your name' });
      if (!emailOk(email)) return res.status(400).json({ error: 'Please enter a valid email address' });
      if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
      const exists = await pool.query('select 1 from users where email=$1', [email]);
      if (exists.rowCount) return res.status(409).json({ error: 'An account with this email already exists. Try logging in.' });
      const id = crypto.randomUUID();
      await pool.query('insert into users (id, name, email, password, created) values ($1,$2,$3,$4,$5)',
        [id, name, email, hashPassword(password), Date.now()]);
      startSession(res, id);
      res.status(201).json({ user: { id, name, email, phone: null } });
    } catch (e) { next(e); }
  });

  app.post('/api/auth/login', limit(20, 15 * 60e3), async (req, res, next) => {
    try {
      const email = normEmail((req.body || {}).email);
      const password = String((req.body || {}).password || '');
      const r = await pool.query('select id, name, email, phone, password from users where email=$1', [email]);
      const u = r.rows[0];
      if (!u || !checkPassword(password, u.password)) {
        return res.status(401).json({ error: 'Email or password is incorrect' });
      }
      startSession(res, u.id);
      res.json({ user: { id: u.id, name: u.name, email: u.email, phone: u.phone } });
    } catch (e) { next(e); }
  });

  app.post('/api/auth/logout', (req, res) => {
    setCookie(res, COOKIE, '', 0);
    res.json({ ok: true });
  });

  /* ---------- WhatsApp one-time code ---------- */
  async function sendWhatsAppOtp(phone, code) {
    const r = await fetch(`https://graph.facebook.com/v20.0/${process.env.WA_PHONE_ID}/messages`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.WA_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messaging_product: 'whatsapp',
        to: phone.replace('+', ''),
        type: 'template',
        template: {
          name: process.env.WA_TEMPLATE || 'otp_login',
          language: { code: process.env.WA_LANG || 'en_US' },
          components: [{ type: 'body', parameters: [{ type: 'text', text: code }] }],
        },
      }),
    });
    if (!r.ok) throw new Error('WhatsApp API ' + r.status + ': ' + (await r.text()).slice(0, 300));
  }

  app.post('/api/auth/otp/send', limit(8, 15 * 60e3), async (req, res, next) => {
    try {
      if (!WA_ON && !OTP_DEV) return res.status(503).json({ error: 'WhatsApp login is not set up yet' });
      const phone = normPhone((req.body || {}).phone);
      if (!phone) return res.status(400).json({ error: 'Enter your number with the country code, e.g. +91 98765 43210' });
      const last = await pool.query('select sent_at from otps where phone=$1', [phone]);
      if (last.rowCount && Date.now() - Number(last.rows[0].sent_at) < 30e3) {
        return res.status(429).json({ error: 'Please wait 30 seconds before asking for another code' });
      }
      const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
      await pool.query(
        `insert into otps (phone, code, expires, attempts, sent_at) values ($1,$2,$3,0,$4)
         on conflict (phone) do update set code=excluded.code, expires=excluded.expires, attempts=0, sent_at=excluded.sent_at`,
        [phone, otpHash(phone, code), Date.now() + 5 * 60e3, Date.now()]);
      if (WA_ON) {
        try { await sendWhatsAppOtp(phone, code); }
        catch (e) { console.error('WhatsApp send failed:', e.message); return res.status(502).json({ error: 'Could not send the WhatsApp code. Check the number and try again.' }); }
        return res.json({ sent: true });
      }
      console.log(`[dev] WhatsApp code for ${phone}: ${code}`);
      res.json({ sent: true, devCode: code });
    } catch (e) { next(e); }
  });

  app.post('/api/auth/otp/verify', limit(30, 15 * 60e3), async (req, res, next) => {
    try {
      const phone = normPhone((req.body || {}).phone);
      const code = String((req.body || {}).code || '').replace(/\D/g, '');
      if (!phone || code.length !== 6) return res.status(400).json({ error: 'Enter the 6-digit code' });
      const r = await pool.query('select code, expires, attempts from otps where phone=$1', [phone]);
      const row = r.rows[0];
      if (!row || Date.now() > Number(row.expires)) return res.status(400).json({ error: 'That code has expired. Ask for a new one.' });
      if (row.attempts >= 5) return res.status(429).json({ error: 'Too many wrong codes. Ask for a new one.' });
      if (!sameSig(otpHash(phone, code), row.code)) {
        await pool.query('update otps set attempts = attempts + 1 where phone=$1', [phone]);
        return res.status(400).json({ error: 'That code is not right' });
      }
      await pool.query('delete from otps where phone=$1', [phone]);
      let u = (await pool.query('select id, name, email, phone from users where phone=$1', [phone])).rows[0];
      if (!u) {
        const id = crypto.randomUUID();
        await pool.query('insert into users (id, phone, created) values ($1,$2,$3)', [id, phone, Date.now()]);
        u = { id, name: null, email: null, phone };
      }
      startSession(res, u.id);
      res.json({ user: u });
    } catch (e) { next(e); }
  });

  /* ---------- Google ---------- */
  const redirectUri = () => `${publicUrl}/api/auth/google/callback`;
  app.get('/api/auth/google', (req, res) => {
    if (!GOOGLE_ON) return res.redirect('/#login?err=google');
    const state = crypto.randomBytes(16).toString('base64url');
    setCookie(res, OAUTH_COOKIE, state, 600);
    const p = new URLSearchParams({
      client_id: GOOGLE_ID, redirect_uri: redirectUri(), response_type: 'code',
      scope: 'openid email profile', state, prompt: 'select_account',
    });
    res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + p.toString());
  });
  app.get('/api/auth/google/callback', async (req, res) => {
    try {
      const state = String(req.query.state || '');
      if (!GOOGLE_ON || !state || state !== cookies(req)[OAUTH_COOKIE] || !req.query.code) {
        return res.redirect('/#login?err=google');
      }
      setCookie(res, OAUTH_COOKIE, '', 0);
      const tok = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code: String(req.query.code), client_id: GOOGLE_ID, client_secret: GOOGLE_SECRET,
          redirect_uri: redirectUri(), grant_type: 'authorization_code',
        }),
      }).then(r => r.json());
      if (!tok.access_token) throw new Error('token exchange failed');
      const info = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
        headers: { Authorization: `Bearer ${tok.access_token}` },
      }).then(r => r.json());
      if (!info.sub) throw new Error('no profile');
      const email = normEmail(info.email);
      let u = (await pool.query('select id, name, email, phone from users where google=$1', [info.sub])).rows[0];
      if (!u && email) u = (await pool.query('select id, name, email, phone from users where email=$1', [email])).rows[0];
      if (u) {
        await pool.query('update users set google=$2, name=coalesce(name,$3) where id=$1', [u.id, info.sub, info.name || null]);
      } else {
        const id = crypto.randomUUID();
        await pool.query('insert into users (id, name, email, google, created) values ($1,$2,$3,$4,$5)',
          [id, info.name || null, email || null, info.sub, Date.now()]);
        u = { id, name: info.name || null, email, phone: null };
      }
      startSession(res, u.id);
      res.redirect('/#discover');
    } catch (e) {
      console.error('Google sign-in failed:', e.message);
      res.redirect('/#login?err=google');
    }
  });

  /* ---------- per-listener subscription (signed-in users only) ---------- */
  app.get('/api/subs/me', async (req, res, next) => {
    try {
      const u = await currentUser(req); if (!u) return res.status(401).json({ error: 'Please log in' });
      const r = await pool.query('select data from subs where cid=$1', ['user:' + u.id]);
      res.json(r.rowCount ? r.rows[0].data : null);
    } catch (e) { next(e); }
  });
  app.put('/api/subs/me', async (req, res, next) => {
    try {
      const u = await currentUser(req); if (!u) return res.status(401).json({ error: 'Please log in' });
      const plan = req.body && req.body.plan;
      if (!['free', 'plus', 'year'].includes(plan)) return res.status(400).json({ error: 'Unknown plan' });
      const data = { plan, at: Date.now() };
      await pool.query('insert into subs (cid, data) values ($1,$2) on conflict (cid) do update set data=excluded.data', ['user:' + u.id, data]);
      res.json(data);
    } catch (e) { next(e); }
  });
  app.delete('/api/subs/me', async (req, res, next) => {
    try {
      const u = await currentUser(req); if (!u) return res.status(401).json({ error: 'Please log in' });
      await pool.query('delete from subs where cid=$1', ['user:' + u.id]);
      res.json({ ok: true });
    } catch (e) { next(e); }
  });

  /* ---------- guard for the music itself: admin key or a signed-in listener ---------- */
  function needListener(req, res, next) {
    if (isAdmin(req)) return next();
    currentUser(req).then(u => {
      if (!u) return res.status(401).json({ error: 'Please log in to listen' });
      next();
    }).catch(next);
  }

  return { schema, needListener, currentUser, WA_ON, OTP_DEV, GOOGLE_ON };
}

module.exports = { install };
