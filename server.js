'use strict';

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');

const PORT = Number(process.env.PORT) || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const APP_NAME = process.env.APP_NAME || 'Waltern Tech';

// Open mode accepts any valid-looking email with any password, so the flow
// can be walked through before the real sign-in rules are decided. Set
// AUTH_MODE=strict to require the configured account plus an email code.
const OPEN_LOGIN = (process.env.AUTH_MODE || 'open') !== 'strict';

const OTP_TTL_MS = 5 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;
const OTP_RESEND_COOLDOWN_MS = 30 * 1000;
const OTP_MAX_SENDS = 4;
const PENDING_TTL_MS = 15 * 60 * 1000;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

// __Host- cookies are pinned to this exact host and must be Secure, so the
// prefix is only usable over HTTPS.
const SESSION_COOKIE = IS_PROD ? '__Host-sid' : 'sid';
const PENDING_COOKIE = IS_PROD ? '__Host-otp' : 'otp';

// ---------------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------------

function normalizeEmail(value) {
  if (typeof value !== 'string') return '';
  const email = value.trim().toLowerCase();
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : '';
}

function loadAccount() {
  const email = normalizeEmail(process.env.LOGIN_EMAIL);
  const hash = process.env.LOGIN_PASSWORD_HASH;
  const plain = process.env.LOGIN_PASSWORD;
  if (!email || (!hash && !plain)) {
    if (!OPEN_LOGIN) {
      console.warn('[auth] AUTH_MODE=strict but LOGIN_EMAIL and LOGIN_PASSWORD_HASH (or LOGIN_PASSWORD) are not set; every sign-in will fail.');
    }
    return null;
  }
  return { email, passwordHash: hash || bcrypt.hashSync(plain, 12) };
}

// Open mode never checks the account, so don't build one (and don't warn).
const account = OPEN_LOGIN ? null : loadAccount();

// Compared against when the email is unknown, so a wrong email costs the
// same time as a wrong password and can't be told apart.
const DECOY_HASH = bcrypt.hashSync(crypto.randomBytes(18).toString('hex'), 12);

// ---------------------------------------------------------------------------
// In-memory state. One instance, so a restart signs everyone out — fine for
// a single-owner login; move to Redis/Postgres before running more than one.
// ---------------------------------------------------------------------------

const OTP_KEY = crypto.randomBytes(32);
const pending = new Map();  // challenge id -> { email, codeHash, codeExpiresAt, attempts, sends, lastSentAt, createdAt }
const sessions = new Map(); // session id -> { email, expiresAt }

function newToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashCode(challengeId, code) {
  return crypto.createHmac('sha256', OTP_KEY).update(`${challengeId}:${code}`).digest();
}

function createLimiter(max, windowMs) {
  const buckets = new Map();
  return {
    retryAfter(key) {
      const b = buckets.get(key);
      if (!b || b.resetAt <= Date.now()) return 0;
      return b.count >= max ? b.resetAt - Date.now() : 0;
    },
    hit(key) {
      const now = Date.now();
      let b = buckets.get(key);
      if (!b || b.resetAt <= now) {
        b = { count: 0, resetAt: now + windowMs };
        buckets.set(key, b);
      }
      b.count += 1;
    },
    clear(key) {
      buckets.delete(key);
    },
    sweep(now) {
      for (const [key, b] of buckets) if (b.resetAt <= now) buckets.delete(key);
    }
  };
}

const loginByIp = createLimiter(30, 15 * 60 * 1000);
const failuresByEmail = createLimiter(8, 15 * 60 * 1000);
const verifyByIp = createLimiter(40, 15 * 60 * 1000);
const sendsByEmail = createLimiter(10, 60 * 60 * 1000);
const limiters = [loginByIp, failuresByEmail, verifyByIp, sendsByEmail];

setInterval(() => {
  const now = Date.now();
  for (const [id, c] of pending) if (c.createdAt + PENDING_TTL_MS <= now) pending.delete(id);
  for (const [id, s] of sessions) if (s.expiresAt <= now) sessions.delete(id);
  for (const l of limiters) l.sweep(now);
}, 60 * 1000).unref();

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

function maskEmail(email) {
  const [local, domain] = email.split('@');
  const visible = local.length <= 2 ? local.slice(0, 1) : local.slice(0, 2);
  const tail = local.length > 4 ? local.slice(-1) : '';
  return `${visible}•••${tail}@${domain}`;
}

function otpEmailHtml(code) {
  return `<!doctype html><html><body style="margin:0;background:#ffffff;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#0b0b0f">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:460px;border:1px solid #ebe9f2;border-radius:16px">
<tr><td style="padding:36px 36px 8px"><div style="font-size:15px;font-weight:700;letter-spacing:-.01em">${APP_NAME}</div></td></tr>
<tr><td style="padding:16px 36px 0"><div style="font-size:22px;font-weight:700;letter-spacing:-.02em">Your verification code</div>
<p style="margin:10px 0 0;font-size:15px;line-height:1.6;color:#4b4b57">Enter this code to finish signing in. It expires in 5 minutes.</p></td></tr>
<tr><td style="padding:24px 36px"><div style="background:#f5f3ff;border-radius:12px;padding:20px;text-align:center;font-size:34px;font-weight:700;letter-spacing:.35em;color:#5b21b6;font-family:SFMono-Regular,Consolas,monospace">${code}</div></td></tr>
<tr><td style="padding:0 36px 36px"><p style="margin:0;font-size:13px;line-height:1.6;color:#8a8a96">If you didn't try to sign in, change your password — someone has it. Never share this code.</p></td></tr>
</table></td></tr></table></body></html>`;
}

// Resend over HTTPS rather than SMTP: Render's free instances block the
// outbound SMTP ports.
async function sendOtpEmail(to, code) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.log(`[otp] RESEND_API_KEY is not set; code for ${maskEmail(to)} is ${code}`);
    return 'log';
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: process.env.OTP_FROM || `${APP_NAME} <onboarding@resend.dev>`,
      to: [to],
      subject: `Your ${APP_NAME} verification code`,
      html: otpEmailHtml(code),
      text: `Your ${APP_NAME} verification code is ${code}. It expires in 5 minutes.`
    }),
    signal: AbortSignal.timeout(10_000)
  });
  if (!res.ok) throw new Error(`Resend responded ${res.status}: ${await res.text()}`);
  return 'email';
}

async function issueCode(challengeId, challenge) {
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  const now = Date.now();
  challenge.codeHash = hashCode(challengeId, code);
  challenge.codeExpiresAt = now + OTP_TTL_MS;
  challenge.attempts = 0;
  challenge.sends += 1;
  challenge.lastSentAt = now;
  sendsByEmail.hit(challenge.email);
  return sendOtpEmail(challenge.email, code);
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function readCookie(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return '';
}

function cookieOptions(maxAge) {
  return { httpOnly: true, secure: IS_PROD, sameSite: 'strict', path: '/', maxAge };
}

function clearCookie(res, name) {
  res.clearCookie(name, { httpOnly: true, secure: IS_PROD, sameSite: 'strict', path: '/' });
}

function tooMany(res, waitMs, message) {
  const seconds = Math.ceil(waitMs / 1000);
  res.set('Retry-After', String(seconds));
  return res.status(429).json({
    error: message || `Too many attempts. Try again in ${Math.ceil(seconds / 60)} minute${seconds > 60 ? 's' : ''}.`,
    retryAfter: seconds
  });
}

function getPending(req) {
  const id = readCookie(req, PENDING_COOKIE);
  const challenge = id && pending.get(id);
  if (!challenge) return null;
  if (challenge.createdAt + PENDING_TTL_MS <= Date.now()) {
    pending.delete(id);
    return null;
  }
  return { id, challenge };
}

function getSession(req) {
  const id = readCookie(req, SESSION_COOKIE);
  const session = id && sessions.get(id);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(id);
    return null;
  }
  return { id, session };
}

function startSession(res, email) {
  const sid = newToken();
  sessions.set(sid, { email, expiresAt: Date.now() + SESSION_TTL_MS });
  res.cookie(SESSION_COOKIE, sid, cookieOptions(SESSION_TTL_MS));
  return sid;
}

function pendingPayload(challenge, delivery) {
  const now = Date.now();
  return {
    email: maskEmail(challenge.email),
    delivery,
    expiresIn: Math.max(0, Math.ceil((challenge.codeExpiresAt - now) / 1000)),
    resendIn: Math.max(0, Math.ceil((challenge.lastSentAt + OTP_RESEND_COOLDOWN_MS - now) / 1000))
  };
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const app = express();
app.disable('x-powered-by');
// Render reaches the app through Cloudflare and two internal hops, so the
// visitor is three addresses back in X-Forwarded-For. Trusting fewer puts
// every visitor behind one proxy IP and one shared rate limit; trusting
// more lets a client pick its own IP by sending the header.
app.set('trust proxy', 3);

app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
  });
  if (IS_PROD) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

app.get('/healthz', (req, res) => res.json({ ok: true }));

app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  if (req.method === 'GET' || req.method === 'HEAD') return next();

  // Cookies are SameSite=Strict already; this also refuses cross-site
  // requests from browsers that don't honour it.
  const origin = req.get('origin');
  if (origin) {
    let host = '';
    try {
      host = new URL(origin).host;
    } catch {}
    if (host !== req.get('host')) return res.status(403).json({ error: 'Cross-site request refused.' });
  }
  if (!req.is('application/json')) return res.status(415).json({ error: 'Expected JSON.' });
  next();
});

app.use(express.json({ limit: '10kb' }));

app.get('/api/auth/session', (req, res) => {
  const current = getSession(req);
  if (current) return res.json({ authenticated: true, user: { email: current.session.email } });
  const challenge = getPending(req);
  if (challenge) return res.json({ authenticated: false, pending: pendingPayload(challenge.challenge) });
  res.json({ authenticated: false });
});

app.post('/api/auth/login', async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!email || !password || password.length > 256) {
    return res.status(400).json({ error: 'Enter a valid email and your password.' });
  }

  const wait = Math.max(loginByIp.retryAfter(req.ip), failuresByEmail.retryAfter(email));
  if (wait) return tooMany(res, wait);
  loginByIp.hit(req.ip);

  // Any valid email with any password signs in, and skips the email code.
  if (OPEN_LOGIN) {
    const previous = readCookie(req, PENDING_COOKIE);
    if (previous) pending.delete(previous);
    clearCookie(res, PENDING_COOKIE);
    startSession(res, email);
    console.log(`[auth] open sign-in for ${maskEmail(email)} from ${req.ip}`);
    return res.json({ ok: true, authenticated: true, user: { email } });
  }

  const known = account && account.email === email;
  const matches = await bcrypt.compare(password, known ? account.passwordHash : DECOY_HASH);
  if (!known || !matches) {
    failuresByEmail.hit(email);
    console.log(`[auth] failed sign-in for ${maskEmail(email)} from ${req.ip}`);
    return res.status(401).json({ error: 'That email and password don’t match.' });
  }
  failuresByEmail.clear(email);

  const sendWait = sendsByEmail.retryAfter(email);
  if (sendWait) return tooMany(res, sendWait, 'Too many codes requested. Try again later.');

  const previous = readCookie(req, PENDING_COOKIE);
  if (previous) pending.delete(previous);

  const id = newToken();
  const challenge = { email, createdAt: Date.now(), sends: 0 };
  pending.set(id, challenge);

  let delivery;
  try {
    delivery = await issueCode(id, challenge);
  } catch (err) {
    pending.delete(id);
    console.error('[otp] send failed:', err.message);
    return res.status(502).json({ error: 'We couldn’t send your code. Try again in a moment.' });
  }

  res.cookie(PENDING_COOKIE, id, cookieOptions(PENDING_TTL_MS));
  res.json({ ok: true, pending: pendingPayload(challenge, delivery) });
});

app.post('/api/auth/resend', async (req, res) => {
  const current = getPending(req);
  if (!current) {
    clearCookie(res, PENDING_COOKIE);
    return res.status(401).json({ error: 'Your sign-in expired. Please start again.', restart: true });
  }
  const { id, challenge } = current;

  const cooldown = challenge.lastSentAt + OTP_RESEND_COOLDOWN_MS - Date.now();
  if (cooldown > 0) return tooMany(res, cooldown, 'Please wait before requesting another code.');
  if (challenge.sends >= OTP_MAX_SENDS) {
    return res.status(429).json({ error: 'That’s the last code we can send. Sign in again to get a new one.' });
  }
  const sendWait = sendsByEmail.retryAfter(challenge.email);
  if (sendWait) return tooMany(res, sendWait, 'Too many codes requested. Try again later.');

  try {
    const delivery = await issueCode(id, challenge);
    res.json({ ok: true, pending: pendingPayload(challenge, delivery) });
  } catch (err) {
    console.error('[otp] resend failed:', err.message);
    res.status(502).json({ error: 'We couldn’t send your code. Try again in a moment.' });
  }
});

app.post('/api/auth/verify', (req, res) => {
  const wait = verifyByIp.retryAfter(req.ip);
  if (wait) return tooMany(res, wait);

  const current = getPending(req);
  if (!current) {
    clearCookie(res, PENDING_COOKIE);
    return res.status(401).json({ error: 'Your sign-in expired. Please start again.', restart: true });
  }
  const { id, challenge } = current;

  const code = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Enter the 6-digit code.' });

  if (challenge.codeExpiresAt <= Date.now()) {
    return res.status(401).json({ error: 'That code has expired. Send a new one.', expired: true });
  }

  verifyByIp.hit(req.ip);
  challenge.attempts += 1;

  if (!crypto.timingSafeEqual(hashCode(id, code), challenge.codeHash)) {
    const left = OTP_MAX_ATTEMPTS - challenge.attempts;
    if (left <= 0) {
      pending.delete(id);
      clearCookie(res, PENDING_COOKIE);
      return res.status(401).json({ error: 'Too many incorrect codes. Please sign in again.', restart: true });
    }
    return res.status(401).json({ error: `That code isn’t right. ${left} ${left === 1 ? 'try' : 'tries'} left.` });
  }

  pending.delete(id);
  clearCookie(res, PENDING_COOKIE);
  startSession(res, challenge.email);
  res.json({ ok: true, user: { email: challenge.email } });
});

app.post('/api/auth/logout', (req, res) => {
  const current = getSession(req);
  if (current) sessions.delete(current.id);
  clearCookie(res, SESSION_COOKIE);
  res.json({ ok: true });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
    return res.status(400).json({ error: 'Malformed request.' });
  }
  console.error(err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

app.listen(PORT, () => {
  const mode = OPEN_LOGIN ? 'open — any valid email + password' : 'strict — account + email code';
  console.log(`[server] listening on :${PORT}${IS_PROD ? '' : ' (development)'} — auth mode: ${mode}`);
  if (!OPEN_LOGIN && !process.env.RESEND_API_KEY) {
    console.warn('[otp] RESEND_API_KEY is not set; codes will be written to this log instead of emailed.');
  }
});
