import express from 'express';
import dotenv from 'dotenv';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Resend } from 'resend';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const OTP_EMAIL = process.env.OTP_EMAIL;
const RESEND_FROM = process.env.RESEND_FROM || 'Attendance Tracker <onboarding@resend.dev>';
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
// Local development: print the OTP in the terminal so email delivery is not
// required just to test the login flow. Render is marked as production below.
const OTP_DEBUG = !IS_PRODUCTION;

if (!RESEND_API_KEY || !SESSION_SECRET || !OTP_EMAIL) {
  console.warn('\nMissing RESEND_API_KEY, SESSION_SECRET or OTP_EMAIL. Create a .env file before using OTP login.\n');
}
if (SESSION_SECRET && SESSION_SECRET.length < 32) {
  console.warn('\nSESSION_SECRET is short. Use a random 64-character value (see README).\n');
}

const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;
const challenges = new Map();
const sessions = new Map();
const requestCooldown = new Map();

app.disable('x-powered-by');
app.set('trust proxy', 1); // correct client IP + secure cookies behind Render/Railway/Nginx etc.
app.use(express.json({ limit: '20kb' }));

// Serve ONLY the three public front-end files. (Previously the whole project
// folder was public, which exposed server.js, package.json, README, etc.)
const PUBLIC_FILES = { '/': 'index.html', '/index.html': 'index.html', '/script.js': 'script.js', '/style.css': 'style.css' };
app.get(Object.keys(PUBLIC_FILES), (req, res) => {
  res.sendFile(path.join(__dirname, PUBLIC_FILES[req.path]));
});

// Render health check endpoint.
app.get('/health', (req, res) => {
  res.status(200).json({ ok: true });
});

function cleanText(value, max) {
  return String(value ?? '').trim().replace(/[<>]/g, '').slice(0, max);
}

function hashOtp(otp) {
  return crypto.createHash('sha256').update(otp).digest('hex');
}

function newToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function signSession(sessionId) {
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(sessionId).digest('hex');
  return `${sessionId}.${signature}`;
}

function verifySessionToken(token) {
  if (!token || !SESSION_SECRET) return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const sessionId = token.slice(0, dot);
  const signature = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(sessionId).digest('hex');
  if (signature.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  return sessionId;
}

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  const pair = raw.split(';').map(x => x.trim()).find(x => x.startsWith(`${name}=`));
  return pair ? decodeURIComponent(pair.slice(name.length + 1)) : '';
}

function setSessionCookie(res, token) {
  // Render terminates HTTPS at its proxy and forwards the request to Node over HTTP.
  // Use the forwarded protocol so the session cookie is Secure in production.
  const forwardedProto = String(res.req?.headers?.['x-forwarded-proto'] || '').split(',')[0].trim();
  const secure = res.req?.secure || forwardedProto === 'https' || process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `attendance_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=86400${secure}`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'attendance_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
}

function authenticatedUser(req) {
  const token = getCookie(req, 'attendance_session');
  const sessionId = verifySessionToken(token);
  if (!sessionId) return null;
  const session = sessions.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(sessionId);
    return null;
  }
  return session;
}

function cleanup() {
  const now = Date.now();
  for (const [id, c] of challenges) if (c.expiresAt < now) challenges.delete(id);
  for (const [id, s] of sessions) if (s.expiresAt < now) sessions.delete(id);
  for (const [ip, t] of requestCooldown) if (t + 30_000 < now) requestCooldown.delete(ip);
}
setInterval(cleanup, 30_000).unref();

app.post('/api/send-otp', async (req, res) => {
  if (!resend || !SESSION_SECRET || !OTP_EMAIL) return res.status(500).json({ error: 'Server is not configured. Add RESEND_API_KEY, SESSION_SECRET and OTP_EMAIL to .env and restart.' });

  const ip = req.ip || 'unknown';
  const lastRequest = requestCooldown.get(ip) || 0;
  if (Date.now() - lastRequest < 30_000) {
    return res.status(429).json({ error: 'Please wait 30 seconds before requesting another OTP.' });
  }

  const name = cleanText(req.body?.name, 80);
  const rollNumber = cleanText(req.body?.rollNumber, 40);
  if (name.length < 2 || rollNumber.length < 1) {
    return res.status(400).json({ error: 'Enter a valid name and roll number.' });
  }

  const otp = String(crypto.randomInt(100000, 1000000));
  const challengeId = newToken(24);

  if (OTP_DEBUG) {
    console.log(`\n[LOCAL OTP DEBUG] ${name} (${rollNumber}) -> ${otp}\n`);
  }
  challenges.set(challengeId, {
    otpHash: hashOtp(otp),
    name,
    rollNumber,
    expiresAt: Date.now() + 60_000,
    attempts: 0
  });
  requestCooldown.set(ip, Date.now());

  try {
    const { error } = await resend.emails.send({
      from: RESEND_FROM,
      to: [OTP_EMAIL],
      subject: `Attendance Tracker Login - ${name} - Roll ${rollNumber}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:28px;color:#172033;background:#ffffff">
          <h2 style="margin:0 0 18px;color:#111827">Attendance Tracker</h2>
          <p style="margin:0 0 18px">A login verification request was received.</p>

          <div style="border:1px solid #e5e7eb;border-radius:12px;padding:18px;margin:0 0 20px;background:#f9fafb">
            <p style="margin:0 0 10px"><strong>Student Name:</strong> ${escapeHtml(name)}</p>
            <p style="margin:0"><strong>Roll Number:</strong> ${escapeHtml(rollNumber)}</p>
          </div>

          <p style="margin:0 0 8px">Your 6-digit verification OTP is:</p>
          <div style="font-size:34px;font-weight:800;letter-spacing:8px;padding:16px 0;color:#059669">${otp}</div>

          <p style="color:#667085;margin:12px 0 0">This OTP is valid for <strong>1 minute</strong>.</p>
          <p style="color:#667085;margin:8px 0 0">If you did not request this login, you can ignore this email.</p>
        </div>`
    });

    if (error) {
      if (OTP_DEBUG) {
        console.error('[Resend API Error - LOCAL DEBUG] ', error);
        console.log(`[LOCAL OTP DEBUG] Email delivery failed, but you can test with OTP: ${otp}`);
        return res.json({ success: true, challengeId, expiresIn: 60, message: 'OTP generated locally. Check the VS Code terminal.' });
      }
      challenges.delete(challengeId);
      requestCooldown.delete(ip);
      return res.status(502).json({ error: error.message || 'Resend could not send the OTP email.' });
    }

    if (OTP_DEBUG) console.log('[LOCAL OTP DEBUG] Email accepted by Resend. Use the OTP shown above.');
    return res.json({ success: true, challengeId, expiresIn: 60, message: OTP_DEBUG ? 'OTP generated. Check the VS Code terminal.' : 'OTP sent.' });
  } catch (err) {
    if (OTP_DEBUG) {
      console.error('[Resend error - LOCAL DEBUG]', err);
      console.log(`[LOCAL OTP DEBUG] Email delivery failed, but you can test with OTP: ${otp}`);
      return res.json({ success: true, challengeId, expiresIn: 60, message: 'OTP generated locally. Check the VS Code terminal.' });
    }
    challenges.delete(challengeId);
    requestCooldown.delete(ip);
    console.error('Resend error:', err);
    return res.status(502).json({ error: 'Unable to send the OTP email. Check your Resend sender/API configuration.' });
  }
});

app.post('/api/verify-otp', (req, res) => {
  const challengeId = cleanText(req.body?.challengeId, 100);
  const otp = cleanText(req.body?.otp, 6);
  const challenge = challenges.get(challengeId);

  if (!challenge) return res.status(400).json({ error: 'OTP request not found. Request a new OTP.' });
  if (challenge.expiresAt < Date.now()) {
    challenges.delete(challengeId);
    return res.status(400).json({ error: 'OTP expired. Request a new OTP.' });
  }
  if (!/^\d{6}$/.test(otp)) return res.status(400).json({ error: 'Enter the 6-digit OTP.' });

  challenge.attempts += 1;
  if (challenge.attempts > 5) {
    challenges.delete(challengeId);
    return res.status(429).json({ error: 'Too many incorrect attempts. Request a new OTP.' });
  }

  const supplied = Buffer.from(hashOtp(otp));
  const expected = Buffer.from(challenge.otpHash);
  if (!crypto.timingSafeEqual(supplied, expected)) {
    return res.status(401).json({ error: `Incorrect OTP. ${5 - challenge.attempts} attempts remaining.` });
  }

  challenges.delete(challengeId);
  const sessionId = newToken(32);
  sessions.set(sessionId, {
    name: challenge.name,
    rollNumber: challenge.rollNumber,
    expiresAt: Date.now() + 24 * 60 * 60 * 1000
  });
  setSessionCookie(res, signSession(sessionId));

  return res.json({ success: true, user: { name: challenge.name, rollNumber: challenge.rollNumber } });
});

app.get('/api/session', (req, res) => {
  const user = authenticatedUser(req);
  if (!user) return res.status(401).json({ authenticated: false });
  return res.json({ authenticated: true, user: { name: user.name, rollNumber: user.rollNumber } });
});

app.post('/api/logout', (req, res) => {
  const token = getCookie(req, 'attendance_session');
  const sessionId = verifySessionToken(token);
  if (sessionId) sessions.delete(sessionId);
  clearSessionCookie(res);
  res.json({ success: true });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

// Works on both Express 4 and 5 (the '*' route string crashes on 5, '/{*splat}' fails on 4)
app.use((req, res, next) => {
  if (req.method !== 'GET') return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Bad JSON bodies etc. -> JSON error instead of an HTML stack trace
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = err.status || 500;
  res.status(status).json({ error: status === 400 ? 'Invalid request.' : 'Server error.' });
});

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' }[c]));
}

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Attendance Tracker running on port ${PORT}`);
});
server.on('error', err => {
  if (err.code === 'EADDRINUSE') console.error(`\nPort ${PORT} is already in use. Close the other app or change PORT in .env.\n`);
  else console.error(err);
  process.exit(1);
});
