import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { db, migrate } from './lib/db.js';

migrate(`
CREATE TABLE IF NOT EXISTS admin_auth (id INTEGER PRIMARY KEY, username TEXT NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin_tokens (token TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS app_settings (id INTEGER PRIMARY KEY, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS activity (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, created_at TEXT NOT NULL);
`);
const initial = db.prepare('SELECT id FROM admin_auth WHERE id = 1').get();
if (!initial) {
  const salt = randomBytes(16).toString('hex');
  db.prepare('INSERT INTO admin_auth (id, username, salt, hash) VALUES (1, ?, ?, ?)').run('Habib', salt, scryptSync('Habib16280', salt, 64).toString('hex'));
}
if (!db.prepare('SELECT id FROM app_settings WHERE id = 1').get()) {
  db.prepare('INSERT INTO app_settings (id, payload) VALUES (1, ?)').run(JSON.stringify({ name: 'Habib Super App', accent: '#6958df', background: '', logo: '', disabled: [] }));
}

type AuthRow = { username: string; salt: string; hash: string };
const loginAttempts = new Map<string, { count: number; until: number }>();
function json(res: ServerResponse, status: number, data: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}
async function body(req: IncomingMessage) {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 100_000) throw new Error('Request too large');
  }
  return JSON.parse(raw || '{}') as Record<string, unknown>;
}
function authorized(req: IncomingMessage) {
  const token = req.headers['x-admin-token'];
  if (typeof token !== 'string') return false;
  const found = db.prepare('SELECT 1 FROM admin_tokens WHERE token = ? AND expires > ?').get(token, Date.now());
  return !!found;
}
function log(action: string) { db.prepare('INSERT INTO activity (action, created_at) VALUES (?, ?)').run(action, new Date().toISOString()); }
function settings() { return JSON.parse((db.prepare('SELECT payload FROM app_settings WHERE id = 1').get() as { payload: string }).payload); }

createServer(async (req, res) => {
  const path = new URL(req.url || '/', 'http://localhost').pathname;
  try {
    if (path === '/api/config' && req.method === 'GET') return json(res, 200, settings());
    if (path === '/api/admin/login' && req.method === 'POST') {
      const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
      const attempt = loginAttempts.get(ip);
      if (attempt && attempt.count >= 5 && attempt.until > Date.now()) return json(res, 429, { error: 'تلاش‌های زیادی انجام شده؛ ۱۵ دقیقه بعد دوباره تلاش کنید.' });
      const input = await body(req);
      const row = db.prepare('SELECT username, salt, hash FROM admin_auth WHERE id = 1').get() as AuthRow;
      const candidate = scryptSync(String(input.password || ''), row.salt, 64);
      const correct = String(input.username || '') === row.username && timingSafeEqual(candidate, Buffer.from(row.hash, 'hex'));
      if (!correct) {
        loginAttempts.set(ip, { count: attempt && attempt.until > Date.now() ? attempt.count + 1 : 1, until: Date.now() + 15 * 60000 });
        return json(res, 401, { error: 'اطلاعات ورود درست نیست.' });
      }
      loginAttempts.delete(ip);
      const token = randomBytes(32).toString('base64url');
      db.prepare('INSERT INTO admin_tokens (token, expires) VALUES (?, ?)').run(token, Date.now() + 7 * 86400000);
      log('ورود مدیر');
      return json(res, 200, { token });
    }
    if (path.startsWith('/api/admin/')) {
      if (!authorized(req)) return json(res, 401, { error: 'نشست مدیریت معتبر نیست.' });
      if (path === '/api/admin/state' && req.method === 'GET') {
        return json(res, 200, { settings: settings(), activities: db.prepare('SELECT action, created_at FROM activity ORDER BY id DESC LIMIT 30').all() });
      }
      if (path === '/api/admin/config' && req.method === 'PUT') {
        const input = await body(req);
        const current = settings();
        const next = {
          name: typeof input.name === 'string' ? input.name.trim().slice(0, 60) || current.name : current.name,
          accent: typeof input.accent === 'string' && /^#[0-9a-fA-F]{6}$/.test(input.accent) ? input.accent : current.accent,
          background: typeof input.background === 'string' ? input.background.slice(0, 500) : current.background,
          logo: typeof input.logo === 'string' ? input.logo.slice(0, 500) : current.logo,
          disabled: Array.isArray(input.disabled) ? input.disabled.filter((x): x is string => typeof x === 'string').slice(0, 100) : current.disabled,
        };
        db.prepare('UPDATE app_settings SET payload = ? WHERE id = 1').run(JSON.stringify(next));
        log('ویرایش تنظیمات برنامه');
        return json(res, 200, next);
      }
      if (path === '/api/admin/password' && req.method === 'POST') {
        const input = await body(req);
        const row = db.prepare('SELECT username, salt, hash FROM admin_auth WHERE id = 1').get() as AuthRow;
        const old = scryptSync(String(input.oldPassword || ''), row.salt, 64);
        if (!timingSafeEqual(old, Buffer.from(row.hash, 'hex'))) return json(res, 400, { error: 'رمز فعلی درست نیست.' });
        const nextPassword = String(input.newPassword || '');
        if (nextPassword.length < 8) return json(res, 400, { error: 'رمز جدید باید دست‌کم ۸ نویسه باشد.' });
        const salt = randomBytes(16).toString('hex');
        db.prepare('UPDATE admin_auth SET salt = ?, hash = ? WHERE id = 1').run(salt, scryptSync(nextPassword, salt, 64).toString('hex'));
        db.prepare('DELETE FROM admin_tokens').run();
        log('تغییر رمز مدیریت');
        return json(res, 200, { ok: true });
      }
      if (path === '/api/admin/logout' && req.method === 'POST') {
        const token = req.headers['x-admin-token'];
        if (typeof token === 'string') db.prepare('DELETE FROM admin_tokens WHERE token = ?').run(token);
        return json(res, 200, { ok: true });
      }
    }
    return json(res, 404, { error: 'یافت نشد.' });
  } catch (error) {
    console.error('Request failed', req.method, path, error);
    return json(res, 500, { error: 'درخواست انجام نشد. دوباره تلاش کنید.' });
  }
}).listen(Number(process.env.PORT || 3000));
