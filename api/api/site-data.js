import * as blob from '@vercel/blob';
import { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const DATA_BLOB_PATH = 'bravamar/site-data.json';
const AUTH_BLOB_PATH = 'bravamar/auth.json';
const MAX_BODY_BYTES = 5 * 1024 * 1024;

const ALLOWED_USERS = new Set([
  'admin',
  'bravamar',
  'nicolas',
  'gustavo',
  'nicolas@bravamarubatuba.com.br',
  'bravamar.ubatuba@gmail.com'
]);

function safeEqual(a, b) {
  const ha = createHash('sha256').update(String(a || '')).digest();
  const hb = createHash('sha256').update(String(b || '')).digest();
  return timingSafeEqual(ha, hb);
}

function sendJson(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.end(JSON.stringify(payload));
}

async function readRawBody(req) {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
    return req.body;
  }
  if (Buffer.isBuffer(req.body)) {
    return JSON.parse(req.body.toString('utf8'));
  }
  if (typeof req.body === 'string') {
    return JSON.parse(req.body);
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      const err = new Error('Payload too large');
      err.status = 413;
      throw err;
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}

async function readDefaultData() {
  try {
    const filePath = path.join(process.cwd(), 'data', 'site-data.json');
    const txt = await fs.readFile(filePath, 'utf8');
    return JSON.parse(txt);
  } catch {
    return null;
  }
}

async function readBlobJson(pathname) {
  if (!process.env.BLOB_READ_WRITE_TOKEN) return null;
  try {
    const { blobs } = await blob.list({ prefix: pathname, limit: 5 });
    const match = blobs.find((b) => b.pathname === pathname);
    if (!match) return null;
    const r = await fetch(`${match.url}?t=${Date.now()}`, { cache: 'no-store' });
    if (!r.ok) return null;
    return await r.json();
  } catch (e) {
    console.error('readBlobJson error:', e?.message);
    return null;
  }
}

async function writeBlobJson(pathname, dataObj) {
  return await blob.put(pathname, JSON.stringify(dataObj, null, 2), {
    access: 'public',
    addRandomSuffix: false,
    allowOverwrite: true,
    contentType: 'application/json',
    cacheControlMaxAge: 0
  });
}

async function getActivePassword() {
  const envPass = process.env.ADMIN_PASSWORD || 'bravamar2026';
  const customAuth = await readBlobJson(AUTH_BLOB_PATH);
  if (customAuth && customAuth.passwordHash) {
    return { type: 'hash', hash: customAuth.passwordHash, envPass };
  }
  return { type: 'plain', plain: envPass };
}

async function verifyCredentials(user, pass) {
  const normUser = String(user || '').trim().toLowerCase();
  if (!ALLOWED_USERS.has(normUser)) return false;

  const authInfo = await getActivePassword();
  const passStr = String(pass || '').trim();
  const envPass = process.env.ADMIN_PASSWORD || 'bravamar2026';

  // Always accept default env password as recovery fallback OR custom password if changed
  if (safeEqual(passStr, envPass)) return true;

  if (authInfo.type === 'hash') {
    const candidateHash = createHash('sha256').update(passStr).digest('hex');
    return safeEqual(candidateHash, authInfo.hash);
  }
  return false;
}

export default async function handler(req, res) {
  try {
    if (req.method === 'GET') {
      const liveData = await readBlobJson(DATA_BLOB_PATH);
      if (liveData && typeof liveData === 'object') {
        return sendJson(res, 200, { ok: true, source: 'blob', data: liveData });
      }
      const fallback = await readDefaultData();
      return sendJson(res, 200, { ok: true, source: 'default', data: fallback || {} });
    }

    if (req.method !== 'POST') {
      res.setHeader('Allow', 'GET, POST');
      return sendJson(res, 405, { ok: false, error: 'Método não permitido' });
    }

    const body = await readRawBody(req);
    const action = body.action || 'save';
    const user = req.headers['x-admin-user'] || body.user || '';
    const pass = req.headers['x-admin-pass'] || body.password || '';

    const authorized = await verifyCredentials(user, pass);
    if (!authorized) {
      return sendJson(res, 401, { ok: false, error: 'Usuário ou senha inválidos.' });
    }

    if (action === 'login') {
      const liveData = (await readBlobJson(DATA_BLOB_PATH)) || (await readDefaultData()) || {};
      return sendJson(res, 200, { ok: true, user: String(user).trim(), data: liveData });
    }

    if (action === 'upload') {
      const dataUrl = String(body.dataUrl || '');
      const m = dataUrl.match(/^data:(image\/(?:webp|jpeg|png));base64,([A-Za-z0-9+/=]+)$/);
      if (!m) {
        return sendJson(res, 400, { ok: false, error: 'Formato de imagem inválido. Use WebP, JPEG ou PNG.' });
      }
      const contentType = m[1];
      const ext = contentType === 'image/webp' ? 'webp' : contentType === 'image/png' ? 'png' : 'jpg';
      const buf = Buffer.from(m[2], 'base64');
      if (buf.length > 4 * 1024 * 1024) {
        return sendJson(res, 413, { ok: false, error: 'Imagem muito grande (máx 4MB).' });
      }
      const cleanName = String(body.filename || 'foto').replace(/[^a-z0-9-_]/gi, '-').toLowerCase().slice(0, 40) || 'foto';
      const uploaded = await blob.put(`bravamar/uploads/${cleanName}-${Date.now()}.${ext}`, buf, {
        access: 'public',
        addRandomSuffix: true,
        contentType,
        cacheControlMaxAge: 31536000
      });
      return sendJson(res, 200, { ok: true, url: uploaded.url });
    }

    if (action === 'change-password') {
      const newPass = String(body.newPassword || '').trim();
      if (newPass.length < 4) {
        return sendJson(res, 400, { ok: false, error: 'A nova senha deve ter pelo menos 4 caracteres.' });
      }
      const passwordHash = createHash('sha256').update(newPass).digest('hex');
      await writeBlobJson(AUTH_BLOB_PATH, {
        passwordHash,
        updatedAt: new Date().toISOString(),
        updatedBy: String(user).trim()
      });
      return sendJson(res, 200, { ok: true, message: 'Senha atualizada com sucesso!' });
    }

    if (action === 'reset-default') {
      const fallback = await readDefaultData();
      if (!fallback) {
        return sendJson(res, 500, { ok: false, error: 'Dados padrão não encontrados.' });
      }
      fallback.updatedAt = new Date().toISOString();
      await writeBlobJson(DATA_BLOB_PATH, fallback);
      return sendJson(res, 200, { ok: true, data: fallback });
    }

    if (action === 'save') {
      const newData = body.data;
      if (!newData || typeof newData !== 'object') {
        return sendJson(res, 400, { ok: false, error: 'Dados do site ausentes ou inválidos.' });
      }
      newData.updatedAt = new Date().toISOString();
      await writeBlobJson(DATA_BLOB_PATH, newData);
      return sendJson(res, 200, { ok: true, updatedAt: newData.updatedAt, data: newData });
    }

    return sendJson(res, 400, { ok: false, error: 'Ação desconhecida.' });
  } catch (err) {
    console.error('API site-data error:', err);
    return sendJson(res, err.status || 500, { ok: false, error: err.message || 'Erro interno no servidor.' });
  }
}
