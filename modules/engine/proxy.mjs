import * as http from 'node:http'
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import redis from '../db_redis/models/index.mjs';

const distPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../static/dist/');
const privateKey = fs.readFileSync('../static/keys/ec_private.key', 'utf8');
const publicKey = fs.readFileSync('../static/keys/ec_public.key', 'utf8');
const CONFIG = { allowedIPs: [], blockedIPs: [], validApiKeys: ['API_KEY_FOR_FRONT', 'API_KEY_FOR_BACK', 'API_KEY_FOR_PROXY'] };

const generateId = (size) => crypto.randomBytes(size).toString('hex');
const generateToken = (payload) => jwt.sign(payload, privateKey, { algorithm: 'ES384', expiresIn: '24h', issuer: 'Cocoa' });
const verifyToken = (token) => jwt.verify(token, publicKey, { algorithms: ['ES384'], issuer: 'Cocoa' });
const generateFingerprint = (req) => crypto.createHash('sha256').update([req.headers['user-agent'], req.headers['accept-encoding'], req.headers['accept-language'], req.headers['origin'] || 'none', req.headers['referer'] || 'none', Intl.DateTimeFormat().resolvedOptions().timeZone].join('-')).digest('hex');
const parseJsonBody = async (req) => { let body = ''; for await (const chunk of req) body += chunk; try { return JSON.parse(body) } catch { return { error: 'Invalid JSON body' } } };
const handleRequestBody = async (req) => !req.headers['content-type'] ? null : req.headers['content-type'] === 'application/json' ? parseJsonBody(req) : { error: 'Unsupported content type' };
const parseCookies = (cookieHeader) => cookieHeader?.split(';').reduce((cookies, cookie) => (([name, value]) => ({ ...cookies, [name.trim()]: value }))(cookie.split('=')), {});

http.createServer(async (req, res) => {
  try {
    const { socket: { remoteAddress: clientIp }, body } = { socket: { remoteAddress: req.socket.remoteAddress }, body: await handleRequestBody(req) };
    const { clientType, prjName, preValidation } = body || {};
    const tokens = parseCookies(req.headers.cookie) || {};

    if (await redis.get(`blocked_ip:${clientIp}`) || /curl|wget|SELECT|INSERT|DROP|UNION/i.test(req.url)) { if (/curl|wget|SELECT|INSERT|DROP|UNION/i.test(req.url)) await redis.set(`blocked_ip:${clientIp}`, true, 'EX', 86400); return res.writeHead(403).end('Blocked') };
    if (body?.error || !body || (!clientType && !tokens.cat)) { return body?.error ? res.writeHead(422, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: body.error })) : req.socket.destroy() };

    if (body && tokens.cat) {
      try {
        try { var decoded = verifyToken(tokens.cat) } catch { return res.writeHead(401).end(JSON.stringify({ error: 'Invalid token' })) };
        const sessionData = JSON.parse(await redis.get(tokens.cs));
        if (!sessionData || sessionData.fingerprint !== generateFingerprint(req)) return res.writeHead(403).end(JSON.stringify({ error: 'Session mismatch' }));

        // const proxy = http.request({ hostname: '127.0.0.10', port: 5000, path: req.url, method: req.method, headers: { 'x-service': decoded.clientType } }, (proxyRes) => proxyRes.pipe(res.writeHead(proxyRes.statusCode, proxyRes.headers), { end: true }));
        // return req.pipe(proxy).on('error', () => res.writeHead(502).end('Bad gateway.'));

        // TODO: Доделать проксирование

        const proxy = http.request(
          {
            hostname: '127.0.0.10',
            port: 5000,
            path: req.url,
            method: req.method,
            headers: {
              ...req.headers, // Передаем все исходные заголовки
              'x-service': decoded.clientType // Дополнительный заголовок
            }
          },
          (proxyRes) => {
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            proxyRes.pipe(res, { end: true });
          }
        );
        
        req.pipe(proxy);

        proxy.on('error', (err) => {
          console.error('Proxy error:', err);
          res.writeHead(502).end('Bad gateway.');
        });

        // const response = await axios[req.method.toLowerCase()](`http://${proxyPriority[0]}:5000${req.url}`, req.body, { headers: { 'x-service': decoded.clientType } });
        // ['x-dora-request-id'].forEach((header) => response.headers[header] && res.header(header, response.headers[header]));

        // return res.writeHead(200).end(JSON.stringify('Тут'/*response.data*/));
      } catch (e) { return res.status(503).send({ error: e.message }) };
    }

    if (clientType) {
      try {
        if (!tokens.cat) {
          if (!clientType || !prjName || !CONFIG.validApiKeys.includes(preValidation)) return res.writeHead(428).end(JSON.stringify({ error: 'Unable to load resource' }));
          tokens.cs = generateId(16);
          tokens.cat = generateToken({ clientType, prjName });
          await redis.set(tokens.cs, JSON.stringify({ fingerprint: generateFingerprint(req), clientType: body.clientType, token: tokens.cat }), 'EX', 86400);
          return res.setHeader('Set-Cookie', [`cat=${tokens.cat}; HttpOnly; Secure; SameSite=Strict; Path=/;`, `cs=${tokens.cs}; HttpOnly; Secure; SameSite=Strict; Path=/;`]).end(JSON.stringify({ message: 'Successfully logged in' }));
        } return res.writeHead(421).end(JSON.stringify({ error: 'Non Actual Body' }));
      } catch (e) { return res.writeHead(503).end(JSON.stringify({ error: e.message })) };
    };
  } catch (e) { return res.writeHead(503).end(JSON.stringify(e.message)) }
}).listen(4430, () => console.log('Listening on port 4430'));