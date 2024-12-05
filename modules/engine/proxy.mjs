import * as http from 'node:http'
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import redis from '../db_redis/models/index.mjs';

const distPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../static/dist/');
const privateKey = fs.readFileSync('../static/keys/ec_private.pem', 'utf8');
const publicKey = fs.readFileSync('../static/keys/ec_public.pem', 'utf8');
const CONFIG = { allowedIPs: [], blockedIPs: [], key: "1dmscnj823?/dsad_02sdawq-ds", frontends: [], backends: [] };

const generateId = (size) => crypto.randomBytes(size).toString('hex');
const generateToken = (payload) => jwt.sign(payload, privateKey, { algorithm: 'ES512', expiresIn: '24h', issuer: 'Cocoa' });
const verifyToken = (token) => jwt.verify(token, publicKey, { algorithms: ['ES512'], issuer: 'Cocoa' });
const validateIP = (ip) => /^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$/.test(ip);
const generateFingerprint = (req) => crypto.createHash('sha256').update([req.headers['user-agent'], req.headers['accept-encoding'], req.headers['accept-language'], req.headers['origin'] || 'none', req.headers['referer'] || 'none', Intl.DateTimeFormat().resolvedOptions().timeZone].join('-')).digest('hex');
const parseJsonBody = async (req) => { let body = ''; for await (const chunk of req) body += chunk; try { return JSON.parse(body) } catch { return { error: 'Invalid JSON body' } } };
const handleRequestBody = async (req) => !req.headers['content-type'] ? null : req.headers['content-type'] === 'application/json' ? parseJsonBody(req) : { error: 'Unsupported content type' };
const parseCookies = (cookieHeader) => cookieHeader?.split(';').reduce((cookies, cookie) => (([name, value]) => ({ ...cookies, [name.trim()]: value }))(cookie.split('=')), {});

http.createServer(async (req, res) => {
  try {
    const authToken = req.headers;
    console.log(authToken)

    const { socket: { remoteAddress: clientIp }, body } = { socket: { remoteAddress: req.socket.remoteAddress }, body: await handleRequestBody(req) };
    const request = body ?? {}, tokens = parseCookies(req.headers?.cookie ?? '');

    if (await redis.get(`blocked_ip:${clientIp}`) || /curl|wget|SELECT|INSERT|DROP|UNION/i.test(req.url)) { if (/curl|wget|SELECT|INSERT|DROP|UNION/i.test(req.url)) await redis.set(`blocked_ip:${clientIp}`, true, 'EX', 86400); return res.writeHead(403).end('Unable to load resource') };
    if (body?.error || !body || (!clientType && !tokens._cat)) { return body?.error ? res.writeHead(422, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: body.error })) : req.socket.destroy() };
    res.setHeader('server', 'Cocoa').setHeader('access-control-allow-headers', 'Origin, X-Requested-With, Content-Type, Accept').setHeader('strict-transport-security', 'max-age=31536000; includeSubDomains; preload').setHeader('x-content-type-options', 'nosniff').setHeader('x-frame-options', 'DENY').setHeader('x-xss-protection', '1; mode=block').setHeader('c-ray', generateId(8));

    if (body && tokens._cat) try {
      const decoded = verifyToken(tokens._cat), sessionData = JSON.parse(await redis.get(tokens._cs));
      if (!sessionData || sessionData.fingerprint !== generateFingerprint(req)) return res.writeHead(403).end(JSON.stringify({ error: 'Session mismatch' }));

      const proxy = http.request({ hostname: CONFIG.backends[0] || '127.0.0.10', port: 5000, path: req.url, method: req.method, headers: { 'host': `${CONFIG.backends[0]}:5000`, 'x-service': decoded.clientType, 'content-type': 'application/json' } }, (proxyRes) => { res.writeHead(proxyRes.statusCode, proxyRes.headers); proxyRes.pipe(res, { end: true }) });
      proxy.on('error', () => res.writeHead(502).end('Bad gateway.'));
      proxy.write(JSON.stringify(body));
      return proxy.end();
    } catch (e) { return res.writeHead(503).end(JSON.stringify({ error: e.message })) };

    if (clientType) try {
      if (tokens._cat) return res.writeHead(421).end(JSON.stringify({ error: 'Non Actual Body' }));
      if (!clientType || !prjName || !CONFIG.validApiKeys.includes(preValidation) || !destinationIp) return res.writeHead(428).end(JSON.stringify({ error: 'Unable to load resource' }));

      if (clientType === 'backend') {
        if (!validateIP(destinationIp)) return res.writeHead(428).end(JSON.stringify({ error: 'IP is incorrect' }));
        if (!CONFIG.backends.includes(destinationIp)) CONFIG.backends.push(destinationIp);
      }

      tokens._cs = generateId(16), tokens._cat = generateToken({ clientType, prjName });
      await redis.set(tokens._cs, JSON.stringify({ fingerprint: generateFingerprint(req), clientType, token: tokens._cat }), 'EX', 86400);
      res.setHeader('Set-Cookie', [`_cat=${tokens._cat}; HttpOnly; Secure; SameSite=Strict; Path=/;`,`_cs=${tokens._cs}; HttpOnly; Secure; SameSite=Strict; Path=/;`]).end(JSON.stringify({ message: 'Successfully logged in' }));
    } catch (e) { res.writeHead(503).end(JSON.stringify({ error: e.message })) }

  } catch (e) { return res.writeHead(503).end(JSON.stringify(e.message)) }
}).listen(4430, () => console.log('Listening on port 4430'));