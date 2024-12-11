import * as https from 'node:https';
import * as http from 'node:http'; // TODO: убрать в будущем и проксировать на https бэки
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import redis from '../db_redis/models/index.mjs';

const jwtOptions = { key: fs.readFileSync('../static/keys/jwt_key/ec_private.pem', 'utf8'), cert: fs.readFileSync('../static/keys/jwt_key/ec_public.pem', 'utf8') }
const httpsOptions = { key: fs.readFileSync('../static/keys/https_key/private.key'), cert: fs.readFileSync('../static/keys/https_key/certificate.crt') };
const CONFIG = { allowedIPs: [], blockedIPs: [], frontends: [], backends: [], key: "1dmscnj823?/dsad_02sdawq-ds" };

const generateId = (size) => crypto.randomBytes(size).toString('hex');
const generateToken = (payload) => jwt.sign(payload, jwtOptions.key, { algorithm: 'ES512', expiresIn: '24h', issuer: 'Cocoa' });
const verifyToken = (token) => jwt.verify(token, jwtOptions.cert, { algorithms: ['ES512'], issuer: 'Cocoa' });
const validateIP = (ip) => /^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$/.test(ip);
const rateLimit = async (ip) => { const key = `rate_limit:${ip}`; const current = await redis.incr(key); if (current === 1) await redis.expire(key, 30); return current > 30 };
const generateFingerprint = (req) => crypto.createHash('sha256').update([req.headers['user-agent'], req.headers['accept-encoding'], req.headers['accept-language'], req.headers['origin'] || 'none', req.headers['referer'] || 'none', Intl.DateTimeFormat().resolvedOptions().timeZone].join('-')).digest('hex');
const parseJsonBody = async (req) => { let body = ''; for await (const chunk of req) body += chunk; try { return JSON.parse(body) } catch { return { error: 'Invalid JSON body' } } };
const handleRequestBody = async (req) => !req.headers['content-type'] ? null : req.headers['content-type'] === 'application/json' ? parseJsonBody(req) : { error: 'Unsupported content type' };

const validateRequestBody = (body) => {
  // if (typeof body !== 'object') return { error: 'Invalid request body' };
  return null;
};

const serveStatic = (res, buildPath, reqUrl, reqHeaders) => {
  const filePath = path.join(buildPath, reqUrl === '/' ? 'index.html' : reqUrl);

  try {
    if (fs.existsSync(filePath)) {
      const data = fs.readFileSync(filePath);
      const etag = `"${crypto.createHash('md5').update(data).digest('hex')}"`;
      if (reqHeaders['if-none-match'] === etag) return res.writeHead(304).end();
      const ext = path.extname(filePath).toLowerCase();
      const contentType = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' }[ext] || 'application/octet-stream';

      return res.writeHead(200, { 'cache-control': 'public, max-age=86400', 'etag': etag, 'content-type': contentType }).end(data);
    }

    const indexFilePath = path.join(buildPath, 'index.html');
    if (fs.existsSync(indexFilePath)) {
      const data = fs.readFileSync(indexFilePath);
      const etag = `"${crypto.createHash('md5').update(data).digest('hex')}"`;

      return res.writeHead(200, { 'cache-control': 'public, max-age=86400', 'etag': etag, 'content-type': 'text/html' }).end(data);
    };

    return res.writeHead(404, { 'content-type': 'text/plain' }).end('404: File Not Found');
  } catch (e) { return res.writeHead(503, { 'content-type': 'text/plain' }).end(`503: Service Unavailable\n${e}`) };
};

const parseCookies = (cookieHeader) => cookieHeader?.split(';').reduce((cookies, cookie) => (([name, value]) => ({ ...cookies, [name.trim()]: value }))(cookie.split('=')), {});
const saveClientsToRedis = async (manageRequest, prjName, destinationIp, destinationPort) => { if (!manageRequest || !destinationIp) { throw new Error('manageRequest and destinationIp are required') } await redis.set(`${manageRequest}:${destinationIp}`, JSON.stringify({ prjName: prjName || 'Master', destinationPort: destinationPort || '' }), 'EX', 86400) };
const getAllFromClientsGroup = async (manageRequest) => { const keys = await redis.keys(`${manageRequest}:*`); if (!keys.length) return {}; const entries = await Promise.all(keys.map(async (key) => [key.split(':')[1], JSON.parse(await redis.get(key))])); return Object.fromEntries(entries) };

https.createServer(httpsOptions, async (req, res) => {
  try {
    const { socket: { remoteAddress: clientIp }, body } = { socket: { remoteAddress: req.socket.remoteAddress }, body: await handleRequestBody(req) };
    if (await rateLimit(clientIp)) return res.writeHead(429).end('429: Too Many Requests');

    const validationError = validateRequestBody(body);
    if (validationError) return res.writeHead(400).end(`400: ${JSON.stringify(validationError)}`);

    const manageRequest = body?.request ?? {}, tokens = parseCookies(req.headers?.cookie ?? '');
    if (await redis.get(`blocked_ip:${clientIp}`) || /curl|wget|SELECT|INSERT|DROP|UNION/i.test(req.url)) { if (/curl|wget|SELECT|INSERT|DROP|UNION/i.test(req.url))  await redis.set(`blocked_ip:${clientIp}`, true, 'EX', 86400); const blockedFilePath = path.join(path.dirname(fileURLToPath(import.meta.url)), '../static/banhammer/index.html'); return serveStatic(res, path.dirname(blockedFilePath), req.url, req.headers) };

    if (body?.error) { return body?.error ? res.writeHead(422).end(JSON.stringify(`400: ${body.error}`)) : req.socket.destroy() }; // TODO: перепилить эту часть
    res.setHeader('server', 'Cocoa').setHeader('access-control-allow-headers', 'Origin, X-Requested-With, Content-Type, Accept').setHeader('strict-transport-security', 'max-age=31536000; includeSubDomains; preload').setHeader('x-content-type-options', 'nosniff').setHeader('x-frame-options', 'DENY').setHeader('x-xss-protection', '1; mode=block').setHeader('c-ray', generateId(8));

    if (!CONFIG.backends.length) for (const group of ['backend', 'frontend']) { const allItems = await getAllFromClientsGroup(group); const entries = Object.entries(allItems).map(([ip, { prjName, destinationPort }]) => ({ destinationIp: ip, prjName, destinationPort })); CONFIG[`${group}s`].push(...entries) };
   
    const authToken = req.headers['x-proxy-token'];
    let prjName, destinationIp, destinationPort;
    if (authToken) { try { ({ prjName, destinationIp, destinationPort } = jwt.verify(authToken, CONFIG.key)) } catch { return res.writeHead(401).end('401: Invalid token') } };

    if (req.method === 'GET') {
      const builds = { /*'127.0.0.1:4430'*/'one.com': path.join(path.dirname(fileURLToPath(import.meta.url)), '../static/banhammer'), 'another.com': path.join(path.dirname(fileURLToPath(import.meta.url)), 'dist-another'), };
      const destinationHost = req.headers?.host;
      const buildPath = builds[destinationHost];
      if (!buildPath) { return res.writeHead(404, { 'content-type': 'text/plain' }).end('404: Not Found') };

      return serveStatic(res, buildPath, req.url, req.headers);
    }

    if (manageRequest && destinationIp) {
      if (!validateIP(destinationIp)) return res.writeHead(400).end(JSON.stringify({ error: 'Wrong Data' }));
      if (manageRequest === 'backend' && !CONFIG.backends.some(backend => backend.destinationIp === destinationIp)) { CONFIG.backends.push({ destinationIp, prjName, destinationPort }); await saveClientsToRedis(manageRequest, prjName, destinationIp, destinationPort) } 
      return res.writeHead(201).end(`201: Successfully registered: IP ${destinationIp} added, ${manageRequest}:${prjName}`);
    }

    if (req.method === 'POST' && body) try {
      const proxy = http.request({ hostname: CONFIG?.backends[0]?.destinationIp || '127.0.0.10', port: CONFIG?.backends[0]?.destinationPort, path: req.url, method: req.method, headers: { 'host': `${CONFIG?.backends[0]?.destinationIp}:${CONFIG?.backends[0]?.destinationPort}`, 'x-service': `Test service`, 'content-type': 'application/json' } }, (proxyRes) => { res.writeHead(proxyRes.statusCode, proxyRes.headers); proxyRes.pipe(res, { end: true }) });
      proxy.on('error', () => res.writeHead(502).end('502: Bad gateway'));
      proxy.write(JSON.stringify(body));

      return proxy.end();
    } catch (e) { return res.writeHead(503).end(`503: Request redirection error\n${JSON.stringify(e.message)}`) };

    req.socket.destroy();
  } catch (e) { return res.writeHead(503).end(`503: Cocoa error\n${JSON.stringify(e.message)}`) };
}).listen(4430, () => console.log('Listening on port 4430'));