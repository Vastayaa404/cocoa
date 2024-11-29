// Import all dependencies ======================================================================================================================================================================================================>
import Fastify from 'fastify';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import fastifyStatic from '@fastify/static';

import crypto from 'crypto';
import cluster from 'cluster';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { corsConfig, headersConfig } from './conf.proxy.mjs';
import redis from '../db_redis/models/index.mjs';
import axios from 'axios';
import jwt from 'jsonwebtoken';

// Module =======================================================================================================================================================================================================================>
if (cluster.isPrimary) { const numCPUs = 1; for (let i = 0; i < numCPUs; i++) cluster.fork(); cluster.on('exit', (worker) => console.log(`Warning! Cocoa cluster ${worker.process.pid} died!`)); console.log(`${numCPUs} Cocoa Started`) } else {
  const distPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../engines/dist/');
  const privateKey = fs.readFileSync('../keys/ec_private.key', 'utf8');
  const publicKey = fs.readFileSync('../keys/ec_public.key', 'utf8');
  const CONFIG = { allowedIPs: ['127.0.0.10'], blockedIPs: [], validApiKeys: ['API_KEY_FOR_FRONT', 'API_KEY_FOR_BACK', 'API_KEY_FOR_PROXY'], };
  const proxyPriority = ['127.0.0.10'];

  const generateId = (size) => crypto.randomBytes(size).toString('hex');
  const generateToken = (payload) => jwt.sign(payload, privateKey, { algorithm: 'ES384', expiresIn: '24h', issuer: 'Cocoa' });
  const verifyToken = (token) => jwt.verify(token, publicKey, { algorithms: ['ES384'], issuer: 'Cocoa' });
  const generateFingerprint = (req) => crypto.createHash('sha256').update([req.headers['user-agent'], req.headers['accept-encoding'], req.headers['accept-language'], req.headers['origin'] || 'none', req.headers['referer'] || 'none', Intl.DateTimeFormat().resolvedOptions().timeZone].join('-')).digest('hex');
  const useBanHammer = async (req, res) => { try { if (!CONFIG.blockedIPs.includes(req.socket.remoteAddress)) { await redis.set(`blocked_ip:${req.socket.remoteAddress}`, true, 'EX', 86400);; CONFIG.blockedIPs.push(req.socket.remoteAddress) }; if (!fs.existsSync(path.join(distPath, req.url))) { return res.sendFile('index.html') } } catch (e) { return res.status(503).send({ error: e.message }) }};

  Fastify()
  .register(cors, corsConfig)
  .register(cookie, { secret: 'ZK9/AS,dsds]sdWQIKM-Sas' })
  .register(fastifyStatic, { root: distPath, wildcard: false })
  .addHook('onRequest', (req, res, done) => { if (req.raw.url === '/') return res.raw.destroy(); done() })
  .addHook('onRequest', headersConfig)
  .route({ method: ['GET', 'POST'], url: '/*', handler: async (req, res) => {
    try {
      if (await redis.get(`blocked_ip:${req.socket.remoteAddress}`) || CONFIG.blockedIPs.includes(req.socket.remoteAddress) || req.headers['x-forwarded-for'] || /curl|wget/i.test(req.headers['user-agent']) || /SELECT|INSERT|DROP|UNION|--/i.test(req.url)) return useBanHammer(req, res);
      if (!req.body) { return res.status(200).send('Serving static content.'); }
      const { clientType, prjName, preValidation } = req.body || {};
      const tokens = { cat: req.cookies.cat, cs: req.cookies.cs };

      if (req.body && req.method.toLowerCase() === 'post' && tokens.cat) {
        try {
          try { var decoded = verifyToken(tokens.cat) } catch { return res.status(401).send({ error: 'Invalid token' }) };
          const sessionData = JSON.parse(await redis.get(tokens.cs));
          if (!sessionData || sessionData.fingerprint !== generateFingerprint(req)) return res.status(403).send({ error: 'Session mismatch' });
          const response = await axios[req.method.toLowerCase()](`http://${proxyPriority[0]}:5000${req.url}`, req.body, { headers: { 'x-service': decoded.clientType } });
          ['x-dora-request-id'].forEach((header) => response.headers[header] && res.header(header, response.headers[header]));
          return res.status(200).send(response.data);
        } catch (e) { return res.status(503).send({ error: e.message }) };
      }
      
      if (clientType) {
        try {
          if (!tokens.cat) {
            if (!clientType || !prjName || !CONFIG.validApiKeys.includes(preValidation)) return res.status(428).send({ error: 'Unable to load resource' });
            tokens.cs = generateId(16);
            tokens.cat = generateToken({ clientType, prjName });
            await redis.set(tokens.cs, JSON.stringify({ fingerprint: generateFingerprint(req), clientType: req.body.clientType, token: tokens.cat }), 'EX', 86400);
            
            res.setCookie('cat', tokens.cat, { path: '/', httpOnly: true, secure: true, sameSite: 'Strict' });
            res.setCookie('cs', tokens.cs, { path: '/', httpOnly: true, secure: true, sameSite: 'Strict' });
            return res.status(201).send('Successful authorization');
          } return res.status(421).send({ error: 'Non Actual Body' });
        } catch (e) { return res.status(503).send({ error: e.message }) };
      };

      return res.raw.destroy();
    } catch (e) { return res.status(e.response?.status || 502).send({ error: e.response?.data || 'Bad Gateway' }) };
  } }).listen({ port: 4430, host: '0.0.0.0' }, (err) => { if (err) throw err }) };