// Import all dependencies ======================================================================================================================================================================================================>
import Fastify from 'fastify';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import fastifyStatic from '@fastify/static';

import crypto from 'crypto';
import cluster from 'cluster';
import { cpus } from 'os';

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { corsConfig, headersConfig } from './conf.core.mjs';
import redis from '../db_redis/models/index.mjs';
import axios from 'axios';
import jwt from 'jsonwebtoken';

// Module =======================================================================================================================================================================================================================>
if (cluster.isPrimary) {
  const numCPUs = 1 //cpus().length;
  for (let i = 0; i < numCPUs; i++) cluster.fork(); cluster.on('exit', (worker) => console.log(`Warning! Cocoa cluster ${worker.process.pid} died!`)); console.log(`${numCPUs} Cocoa Started`);
} else {
  const distPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../engines/dist/');
  const privateKey = fs.readFileSync('../keys/ec_private.key', 'utf8');
  const publicKey = fs.readFileSync('../keys/ec_public.key', 'utf8');
  const CONFIG = { allowedIPs: ['FRONTEND', '127.0.0.1', 'BACKEND', 'BACKEND_IP_2', '127.0.0.10'], blockedIPs: ['127.0.0.19 '],  validApiKeys: ['API_KEY_FOR_FRONT', 'API_KEY_FOR_BACK', 'API_KEY_FOR_PROXY'], frontends: ['127.0.0.7'], backends: ['127.0.0.10'] };
  const cmsParameters = {  }

  const generateId = (size) => crypto.randomBytes(size).toString('hex');
  const generateToken = (payload) => jwt.sign(payload, privateKey, { algorithm: 'ES384', expiresIn: '24h', issuer: 'Cocoa' });
  const verifyToken = (token) => jwt.verify(token, publicKey, { algorithms: ['ES384'], issuer: 'Cocoa' });
  const generateFingerprint = (req) => crypto.createHash('sha256').update([req.headers['user-agent'], req.headers['accept-encoding'], req.headers['accept-language'], req.headers['origin'] || 'none', req.headers['referer'] || 'none', Intl.DateTimeFormat().resolvedOptions().timeZone].join('-')).digest('hex');
  const isMaliciousRequest = (req) => { return /SELECT|INSERT|DROP|UNION|--/i.test(req.url) };
  const modifyIndexHtml = (html) => { html = html.replace(/(href|src)="\/(assets\/[^"]+)"/g, (match, attr, path) => { return `${attr}="/${path}"` }); return html };
  const useBanHammer = (req, res) => { try { const requestedPath = path.join(distPath, req.url); const fileToServe = fs.existsSync(requestedPath) && fs.statSync(requestedPath).isFile() ? requestedPath : path.join(distPath, 'index.html'); if (fs.existsSync(fileToServe)) { return fileToServe.endsWith('.html') ? res.type('text/html').send(modifyIndexHtml(fs.readFileSync(fileToServe, 'utf8'))) : res.sendFile(fileToServe.replace(distPath, '')) }; return res.status(404).send({ error: 'File not found' }) } catch (e) { return res.status(503).send({ error: e.message }) } };

  Fastify().register(cors, corsConfig).register(cookie, { secret: 'ZK9/AS,dsds]sdWQIKM-Sas' }).register(fastifyStatic, { root: distPath, prefix: '/c' })
  .addHook('onRequest', headersConfig)
  .route({ method: ['GET', 'POST'], url: '/*', handler: async (req, res) => {
    try {
      if (CONFIG.blockedIPs.includes(req.socket.remoteAddress) || /curl|wget/i.test(req.headers['user-agent']) || isMaliciousRequest(req)) return useBanHammer(req, res);
      if (req.headers['x-forwarded-for']) return res.status(406).send({ error: 'Proxying is not allowed' });
      let token = req.cookies.cat;

      const { clientType, prjName, preValidation } = req.body || {};

      if (!req.body) {
        try { // Какой-либо клиентский ресурс
          return res.status(200).send('Ну да, на статике');
        } catch (err) { return res.status(500).send({ error: 'Internal Server Error' }) };
      };

      if (req.body && req.method.toLocaleLowerCase() === 'post' && token) {
        try { var decoded = verifyToken(token) } catch { return res.status(401).send({ error: 'Invalid token' }) };
        const sessionData = JSON.parse(await redis.get(req.headers['x-session-id']));
        if (!sessionData) return res.status(401).send({ error: 'Session not found' });
        if (sessionData.fingerprint !== generateFingerprint(req)) return res.status(403).send({ error: 'Session mismatch' });
        // console.log(sessionData.fingerprint)
        
        const response = await axios[req.method.toLowerCase()](`http://${sessionData.backendIP}:5000${req.url}`, req.body, { headers: { 'x-service': decoded.clientType } } );
        ['x-dora-request-id'].forEach((header) => response.headers[header] && res.header(header, response.headers[header]));
        return res.status(200).send(response.data);
      }
      
      if (clientType) {
        if (!token) {
          if (!clientType || !prjName || !CONFIG.validApiKeys.includes(preValidation)) return res.status(428).send({ error: 'Unable to load resource' });
          const backendIP = { frontend: CONFIG.allowedIPs[4], backend: CONFIG.allowedIPs[1] }[clientType];
          // if (!backendIP) return res.status(400).send({ error: 'Invalid client type' });
          
          const sessionID = generateId(16);
          token = generateToken({ clientType, prjName });
          await redis.set(sessionID, JSON.stringify({ fingerprint: generateFingerprint(req), backendIP, clientType, token }), 'EX', 86400);
          
          res.setCookie('cat', token, { httpOnly: true, secure: true, sameSite: 'Strict' });
          return res.status(201).send({ sessionID });
        }
        
        try { var decoded = verifyToken(token) } catch { return res.status(401).send({ error: 'Invalid token' }) };
        const sessionData = JSON.parse(await redis.get(req.headers['x-session-id']));
        if (!sessionData) return res.status(401).send({ error: 'Session not found' });
        if (sessionData.fingerprint !== generateFingerprint(req)) return res.status(403).send({ error: 'Session mismatch' });
        // console.log(sessionData.fingerprint)
        
        const response = await axios[req.method.toLowerCase()](`http://${sessionData.backendIP}:5000${req.url}`, req.body, { headers: { 'x-service': decoded.clientType } } );
        ['x-dora-request-id'].forEach((header) => response.headers[header] && res.header(header, response.headers[header]));
        return res.status(200).send(response.data);
      };

      if (req.body.getAllDevices) {
        // if (!token) return res.status(403).send("Access Denied")
        // try { var decoded = verifyToken(token) } catch { return res.status(401).send({ error: 'Invalid token' }) };

        // const sessionData = JSON.parse(await redis.get(req.headers['x-session-id']));
        // if (!sessionData) return res.status(401).send({ error: 'Session not found' });
        // if (sessionData.fingerprint !== generateFingerprint(req)) return res.status(403).send({ error: 'Session mismatch' });

        return res.status(200).send({ af: CONFIG.frontends, ab: CONFIG.backends });
      }
     
      return res.status(400).send({ error: 'Invalid client type' });
    } catch (err) { return res.status(err.response?.status || 502).send({ error: err.response?.data || 'Bad Gateway' }) } } }).listen({ port: 4430, host: '0.0.0.0' }, (err) => { if (err) throw err }); 




  // v6 xd





  // const distPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../engines/dist/');
  // const privateKey = fs.readFileSync('../keys/ec_private.key', 'utf8');
  // const publicKey = fs.readFileSync('../keys/ec_public.key', 'utf8');
  // const CONFIG = { allowedIPs: ['FRONTEND', '127.0.0.1', 'BACKEND', 'BACKEND_IP_2', '127.0.0.10'], blockedIPs: ['127.0.0.19'],  validApiKeys: ['API_KEY_FOR_FRONT', 'API_KEY_FOR_BACK'] };

  // const modifyIndexHtml = (html) => { html = html.replace(/(href|src)="\/(assets\/[^"]+)"/g, (match, attr, path) => { return `${attr}="/c/${path}"` }); return html };
  // const generateId = (size) => crypto.randomBytes(size).toString('hex');
  // const generateToken = (payload) => jwt.sign(payload, privateKey, { algorithm: 'ES384', expiresIn: '24h', issuer: 'Cocoa' });
  // const verifyToken = (token) => jwt.verify(token, publicKey, { algorithms: ['ES384'], issuer: 'Cocoa' });
  // const generateFingerprint = (req) => crypto.createHash('sha256').update([req.headers['user-agent'], req.headers['accept-encoding'], req.headers['accept-language'], req.headers['referer'] || 'none', Intl.DateTimeFormat().resolvedOptions().timeZone].join('-')).digest('hex');
   
  // Fastify().register(cors, corsConfig).register(cookie, { secret: 'ZK9/AS,dsds]sdWQIKM-Sas' }).register(fastifyStatic, { root: distPath, prefix: '/c/' })
  // .addHook('onRequest', headersConfig).addHook('onRequest', async (req, res) => {
  //   const ip = req.ip;
  //   // console.log(`Запрос от IP: ${ip} к маршруту: ${req.url}`);
  // })
  // .route({ method: ['GET', 'POST'], url: '/*', handler: async (req, res) => {
  //   try {
  //     // console.log(`Запрос от IP: ${req.ip} к маршруту: ${req.url}`);
  //     // console.log('Headers:', req.headers);
  //     // console.log('Body:', req.body);

  //     if (CONFIG.blockedIPs.includes(req.socket.remoteAddress)) return res.status(407).send({ error: 'Unable to load site' });
  //     if (req.headers['x-forwarded-for']) return res.status(406).send({ error: 'Proxying is not allowed' });
  //     let token = req.cookies.cat;

  //     const { clientType, prjName, preValidation } = req.body || {};

  //     if (!req.body || !clientType || !token) {
  //     // if (!clientType || !token || !req.body) {
  //       console.log('Отправлен на статику')
  //       // try {
  //       //   const requestedPath = path.join(distPath, req.url.replace(/^\/c/, '').replace(/^\//, ''));
  //       //   if (fs.existsSync(requestedPath) && fs.statSync(requestedPath).isFile()) { return res.sendFile(requestedPath.replace(distPath, '')) };
  //       //   const indexHtmlPath = path.join(distPath, 'index.html');
  //       //   if (!fs.existsSync(indexHtmlPath)) { return res.status(404).send({ error: 'index.html not found' }) };
  //       //   const indexHtml = fs.readFileSync(indexHtmlPath, 'utf8');
  //       //   const modifiedHtml = modifyIndexHtml(indexHtml);
  //       //   res.type('text/html').send(modifiedHtml);
  //       // } catch (err) { res.status(500).send({ error: 'Internal Server Error' }) };
        
  //       try {
  //         const requestedPath = path.join(distPath, req.url.replace(/^\/c/, '').replace(/^\//, ''));
  //         const fileToServe = fs.existsSync(requestedPath) && fs.statSync(requestedPath).isFile() ? requestedPath : path.join(distPath, 'index.html');
  //         if (!fs.existsSync(fileToServe)) { return res.status(404).send({ error: `${fileToServe === requestedPath ? 'File' : 'index.html'} not found` }) };
  //         const content = fs.readFileSync(fileToServe, 'utf8');
  //         return res.type(fileToServe.endsWith('.html') ? 'text/html' : undefined).send(fileToServe.endsWith('index.html') ? modifyIndexHtml(content) : content);
  //       } catch { return res.status(503).send({ error: 'Internal Server Error' }) };
  //     };
      
  //     if (clientType === 'frontend' || clientType === 'backend') {
  //       console.log('Отправлен как приложение')
  //       if (!token) {
  //         if (!clientType || !prjName || !CONFIG.validApiKeys.includes(preValidation)) return res.status(428).send({ error: 'Unable to load resource' });
  //         const backendIP = { frontend: CONFIG.allowedIPs[4], backend: CONFIG.allowedIPs[1] }[clientType];
  //         if (!backendIP) return res.status(400).send({ error: 'Invalid client type' });
          
  //         const sessionID = generateId(16);
  //         token = generateToken({ clientType, prjName });
  //         await redis.set(sessionID, JSON.stringify({ fingerprint: generateFingerprint(req), backendIP, clientType, token }), 'EX', 86400);
          
  //         res.setCookie('cat', token, { httpOnly: true, secure: true, sameSite: 'Strict' });
  //         return res.status(201).send({ sessionID });
  //       }
        
  //       try { var decoded = verifyToken(token) } catch { return res.status(401).send({ error: 'Invalid token' }) };
  //       const sessionData = JSON.parse(await redis.get(req.headers['x-session-id']));
  //       if (!sessionData) return res.status(401).send({ error: 'Session not found' });
  //       if (sessionData.fingerprint !== generateFingerprint(req)) return res.status(403).send({ error: 'Session mismatch' });
  //       // console.log(sessionData.fingerprint)
        
  //       const response = await axios[req.method.toLowerCase()](`http://${sessionData.backendIP}:5000${req.url}`, req.body, { headers: { 'x-service': decoded.clientType } } );
  //       ['x-dora-request-id'].forEach((header) => response.headers[header] && res.header(header, response.headers[header]));
  //       return res.status(200).send(response.data);
  //     };
     
  //     return res.status(400).send({ error: 'Invalid client type' });
  //   } catch (err) { return res.status(err.response?.status || 502).send({ error: err.response?.data || 'Bad Gateway' }) } } }).listen({ port: 4000, host: '0.0.0.0' }, (err) => { if (err) throw err }); 
  
  





    //   let token = req.cookies.cat;

    //   if (!token) {
    //     const { clientType, prjName, preValidation } = req.body || {};
    //     if (!clientType || !prjName || !CONFIG.validApiKeys.includes(preValidation)) return res.status(428).send({ error: 'Unable to load resource' });
        
    //     const backendIP = { frontend: CONFIG.allowedIPs[4], backend: CONFIG.allowedIPs[1] }[clientType];
    //     if (!backendIP) return res.status(400).send({ error: 'Invalid client type' });
        
    //     const sessionID = generateId(16);
    //     token = generateToken({ clientType, prjName });
    //     await redis.set(sessionID, JSON.stringify({ fingerprint: generateFingerprint(req), backendIP, clientType, token }), 'EX', 86400);
        
    //     res.setCookie('cat', token, { httpOnly: true, secure: true, sameSite: 'Strict' });
    //     return res.status(201).send({ sessionID });
    //   }

    //   try { var decoded = verifyToken(token) } catch { return res.status(401).send({ error: 'Invalid token' }) };
    //   const sessionData = JSON.parse(await redis.get(req.headers['x-session-id']));
    //   if (!sessionData) return res.status(401).send({ error: 'Session not found' });
    //   if (sessionData.fingerprint !== generateFingerprint(req)) return res.status(403).send({ error: 'Session mismatch' });
    //   console.log(sessionData.fingerprint)

    //   const response = await axios[req.method.toLowerCase()](`http://${sessionData.backendIP}:5000${req.url}`, req.body, { headers: { 'x-service': decoded.clientType } } );
    //   ['x-dora-request-id'].forEach((header) => response.headers[header] && res.header(header, response.headers[header]));
    //   res.send(response.data);
    // } catch (err) { res.status(err.response?.status || 502).send({ error: err.response?.data || 'Bad Gateway' }) } } }).listen({ port: 4000, host: '0.0.0.0' }, (err) => { if (err) throw err });





  // v5

  // .route({ method: ['GET', 'POST'], url: '/hello', handler: async (req, res) => { res.status(200).send('Hello') } })

  // if (clientType/* === 'frontend' || clientType === 'backend'*/) {
  //   if (!CONFIG.allowedIPs.includes(req.socket.remoteAddress)) return res.status(407).send({ error: 'Unable to load site' });
  //   if (!CONFIG.validApiKeys.includes(preValidation)) { return res.status(401).send({ error: 'Invalid API Key' }) };

  //   const token = req.cookies.cat || generateToken({ clientType, prjName });
  //   if (!req.cookies.cat) { res.setCookie('cat', token, { httpOnly: true, secure: true, sameSite: 'Strict' }) };

  //   // const backendIP = CONFIG.allowedIPs.find(ip => ip.includes(clientType));
  //   const backendIP = { frontend: CONFIG.allowedIPs[4], backend: CONFIG.allowedIPs[1] }[clientType];
  //   if (!backendIP) { return res.status(400).send({ error: `No backend available for ${clientType}` }) };

  //   await redis.set(`session:${generateId(16)}`, JSON.stringify({ fingerprint: generateFingerprint(req), backendIP, clientType, token }), 'EX', 86400);
  //   return res.status(201).send({ message: 'Session created', token });
  // };


  // const privateKey = fs.readFileSync('../keys/ec_private.key', 'utf8');
  // const publicKey = fs.readFileSync('../keys/ec_public.key', 'utf8');

  // const CONFIG = { allowedIPs: ['FRONTEND', '127.0.0.1', 'BACKEND', 'BACKEND_IP_2', '127.0.0.10'], validApiKeys: ['API_KEY_FOR_FRONT', 'API_KEY_FOR_BACK'] };

  // const generateId = (size) => crypto.randomBytes(size).toString('hex');
  // const verifyApiKey = (apiKey) => CONFIG.validApiKeys.includes(apiKey);
  // const selectBackend = (clientType) => ({ frontend: CONFIG.allowedIPs[4], backend: CONFIG.allowedIPs[1] }[clientType] || null);
  // const generateToken = (payload) => jwt.sign(payload, privateKey, { algorithm: 'ES384', expiresIn: '24h', issuer: 'Cocoa', });
  // const verifyToken = (token) => jwt.verify(token, publicKey, { algorithms: ['ES384'], issuer: 'Cocoa' });

  // const generateFingerprint = (req) => {
  //   const hash = crypto.createHash('sha256');
  //   hash.update(req.headers['user-agent'] || '');
  //   hash.update(req.headers['accept-encoding'] || '');
  //   hash.update(req.headers['accept-language'] || '');
  //   return hash.digest('hex');
  // };

  // const validateClient = (req, res) => { const clientIP = req.socket.remoteAddress;
  //   if (!CONFIG.allowedIPs.includes(clientIP)) return res.status(407).send({ error: 'Unable to load site' });
  //   if (req.headers['x-forwarded-for']) return res.status(406).send('Proxying is not allowed');
  // };

  // Fastify().register(cors, corsConfig).register(cookie, { secret: "ZK9/AS,dsds]sdWQIKM-Sas", hook: 'onRequest' }).addHook('onRequest', headersConfig)
  //   .route({ method: ['GET', 'POST'], url: '/*', handler: async (req, res) => {
  //     try {
  //       res.header('server', 'Cocoa');
  //       validateClient(req, res);
  
  //       const rayId = req.headers['c-ray'] || generateId(8);
  //       let token = req.cookies.cat;
  
  //       // Если токена нет, авторизуем клиента "на лету"
  //       if (!token) {
  //         const { clientType, prjName, preValidation } = req.body || {};
  //         if (!clientType || !prjName || !preValidation) { return res.status(428).send({ error: 'Unable to load resource' }) };
  //         if (!verifyApiKey(preValidation)) { return res.status(422).send({ error: 'Invalid API key' }) };
  
  //         const backendIP = selectBackend(clientType);
  //         if (!backendIP) { return res.status(400).send({ error: 'Invalid client type' }) };
  
  //         const sessionID = generateId(16);
  //         const newRayId = generateId(8);
  //         token = generateToken({ clientType, prjName });
  //         const fingerprint = generateFingerprint(req);
  //         await redis.set(sessionID, JSON.stringify({ fingerprint, backendIP, clientType, token }) );

  //         res.setCookie('cat', token, { httpOnly: true, secure: true, sameSite: 'Strict' });
  //         res.header('c-ray', newRayId);
  //         return res.status(201).send({ sessionID });
  //       };

  //       // Если токен есть, проверяем его
        // let decoded;
        // try { decoded = verifyToken(token) } catch (err) { return res.status(401).send({ error: 'Invalid token' }) };
  
  //       const sessionID = req.headers['x-session-id'];
  //       const sessionData = JSON.parse(await redis.get(sessionID));
  //       if (!sessionData) { return res.status(401).send({ error: 'Session not found' }) };

  //       const { fingerprint: storedFingerprint, backendIP: storedBackendIP } = sessionData;
  //       if (storedFingerprint !== generateFingerprint(req)) return res.status(403).send({ error: 'Session mismatch' });
  
  //       // Прокидываем запрос на соответствующий бэкенд
        // const response = await axios[req.method.toLowerCase()](`http://${storedBackendIP}:5000${req.url}`, req.body, { headers: { 'x-service': decoded.clientType } } );
        // const selectedHeaders = ['x-dora-request-id'];
        // selectedHeaders.forEach((header) => response.headers[header] && res.header(header, response.headers[header]));
        // res.send(response.data);
  //     } catch (err) { res.status(err.response?.status || 502).send({ error: err.response?.data || 'Bad Gateway' }) };
  //   } }).listen({ port: 4000, host: '127.0.0.100' }, (err) => { if (err) throw err });





  // v4





  // const privateKey = fs.readFileSync('../keys/ec_private.key', 'utf8');
  // const publicKey = fs.readFileSync('../keys/ec_public.key', 'utf8');

  // const CONFIG = { allowedIPs: ['FRONTEND', '127.0.0.1', 'BACKEND', 'BACKEND_IP_2', '127.0.0.10'], validApiKeys: ['API_KEY_FOR_FRONT', 'API_KEY_FOR_BACK'] };

  // const generateId = (size) => crypto.randomBytes(size).toString('hex');
  // const verifyApiKey = (apiKey) => CONFIG.validApiKeys.includes(apiKey);
  // const selectBackend = (clientType) => ({ frontend: CONFIG.allowedIPs[4], backend: CONFIG.allowedIPs[1] }[clientType] || null);
  // const generateToken = (payload) => jwt.sign(payload, privateKey, { algorithm: 'ES384', expiresIn: '24h', issuer: 'Cocoa', });
  // const verifyToken = (token) => jwt.verify(token, publicKey, { algorithms: ['ES384'], issuer: 'Cocoa' });

  // const generateFingerprint = (req) => {
  //   const hash = crypto.createHash('sha256');
  //   hash.update(req.headers['user-agent'] || '');
  //   hash.update(req.headers['accept-encoding'] || '');
  //   hash.update(req.headers['accept-language'] || '');
  //   return hash.digest('hex');
  // };

  // const validateClient = (req, res) => { const clientIP = req.socket.remoteAddress;
  //   if (!CONFIG.allowedIPs.includes(clientIP)) { return res.status(407).send({ error: 'Unable to load site' }) };
  //   if (req.headers['x-forwarded-for']) { return res.status(406).send('Proxying is not allowed') };
  // };

  // Fastify().register(cors, corsConfig).register(cookie, { secret: "ZK9/AS,dsds]sdWQIKM-Sas", hook: 'onRequest' }).addHook('onRequest', headersConfig)
  //   .addHook('onRequest', async (req, res) => {
  //     const rayId = req.headers['ray-id'] || generateId(8);
  //     const requestCount = await redis.incr(`rate_limit:${rayId}`);
  //     if (requestCount > 30) return res.status(429).send({ error: 'Too many requests' });
  //     redis.expire(`rate_limit:${rayId}`, 60);
  //     res.header('c-ray', rayId);
  //   })
  //   .post('/a', async (req, res) => {
  //     try {
  //       res.header('server', 'Cocoa');
  //       const rayId = req.headers['ray-id'] || generateId(8);
  //       const fingerprint = generateFingerprint(req);

  //       validateClient(req, res);
        
  //       const { clientType, prjName, preValidation } = req.body || {};
  //       if (!clientType || !prjName || !preValidation) { return res.status(428).send({ error: 'Unable to load resource' }) };
  //       if (!verifyApiKey(preValidation)) { return res.status(422).send({ error: 'Invalid API key' }) };

  //       const backendIP = selectBackend(clientType);
  //       if (!backendIP) { return res.status(400).send({ error: 'Invalid client type' }) };

  //       const sessionID = generateId(16);
  //       const token = generateToken({ clientType, prjName });
  //       await redis.set(sessionID, JSON.stringify({ backendIP, clientType, token, rayId, fingerprint }));


  //       res.setCookie('cat', token, { httpOnly: true, secure: true, sameSite: 'Strict' });
  //       res.status(201).send({ sessionID });
  //     } catch (err) { res.status(503).send({ error: err/*'Cocoa error'*/ }) };
  //   })
  //   .route({ method: ['GET', 'POST'], url: '/*', handler: async (req, res) => {
  //     try {
  //       res.header('server', 'Cocoa');
  //       const rayId = req.headers['ray-id'] || generateId(8);
  //       res.header('c-ray', rayId);

  //       validateClient(req, res);

  //       const token = req.cookies.cat;
  //       if (!token) { return res.status(422).send({ error: 'Missing auth token' }) };

  //       let decoded;
  //       try { decoded = verifyToken(token) } catch (err) { return res.status(401).send({ error: 'Invalid token' }) };

  //       const sessionID = req.headers['x-session-id'];
  //       const sessionData = JSON.parse(await redis.get(sessionID));
  //       if (!sessionData) { return res.status(401).send({ error: 'Session not found' }) };

  //       const { backendIP, rayId: storedRayId, fingerprint: storedFingerprint } = sessionData;
  //       if (storedRayId !== rayId || storedFingerprint !== generateFingerprint(req)) { return res.status(403).send({ error: 'Session mismatch' }) };

  //       req.headers['x-forwarded-for'] = '127.0.0.100:4000';

  //       const response = await axios[req.method.toLowerCase()](`http://${backendIP}:5000${req.url}`, req.body, { headers: { 'x-service': decoded.clientType } });
        // const selectedHeaders = ['x-dora-request-id'];
        // selectedHeaders.forEach((header) => response.headers[header] && res.header(header, response.headers[header]));
        // res.send(response.data);
  //     } catch (err) { res.status(err.response?.status || 502).send({ error: err.response?.data || 'Bad Gateway' }) } } 
  //   }).listen({ port: 4000, host: '127.0.0.100' }, (err) => { if (err) throw err });

    // TODO: Разобраться с обработкой ошибок. Что-то придумать с Дэборой.






  // v3





  // const privateKey = fs.readFileSync('../keys/ec_private.key', 'utf8');
  // const publicKey = fs.readFileSync('../keys/ec_public.key', 'utf8');

  // const CONFIG = { allowedIPs: ['FRONTEND', '127.0.0.1', 'BACKEND', 'BACKEND_IP_2', '127.0.0.10'], validApiKeys: ['API_KEY_FOR_FRONT', 'API_KEY_FOR_BACK'], };

  // const generateId = (size) => crypto.randomBytes(size).toString('hex');
  // const verifyApiKey = (apiKey) => CONFIG.validApiKeys.includes(apiKey);
  // const selectBackend = (clientType) => ({ frontend: CONFIG.allowedIPs[4], backend: CONFIG.allowedIPs[1], }[clientType] || null);
  // const generateToken = (payload) => jwt.sign(payload, privateKey, { algorithm: 'ES384', expiresIn: '24h', issuer: 'Cocoa' });
  // const verifyToken = (token) => jwt.verify(token, publicKey, { algorithms: ['ES384'], issuer: 'Cocoa' });

  // const validateClient = (req, res) => {
  //   const clientIP = req.socket.remoteAddress;
  //   if (!CONFIG.allowedIPs.includes(clientIP)) return res.status(407).send({ error: 'Unable to load site' });
  //   if (req.headers['x-forwarded-for']) return res.status(406).send('Proxying is not allowed');
  // };

  // Fastify().register(cors, corsConfig).register(limit, { hook: 'preHandler', max: 30, timeWindow: '1 minute', ban: 2 })c
  // .post('/a', async (req, res) => {
  //   try {
  //     res.header('server', 'Cocoa');
  //     const rayId = req.headers['ray-id'] || generateId(8);
  //     res.header('c-ray', rayId);

  //     validateClient(req, res);

  //     const { clientType, prjName, preValidation } = req.body || {};
  //     if (!clientType || !prjName || !preValidation) return res.status(428).send({ error: 'Unable to load resource' });
  //     if (!verifyApiKey(preValidation)) return res.status(422).send({ error: 'Unprocessible connection' });

  //     const backendIP = selectBackend(clientType);
  //     if (!backendIP) return res.status(400).send({ error: 'Invalid clientType' });

  //     const sessionID = generateId(16);
  //     const token = generateToken({ clientType, prjName });

  //     await redis.set(sessionID, JSON.stringify({ backendIP, clientType, token, rayId }));
  //     res.status(201).send({ sessionID, token });
  //   } catch (err) { res.status(503).send({ error: 'Cocoa error' }) };
  // })
  // .route({
  //   method: ['GET', 'POST'], url: '/*', handler: async (req, res) => {
  //     try {
  //       res.header('server', 'Cocoa');
  //       const rayId = req.headers['ray-id'] || generateId(8);
  //       res.header('c-ray', rayId);

  //       validateClient(req, res);

  //       const token = req.headers['x-cat'];
  //       if (!token) return res.status(422).send({ error: 'Unprocessible session' });

  //       try { verifyToken(token) } catch (err) { return res.status(401).send({ error: 'Invalid token' }) }

  //       const sessionID = req.headers['x-session-id'];
  //       // const sessionData = await redis.get(sessionID);
        

  //       const sessionData = JSON.parse(await redis.get(sessionID));
  //       console.log(sessionData);
  //       if (sessionData.rayId !== req.headers['ray-id']) { return res.status(403).send({ error: 'Ray ID mismatch. Possible forgery detected.' }) };

  //       if (!sessionData) return res.status(401).send({ error: 'Session not found' });

  //       const { backendIP, clientType } = JSON.parse(sessionData);
  //       req.headers['x-forwarded-for'] = '127.0.0.100:4000';

  //       const response = await axios[req.method.toLowerCase()](`http://${backendIP}:5000${req.url}`, req.body, { headers: { 'x-service': clientType } });

  //       const selectedHeaders = ['x-dora-request-id']; // То что надо оставить с бэка
  //       selectedHeaders.forEach(header => response.headers[header] && res.header(header, response.headers[header]));
  //       res.send(response.data);
  //     } catch (err) { res.status(err.response?.status || 502).send({ error: err.response?.data || 'Bad Gateway' }) }} 
  //   }).listen({ port: 4000, host: '127.0.0.100' }, (err) => { if (err) throw err });



 // v 2





  // const allowedIPs = ['FRONTEND', '127.0.0.1', 'BACKEND', 'BACKEND_IP_2', '127.0.0.10'];
  // const validApiKeys = ['API_KEY_FOR_FRONT', 'API_KEY_FOR_BACK'];

  // const privateKey = fs.readFileSync('../keys/ec_private.key', 'utf8');
  // const publicKey = fs.readFileSync('../keys/ec_public.key', 'utf8');

  // const generateRayId = () => crypto.randomBytes(8).toString('hex'); // 32-символьный идентификатор
  // const generateSessionID = () => crypto.randomBytes(16).toString('hex'); // Идентификатор сессии
  // const verifyApiKey = (apiKey) => validApiKeys.includes(apiKey); // Пример проверки API-ключа
  // const selectBackend = (clientType) => { if (clientType === 'frontend') return allowedIPs[4]; if (clientType === 'backend') return allowedIPs[1]; console.log('Для клиента нет необходимого сервера'); return null }; // Пример функции выбора бэкенда

  // const generateToken = (payload) => { return jwt.sign(payload, privateKey, { algorithm: 'ES384', expiresIn: '24h', issuer: 'Cocoa authorization service' }) };
  // const verifyToken = (token) => { return jwt.verify(token, publicKey, { algorithms: ['ES384'], issuer: 'Cocoa authorization service' }) };

  // const fastify = Fastify()
  // fastify.register(cors, corsConfig).register(limit, { hook: 'preHandler', max: 30, timeWindow: '1 minute', ban: 2 }).addHook('onRequest', headersConfig)
  // .post('/a', async (req, res) => {
  //   try {
  //     res.header("server", "Cocoa");
  //     // RAY-ID отправляется при любой ошибке в случае проблем с нашей стороной
  //     // Добавление ray-id для новых сессий. TODO: Пусть RAY-ID будет одинаков для тех запросов, направленных от одного и того же клиента разным сервисам.
  //     if (!req.headers['ray-id']) req.headers['Ray-id'] = generateRayId();
  //     res.header("c-ray", req.headers['Ray-id']);

  //     const clientIP = req.socket.remoteAddress;
  //     // if (req.headers['x-forwarded-for']) return res.status(406).send('Proxying is not allowed. Dirty Query'); // Если новый клиент проксирован, то кто он?
  //     if (!allowedIPs.includes(clientIP)) return res.status(407).send({ error: 'Unable to load site' });
  //     if (!req.body || !req.body.clientType || !req.body.prjName || !req.body.preValidation) return res.status(428).send({ error: 'Unable to load resource' });
  //     const { clientType, prjName, preValidation } = req.body;  // clientType может быть "frontend" или "backend" // preValidation заливать sha256 для доп.безопасности

  //     const __dirname = path.dirname(fileURLToPath(import.meta.url));
  //     const checkKeysExist = () => { const privateKeyPath = path.join(__dirname, '../keys', 'ec_private.key'); const publicKeyPath = path.join(__dirname, '../keys', 'ec_public.key'); return fs.existsSync(privateKeyPath) && fs.existsSync(publicKeyPath) };
  //     if (!checkKeysExist()) { return res.status(501).send({ error: 'Secret keys not found' }) };
  //     const token = generateToken({ clientType, prjName });

  //     // Проверка API-ключа
  //     const isAuthentic = verifyApiKey(preValidation);
  //     if (!isAuthentic) return res.status(422).send({ error: 'Unprocessible connection' });

  //     // Выбор бэкенда в зависимости от clientType
  //     const backendIP = selectBackend(clientType); // Функция выбора подходящего бэкенда
  //     const sessionID = generateSessionID();
  //     await redis.set(sessionID, JSON.stringify({ backendIP, clientType, token }));

  //     res.status(201).send({ sessionID, cat: token }); // TODO: не факт что отправляем, сделаем все под капотом
  //   } catch (e) { console.log(e.message) }
  // })
  // .route({
  //   method: ['GET', 'POST'], url: '/*', handler: async (req, res) => { // TODO: check methods in backend
  //     try {
  //       res.header("server", "Cocoa");
  //       if (!req.headers['ray-id']) req.headers['Ray-id'] = generateRayId();
  //       res.header("c-ray", req.headers['Ray-id']);
  //       const clientIP = req.socket.remoteAddress;
  //       if (!allowedIPs.includes(clientIP)) return res.status(407).send({ error: 'Unable to load site' });
  //       if (req.headers['x-forwarded-for']) return res.status(406).send('Proxying is not allowed. Dirty Query'); // Если новый клиент проксирован, то кто он?
  //       if (!req.headers['x-cat']) return res.status(422).send({ error: 'Unprocessible session' });
  //       try { const decoded = verifyToken(req.headers['x-cat']) } catch (e) { return res.status(401).send({ code: 401, data: e.message }) }

  //       // Извлекаем информацию из сессии
  //       const sessionID = req.headers['x-session-id'];
  //       if (req.headers['x-session-id'] !== sessionID) return res.status(403).send({ error: 'Invalid or mismatched session identifiers' });

  //       const storedData = await redis.get(sessionID);
  //       if (!storedData) return res.status(401).send({ error: 'Unauthorized session' });
  //       const { backendIP, clientType } = JSON.parse(storedData);
        
  //       req.headers['x-forwarded-for'] = '127.0.0.100:4000'; // Сами проксируем, ну а хуле
  //       // Проксируем запрос на бэкенд
  //       if (!req.body) return res.status(400).send('Nullish request')
  //       const response = await axios[req.method.toLowerCase()](`http://${backendIP}:5000${req.url}`, req.body, { headers: { 'x-forwarded-for': req.headers['x-forwarded-for'], 'x-session-id': req.headers['x-session-id'], 'x-service': clientType } })
        // const selectedHeaders = ['x-dora-request-id']; // То что надо оставить с бэка
        // selectedHeaders.forEach(header => response.headers[header] && res.header(header, response.headers[header]));
        // res.send(response.data);
  //     } catch (e) { res.status(e.response?.status || 502).send({ data: e.response?.data || 'Bad Gateway' }) }
  //   }}).listen({ port: 4000, host: '127.0.0.100' }, (err, address) => { if (err) throw err });
};