// Import all dependencies ======================================================================================================================================================================================================>
import Fastify from 'fastify';
import cors from '@fastify/cors';
import proxy from '@fastify/http-proxy';
import cluster from 'cluster';
import { cpus } from 'os';
import { corsConfig, headersConfig } from './conf.core.mjs';
import redis from '../db_redis/models/index.mjs';

// Module =======================================================================================================================================================================================================================>
if (cluster.isPrimary) {
  const numCPUs = cpus().length;
  for (let i = 0; i < numCPUs; i++) cluster.fork(); cluster.on('exit', (worker) => console.log(`Warning! Cocoa cluster ${worker.process.pid} died!`)); console.log(`Cocoa Started`)
} else {
  const allowedIPs = ['CLIENT_IP_1', 'CLIENT_IP_2', 'BACKEND_IP_1', 'BACKEND_IP_2'];

  fastify.addHook('onRequest', async (req, res) => {
    // Проверка IP-адреса клиента
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (!allowedIPs.includes(clientIP)) {
      res.status(403).send({ error: 'Forbidden' });
    }
  });

  fastify.post('/authenticate', async (req, res) => {
    const { clientType } = req.body;  // clientType может быть "frontend" или "backend"
    
    // Проверка и верификация API-ключей или JWT
    const isAuthentic = verifyRequest(req);
    if (!isAuthentic) {
      return res.status(401).send({ error: 'Unauthorized' });
    }

    // Привязка клиента к бэкенду
    const backendIP = selectBackend(clientType); // Функция для выбора бэкенда
    const sessionID = generateSessionID();
    await redis.set(sessionID, backendIP);

    res.send({ sessionID, backendIP });
  });

  fastify.all('/route/*', async (req, res) => {
    const sessionID = req.headers['x-session-id'];
    const backendIP = await redis.get(sessionID);

    if (!backendIP) {
      return res.status(401).send({ error: 'Unauthorized' });
    }

    // Перенаправление на нужный бэкенд
    const response = await fetch(`http://${backendIP}${req.url}`, {
      method: req.method,
      headers: req.headers,
      body: req.body,
    });

    res.status(response.status).send(await response.json());
  });

  const fastify = Fastify();

  fastify.get('/', async (req, res) => {
    res.code(200).send('hello')
  });

  fastify.addHook('onRequest', headersConfig).register(cors, corsConfig)
  .register(proxy, { upstream: 'http://localhost:5000', prefix: '/dynamic' }) // To dynamic gateway
  .listen({ port: 4000 }, (err, address) => { if (err) throw err });
};