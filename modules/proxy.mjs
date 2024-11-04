// Import all dependencies ======================================================================================================================================================================================================>
import Fastify from 'fastify';
import cors from '@fastify/cors';
import crypto from 'crypto';
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
  const allowedIPs = ['192.168.1.165', '127.0.0.1', 'BACKEND', 'BACKEND_IP_2'];

  const generateRayId = () => crypto.randomBytes(16).toString('hex'); // 32-символьный идентификатор
  const generateSessionID = () => crypto.randomBytes(16).toString('hex'); // Идентификатор сессии

  // Проверка допустимого IP-адреса и добавление ray-id
  const fastify = Fastify()
  fastify.addHook('onRequest', headersConfig).register(cors, corsConfig)
  .addHook('onRequest', async (req, res) => {
    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log(req.headers['x-forwarded-for'], req.socket.remoteAddress)
    if (!allowedIPs.includes(clientIP)) return res.status(407).send({ error: 'Invalid session' })
    
    // Добавление ray-id для новых сессий
    if (!req.headers['ray-id']) req.headers['ray-id'] = generateRayId();
    console.log(req.headers)
  })
  // Верификация запроса и аутентификация клиентов
  .post('/authenticate', async (req, res) => {
    const { clientType, apiKey } = req.body;  // clientType может быть "frontend" или "backend"
    
    // Проверка API-ключа
    const isAuthentic = verifyApiKey(apiKey); // Создать свою функцию для проверки ключа
    if (!isAuthentic) return res.status(401).send({ error: 'Unauthorized' });

    // Выбор бэкенда в зависимости от clientType
    const backendIP = selectBackend(clientType); // Функция выбора подходящего бэкенда
    const sessionID = generateSessionID();
    
    // Сохранение сессии в Redis
    await redis.set(sessionID, JSON.stringify({ backendIP, rayId: req.headers['ray-id'], clientType }));

    res.send({ sessionID, backendIP });
  })
  // Прокси сессий с проверкой ray-id и x-service-id
  .all('/route/*', async (req, res) => {
    const sessionID = req.headers['x-session-id'];
    const storedData = await redis.get(sessionID);
    
    if (!storedData) return res.status(401).send({ error: 'Unauthorized' });

    const { backendIP, rayId, clientType } = JSON.parse(storedData);

    // Проверка ray-id и x-service-id для цепочки запросов
    if (req.headers['ray-id'] !== rayId || req.headers['x-service-id'] !== clientType) return res.status(403).send({ error: 'Invalid or mismatched session identifiers' });

    // Перенаправление на соответствующий бэкенд
    try {
      const response = await fetch(`http://${backendIP}${req.url}`, {
        method: req.method,
        headers: {
          ...req.headers,
          'x-service-id': clientType
        },
        body: req.body,
      });

      const data = await response.json();
      res.status(response.status).send(data);
    } catch (error) {
      console.error('Error forwarding request:', error);
      res.status(502).send({ error: 'Bad Gateway' });
    }
  })
  .register(proxy, { upstream: 'http://localhost:5000', prefix: '/dynamic' }) // To dynamic gateway
  .listen({ port: 4000 }, (err, address) => { if (err) throw err });;

  // Пример проверки API-ключа
  function verifyApiKey(apiKey) {
    const validApiKeys = ['API_KEY_FOR_FRONT', 'API_KEY_FOR_BACK'];
    return validApiKeys.includes(apiKey);
  }

  // Пример функции выбора бэкенда
  function selectBackend(clientType) {
    if (clientType === 'frontend') return 'BACKEND_IP_1';  // Подставьте свои значения
    if (clientType === 'backend') return 'BACKEND_IP_2';
    return null;
  }
};