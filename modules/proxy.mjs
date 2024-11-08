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
  const allowedIPs = ['FRONTEND', '127.0.0.1', 'BACKEND', 'BACKEND_IP_2', '127.0.0.12'];
  const validApiKeys = ['API_KEY_FOR_FRONT', 'API_KEY_FOR_BACK'];

  const generateRayId = () => crypto.randomBytes(16).toString('hex'); // 32-символьный идентификатор
  const generateSessionID = () => crypto.randomBytes(16).toString('hex'); // Идентификатор сессии
  const verifyApiKey = (apiKey) => validApiKeys.includes(apiKey); // Пример проверки API-ключа
  const selectBackend = (clientType) => { if (clientType === 'frontend') return 'BACKEND_IP_1'; if (clientType === 'backend') return 'BACKEND_IP_2'; console.log('Для клиента нет необходимого сервера'); return null }; // Пример функции выбора бэкенда

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
    if (!isAuthentic) return res.status(401).send({ error: 'Unauthorized client' });

    // Выбор бэкенда в зависимости от clientType
    const backendIP = selectBackend(clientType); // Функция выбора подходящего бэкенда
    const sessionID = generateSessionID();
    
    // Сохранение сессии в Redis
    await redis.set(sessionID, JSON.stringify({ backendIP, rayId: req.headers['ray-id'], clientType }));

    res.code(201).send({ sessionID, backendIP });
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
  .register(proxy, { upstream: 'http://localhost:5000', prefix: '/v' }) // To dynamic gateway
  .listen({ port: 4000 }, (err, address) => { if (err) throw err });;
};

// fastify.register(cors).addHook('onRequest', async (req, res) => {
//     const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
//     if (!allowedIPs.includes(clientIP)) {
//       const rayId = generateRayId();
//       return res.status(403).send({ error: 'Forbidden', rayId });
//     }

//     if (!req.headers['ray-id']) {
//       req.headers['ray-id'] = generateRayId();
//     }
//   })
//   .post('/authenticate', async (req, res) => {
//     const { clientType, apiKey } = req.body;
//     if (!validApiKeys.includes(apiKey)) {
//       return res.status(401).send({ error: 'Unauthorized' });
//     }

//     const backendIP = selectBackend(clientType);
//     if (!backendIP) {
//       return res.status(400).send({ error: 'Invalid client type' });
//     }

//     const sessionID = generateSessionID();
//     const rayId = req.headers['ray-id'];

//     await redis.set(sessionID, JSON.stringify({ backendIP, rayId, clientType }));

//     res.send({ sessionID, backendIP });
//   })
//   .all('/route/*', async (req, res) => {
//     const sessionID = req.headers['x-session-id'];
//     const storedData = await redis.get(sessionID);

//     if (!storedData) {
//       return res.status(401).send({ error: 'Session not found' });
//     }

//     const { backendIP, rayId, clientType } = JSON.parse(storedData);

//     if (req.headers['ray-id'] !== rayId) {
//       return res.status(403).send({ error: 'Ray-ID mismatch' });
//     }

//     try {
//       const response = await fetch(`http://${backendIP}${req.url}`, {
//         method: req.method,
//         headers: {
//           ...req.headers,
//           'x-service-id': clientType,
//         },
//         body: req.body ? JSON.stringify(req.body) : undefined,
//       });

//       const data = await response.json();
//       res.status(response.status).send(data);
//     } catch (error) {
//       console.error('Error forwarding request:', error);
//       res.status(502).send({ error: 'Bad Gateway' });
//     }
//   });

// function selectBackend(clientType) {
//   const backends = {
//     frontend: '67.21.34.231', // IP бэкенда для фронтенда
//     backend: '67.21.34.232',  // IP другого бэкенда
//   };
//   return backends[clientType];
// }