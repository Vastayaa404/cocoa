// Import all dependencies ======================================================================================================================================================================================================>
import Fastify from 'fastify';
import cors from '@fastify/cors';
import crypto from 'crypto';
import cluster from 'cluster';
import { cpus } from 'os';
import { corsConfig, headersConfig } from './conf.core.mjs';
import redis from '../db_redis/models/index.mjs';
import axios from 'axios';

// Module =======================================================================================================================================================================================================================>
if (cluster.isPrimary) {
  const numCPUs = 1 //cpus().length;
  for (let i = 0; i < numCPUs; i++) cluster.fork(); cluster.on('exit', (worker) => console.log(`Warning! Cocoa cluster ${worker.process.pid} died!`)); console.log(`${numCPUs} Cocoa Started`);
} else {
  const allowedIPs = ['FRONTEND', '127.0.0.1', 'BACKEND', 'BACKEND_IP_2', '127.0.0.10'];
  const validApiKeys = ['API_KEY_FOR_FRONT', 'API_KEY_FOR_BACK'];

  const generateRayId = () => crypto.randomBytes(16).toString('hex'); // 32-символьный идентификатор
  const generateSessionID = () => crypto.randomBytes(16).toString('hex'); // Идентификатор сессии
  const verifyApiKey = (apiKey) => validApiKeys.includes(apiKey); // Пример проверки API-ключа
  const selectBackend = (clientType) => { if (clientType === 'frontend') return allowedIPs[4]; if (clientType === 'backend') return 'BACKEND_IP_2'; console.log('Для клиента нет необходимого сервера'); return null }; // Пример функции выбора бэкенда

  const fastify = Fastify()
  fastify.addHook('onRequest', headersConfig).register(cors, corsConfig)
  .post('/authenticate', async (req, res) => {
    res.header("server", "Cocoa");

    // RAY-ID отправляется при любой ошибке в случае проблем с нашей стороной
    // Добавление ray-id для новых сессий. TODO: Пусть RAY-ID будет одинаков для тех запросов, направленных от одного и того же клиента разным сервисам.
    if (!req.headers['ray-id']) req.headers['Ray-id'] = generateRayId();
    res.header("c-ray", req.headers['Ray-id']);

    const clientIP = req.socket.remoteAddress;
    if (req.headers['x-forwarded-for']) return res.status(406).send('Proxying is not allowed. Dirty Query'); // Если новый клиент проксирован, то кто он?
    if (!allowedIPs.includes(clientIP)) return res.status(407).send({ error: 'Unable to load site' });
    
    if (!req.body || !req.body.clientType || !req.body.apiKey) return res.status(428).send({ error: 'Unable to load resource' });
    const { clientType, apiKey } = req.body;  // clientType может быть "frontend" или "backend"
    
    // Проверка API-ключа
    const isAuthentic = verifyApiKey(apiKey);
    if (!isAuthentic) return res.status(422).send({ error: 'Unprocessible connection' });

    // Выбор бэкенда в зависимости от clientType
    const backendIP = selectBackend(clientType); // Функция выбора подходящего бэкенда
    const sessionID = generateSessionID();
    await redis.set(sessionID, JSON.stringify({ backendIP, clientType }));

    res.status(201).send({ sessionID, backendIP }); // TODO: не факт что отправляем, сделаем все под капотом
  })
  .route({
    method: ['GET', 'POST'], url: '/*', handler: async (req, res) => { // TODO: check methods in backend
      try {
        res.header("server", "Cocoa");
        if (!req.headers['ray-id']) req.headers['Ray-id'] = generateRayId();
        res.header("c-ray", req.headers['Ray-id']);
        const clientIP = req.socket.remoteAddress;
        if (!allowedIPs.includes(clientIP)) return res.status(407).send({ error: 'Unable to load site' });
        if (req.headers['x-forwarded-for']) return res.status(406).send('Proxying is not allowed. Dirty Query'); // Если новый клиент проксирован, то кто он?
        if (!req.headers['x-session-id']) return res.status(422).send({ error: 'Unprocessible session' });

        // Извлекаем информацию из сессии
        const sessionID = req.headers['x-session-id'];
        if (req.headers['x-session-id'] !== sessionID) return res.status(403).send({ error: 'Invalid or mismatched session identifiers' });

        const storedData = await redis.get(sessionID);
        if (!storedData) return res.status(401).send({ error: 'Unauthorized session' });
        const { backendIP, clientType } = JSON.parse(storedData);
        
        req.headers['x-forwarded-for'] = '127.0.0.100:4000'; // Сами проксируем, ну а хуле
        // Проксируем запрос на бэкенд
        const response = await axios[req.method.toLowerCase()](`http://${backendIP}:5000${req.url}`, req.body, { headers: { 'x-forwarded-for': req.headers['x-forwarded-for'], 'x-session-id': req.headers['x-session-id'], 'x-service': clientType } })
        const selectedHeaders = ['x-dora-request-id']; // То что надо оставить с бэка
        selectedHeaders.forEach(header => response.headers[header] && res.header(header, response.headers[header]));
        res.send(response.data);
      } catch (e) {
        res.status(e.response?.status || 502).send({ error: e.response?.data || 'Bad Gateway' });
      }
    },
  })
  .listen({ port: 4000, host: '127.0.0.100' }, (err, address) => { if (err) throw err });
};