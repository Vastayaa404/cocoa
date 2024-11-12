// Import all dependencies ======================================================================================================================================================================================================>
import Fastify from 'fastify';
import cors from '@fastify/cors';
import crypto from 'crypto';
import cluster from 'cluster';
import { cpus } from 'os';
import { corsConfig, headersConfig } from './conf.core.mjs';
import redis from '../db_redis/models/index.mjs';

import axios from 'axios';
import proxy from '@fastify/http-proxy';

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

  // Проверка допустимого IP-адреса и добавление ray-id
  const fastify = Fastify()
  fastify.addHook('onRequest', headersConfig).register(cors, corsConfig)
  // Верификация запроса и аутентификация клиентов
  .post('/authenticate', async (req, res) => {

    res.header("server", "Cocoa");

    const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (!allowedIPs.includes(clientIP)) return res.status(407).send({ error: 'Unable to load site' });
    
    // Добавление ray-id для новых сессий
    if (!req.headers['ray-id']) req.headers['Ray-id'] = generateRayId();
    res.header("c-ray", req.headers['Ray-id']);


    if (!req.body || !req.body.clientType || !req.body.apiKey) return res.status(428).send({ error: 'Unable to load resource' });
    const { clientType, apiKey } = req.body;  // clientType может быть "frontend" или "backend"
    
    // Проверка API-ключа
    const isAuthentic = verifyApiKey(apiKey);
    if (!isAuthentic) return res.status(422).send({ error: 'Unprocessible connection' });

    // Выбор бэкенда в зависимости от clientType
    const backendIP = selectBackend(clientType); // Функция выбора подходящего бэкенда
    const sessionID = generateSessionID();
    
    // Сохранение сессии в Redis
    await redis.set(sessionID, JSON.stringify({ backendIP, clientType }));

    res.code(201).send({ sessionID, backendIP });
  })
  // Прокси сессий с проверкой ray-id и x-service-id
  .route({
    method: ['GET', 'POST'], url: '/*', handler: async (req, res) => {
      try {
        res.header("server", "Cocoa");
        req.headers['x-forwarded-for'] = '127.0.0.100';
        // req.headers['content-type'] = 'application/json';
        // Извлекаем информацию из сессии
        // const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const clientIP = req.socket.remoteAddress;
        if (!allowedIPs.includes(clientIP)) return res.status(407).send({ error: 'Unable to load site' });
        if (!req.headers['x-session-id']) return res.status(422).send({ error: 'Unprocessible session' });

        const sessionID = req.headers['x-session-id'];
        if (req.headers['x-session-id'] !== sessionID) return res.status(403).send({ error: 'Invalid or mismatched session identifiers' });

        const storedData = await redis.get(sessionID);
        if (!storedData) return res.status(401).send({ error: 'Unauthorized session' });

        const { backendIP, clientType } = JSON.parse(storedData);
  
        console.log(`Forwarding request to backend at http://${backendIP}:5000${req.url}`);
  
        // Проксируем запрос на бэкенд
        const response = await axios({
          method: req.method, // GET или POST
          url: `http://${backendIP}:5000${req.url}`,
          data: req.body, // Передаем тело запроса
          headers: {
            ...req.headers,
            'x-service-id': clientType,
            'host': '127.0.0.10:5000'
          },
        });
  
        // Отправляем ответ клиента обратно
        res.send(response.data);
      } catch (error) {
        console.error('Error forwarding request:', error.message);
        res.status(error.response?.status || 502).send({
          error: error.response?.data || 'Bad Gateway',
        });
      }
    },
  })




  // .route({ method: ['GET', 'POST'], url: '/*', handler: async (req, res) => {

  //   res.header("server", "Cocoa");

  //   const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  //   if (!allowedIPs.includes(clientIP)) return res.status(407).send({ error: 'Unable to load site' });

    // const cocoaIp = '127.0.0.100';
    // req.headers['x-forwarded-for'] = '127.0.0.100';
    // req.headers['content-type'] = 'application/json';

    // if (!req.headers['x-session-id']) return res.status(422).send({ error: 'Unprocessible session' });
    // const sessionID = req.headers['x-session-id'];
    // const storedData = await redis.get(sessionID);
    // if (!storedData) return res.status(401).send({ error: 'Unauthorized session' });

    // const { backendIP, clientType } = JSON.parse(storedData);

    // // Проверка ray-id и x-service-id для цепочки запросов
    // if (req.headers['x-session-id'] !== sessionID) return res.status(403).send({ error: 'Invalid or mismatched session identifiers' });
  //   // Перенаправление на соответствующий бэкенд

  //   console.log(`Forwarding request to: http://${backendIP}:5000${req.url}`);
  //   console.log({ headers: req.headers, body: req.body });

  //   // Пробуем асинхронно отправить запрос, не ожидая ответа
  //   axios({
  //     method: req.method, // GET или POST
  //     url: `http://${backendIP}:5000${req.url}`,
  //     data: req.body,
  //     headers: {
  //       ...req.headers,
  //       'x-service-id': clientType,
  //       'host': `${backendIP}:5000`,
  //     },
  //   })
  //     .then(() => console.log("Request successfully proxied"))
  //     .catch(err => console.error("Error forwarding request", err));

  //   // Немедленно завершение работы прокси и отправка клиенту ответа
  //   res.status(204).send(); // Ответ типа "No Content"


  //   // console.log({ method: req.method, url: req.url, headers: req.headers, query: req.query, body: req.body, params: req.params })

  //   // try {
  //   //   console.log(`Forwarding request to: http://${backendIP}:5000${req.url}`);
  //   //   const response = await axios({
  //   //     method: req.method, // Поддержка GET и POST
  //   //     url: `http://${backendIP}:5000${req.url}`,
  //   //     data: req.body, // Передаем тело напрямую
  //   //     headers: { 
  //   //       ...req.headers,
  //   //       'x-service-id': clientType,
  //   //       'host': `${backendIP}:5000`,
  //   //     },
  //   //   });

  //   //   res.send(response.data);
  //   // } catch (error) {
  //   //   console.error('Error forwarding request:', error.message);
  //   //   res.status(502).send({ error: error.message });
  //   // }
  // }})
  .listen({ port: 4000, host: '127.0.0.100' }, (err, address) => { if (err) throw err });
};