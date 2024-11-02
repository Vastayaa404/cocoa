// Import all dependencies ======================================================================================================================================================================================================>
import Fastify from 'fastify';
import cors from '@fastify/cors';
import proxy from '@fastify/http-proxy';
import cluster from 'cluster';
import { cpus } from 'os';
import { corsConfig, headersConfig } from './conf.core.mjs';

// Module =======================================================================================================================================================================================================================>
if (cluster.isPrimary) {
  const numCPUs = cpus().length;
  for (let i = 0; i < numCPUs; i++) cluster.fork(); cluster.on('exit', (worker) => console.log(`Warning! Cocoa cluster ${worker.process.pid} died!`)); console.log(`Cocoa Started`)
} else {
  const fastify = Fastify();
  fastify.addHook('onRequest', headersConfig).register(cors, corsConfig)
  .register(proxy, { upstream: 'http://localhost:5000', prefix: '/dynamic' }) // To dynamic gateway
  .listen({ port: 4000 }, (err, address) => { if (err) throw err });
};