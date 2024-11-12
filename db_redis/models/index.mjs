// Import all dependencies ======================================================================================================================================================================================================>
import Redis from 'ioredis'; // Redis for weather service

// Module =======================================================================================================================================================================================================================>
const redis = new Redis({
  host: '127.0.0.1',
  port: 6379,
  // password: 'your_password',
});

// redis.keys('*', (err, keys) => console.log(keys));

// redis.on('connect', () => console.log('Redis client connected'));
// redis.on('ready', () => console.log('Redis client is ready to use'));
redis.on('end', () => console.log('Redis connection closed'));
redis.on('error', (err) => console.error('Redis error:', err));
redis.on('reconnecting', () => console.log('Reconnecting to Redis...'));

export default redis;