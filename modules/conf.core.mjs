// Import all dependencies ======================================================================================================================================================================================================>
import crypto from 'crypto';

// Module =======================================================================================================================================================================================================================>
const generateId = (size) => crypto.randomBytes(size).toString('hex');

const corsConfig = {
  origin: ['http://localhost:5174', 'http://localhost:3000', 'https://weather-now.ru', 'https://www.weather-now.ru'],
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true
};

const headersConfig = (req, res, next) => {
  req.headers['x-cocoa-request-id'] = generateId(32);
  res.header('server', 'Cocoa');
  res.header('access-control-allow-headers', 'Origin, X-Requested-With, Content-Type, Accept');
  res.header('strict-transport-security', 'max-age=31536000; includeSubDomains; preload');
  res.header('x-content-type-options', 'nosniff');
  res.header('x-frame-options', 'DENY');
  res.header('x-xss-protection', '1; mode=block');
  res.header('c-ray', generateId(8));
  next();
};

export { corsConfig, headersConfig };