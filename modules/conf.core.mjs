// Import all dependencies ======================================================================================================================================================================================================>
import { v4 as uuidv4 } from 'uuid';

// Module =======================================================================================================================================================================================================================>
const corsConfig = {
  origin: ['http://localhost:5173', 'http://localhost:3000', 'https://weather-now.ru', 'https://www.weather-now.ru'],
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true
};

const headersConfig = (req, res, next) => {
  req.headers['X-Cocoa-Request-Id'] = uuidv4();
  req.headers['Ray-Id'] = uuidv4();
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  res.header('strict-transport-security', 'max-age=31536000; includeSubDomains; preload');
  res.header('x-content-type-options', 'nosniff');
  res.header('x-frame-options', 'DENY');
  res.header('x-xss-protection', '1; mode=block');
  next();
};

export { corsConfig, headersConfig };