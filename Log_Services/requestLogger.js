const geoip = require('geoip-lite');
const logger = require('./logger');
const sanitizeLogData = require('./sanitizeLogData');

function requestLogger(req, res, next) {
  const ip =
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress?.replace(/^::ffff:/, '') ||
    req.ip;

  const geo = geoip.lookup(ip) || {};
  const location = geo.city ? `${geo.city}, ${geo.country}` : geo.country || 'Unknown';

  const method = req.method;
  const url = req.originalUrl;
  const userAgent = req.headers['user-agent'];

  logger.info(`→ ${method} ${url} from IP ${ip} (${location}) | UA: ${userAgent}`);

  if (['POST', 'PUT', 'PATCH'].includes(method)) {
    logger.debug(`Request Body: ${JSON.stringify(sanitizeLogData(req.body))}`);
  }

  next();
}

module.exports = requestLogger;
