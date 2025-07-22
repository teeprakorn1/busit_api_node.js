const { createLogger, format, transports } = require('winston');
const path = require('path');

const logDir = path.resolve(__dirname, '..', 'logs');

const logFormat = format.printf(({ timestamp, level, message }) => {
  return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
});

const logger = createLogger({
  level: 'info',
  format: format.combine(format.timestamp(), logFormat),
  transports: [
    new transports.Console(),
    new transports.File({ filename: path.join(logDir, 'combined.log') }),
    new transports.File({ filename: path.join(logDir, 'error.log'), level: 'error' })
  ]
});

module.exports = logger;
