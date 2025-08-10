const redis = require('redis');

//Redis Connection
const redisClient = redis.createClient({
  username: process.env.REDIS_USER || 'default',
  password: process.env.REDIS_PASS || undefined,
  socket: {
    host: process.env.REDIS_HOST,
    port: Number(process.env.REDIS_PORT),
    tls: process.env.REDIS_TLS === 'true' ? {} : false,
  }
});

redisClient.connect()
  .then(() => console.log('Redis connected successfully'))
  .catch(err => console.error('Redis error:', err));

redisClient.on('error', (err) => {
  console.error('Redis client error:', err);
}
);

module.exports = redisClient;
