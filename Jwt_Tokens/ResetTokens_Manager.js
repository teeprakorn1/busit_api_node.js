const crypto = require('crypto');
const redisClient = require('./../Server_Services/redisClient');

// --------- Utility ---------
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function makeRedisKey(token) {
  return `resetToken:${hashToken(token)}`;
}

async function generateResetToken(email) {
  const token = crypto.randomBytes(32).toString('hex');
  const key = makeRedisKey(token);
  await redisClient.set(key, email, { EX: 600 });
  return token;
}

async function verifyResetToken(email, token) {
  const key = makeRedisKey(token);
  const storedEmail = await redisClient.get(key);
  if (!storedEmail) return false;
  return storedEmail === email;
}

async function deleteResetToken(token) {
  const key = makeRedisKey(token);
  await redisClient.del(key);
}

module.exports = {
  generateResetToken,
  verifyResetToken,
  deleteResetToken,
};
