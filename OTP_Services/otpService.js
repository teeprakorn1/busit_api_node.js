const nodemailer = require('nodemailer');
const redis = require('redis');
const crypto = require('crypto');
const otpEmailTemplate = require('./otpTemplate');

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
  .then(() => console.log('Redis connected'))
  .catch(err => console.error('Redis error:', err));

// --------- Utility ---------
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function hashOTP(otp) {
  return crypto.createHash('sha256').update(otp).digest('hex');
}

// --------- Email ---------
async function sendOTPEmail(email, otp, message) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  const html = otpEmailTemplate(email, otp , message);

  await transporter.sendMail({
    from: `"BusitPlus OTP" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'รหัส OTP ของคุณ',
    html
  });
}

// --------- Rate Limit ---------
async function canSendOtp(email) {
  const key = `otp:rate:${email}`;
  const attempts = await redisClient.incr(key);
  if (attempts === 1) await redisClient.expire(key, 3600); // 1 ชม.
  return attempts <= 8;
}

// --------- Send OTP ---------
async function sendOTP(email , status) {
  if (!await canSendOtp(email)) {
    throw new Error('Exceeded the OTP request limit.');
  }
  if(status == null || status === undefined) {
    message = 'ดำเนินการทดสอบส่ง OTP';
  }
  else if (status === 'resetpassword') {
    message = 'ร้องขอรีเซ็ตรหัสผ่าน';
  }

  const otp = generateOTP();
  const hashed = hashOTP(otp);
  await redisClient.set(`otp:${email}`, hashed, { EX: 300 }); // 5 นาที
  await sendOTPEmail(email, otp , message);
}

// --------- Verify OTP ---------
async function verifyOTP(email, otpInput) {
  const hashedInput = hashOTP(otpInput);
  const stored = await redisClient.get(`otp:${email}`);
  if (!stored) return { success: false, message: 'OTP expired or not found.' };
  if (stored !== hashedInput) return { success: false, message: 'OTP is invalid.' };

  await redisClient.del(`otp:${email}`);
  return { success: true, message: 'OTP verification successful' };
}

module.exports = {
  sendOTP,
  verifyOTP
};
