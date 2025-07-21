const nodemailer = require('nodemailer');
const redis = require('redis');
const crypto = require('crypto');
const otpEmailTemplate = require('./otpTemplate');
const notificationEmailTemplate = require('./notificationTemplate');

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

function hashEmail(email) {
  return crypto.createHash('sha256').update(email).digest('hex').slice(0, 32);
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

  const html = otpEmailTemplate(email, otp, message);

  await transporter.sendMail({
    from: `"BusitPlus OTP" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'รหัส OTP ของคุณ',
    html
  });
}

// --------- Rate Limit ---------
async function canSendOtp(email) {
  const hashedEmail = hashEmail(email);
  const key = `busit_otp:email_rate:${hashedEmail}`;
  const attempts = await redisClient.incr(key);
  if (attempts === 1) await redisClient.expire(key, 3600); // 1 ชั่วโมง
  return attempts <= 8;
}

// --------- Send OTP ---------
async function sendOTP(email, status) {
  if (!await canSendOtp(email)) {
    throw new Error('Exceeded the OTP request limit.');
  }

  let message;
  if (!status) {
    message = 'ดำเนินการทดสอบส่ง OTP';
  } else if (status === 'resetpassword') {
    message = 'ร้องขอรีเซ็ตรหัสผ่าน';
  }

  const otp = generateOTP();
  const hashedOtp = hashOTP(otp);
  const hashedEmail = hashEmail(email);

  await redisClient.set(`busit_otp:${hashedEmail}`, hashedOtp, { EX: 300 }); // 5 นาที
  await sendOTPEmail(email, otp, message);
}

// --------- Verify OTP ---------
async function verifyOTP(email, otpInput) {
  const hashedInput = hashOTP(otpInput);
  const hashedEmail = hashEmail(email);

  const stored = await redisClient.get(`busit_otp:${hashedEmail}`);
  if (!stored) return { success: false, message: 'OTP expired or not found.' };
  if (stored !== hashedInput) return { success: false, message: 'OTP is invalid.' };

  await redisClient.del(`busit_otp:${hashedEmail}`);
  return { success: true, message: 'OTP verification successful' };
}

// --------- Send Notification Email ---------
async function sendEmail(email, subject, message, heading, subheading) {
  const fallbackSubject = (!subject || !subject.trim())
    ? "แจ้งเตือนจากระบบ BusitPlus"
    : subject;

  const fallbackMessage = (!message || !message.trim())
    ? "นี่คืออีเมลสำหรับการทดสอบระบบ"
    : message;

  const fallbackHeading = (!heading || !heading.trim())
    ? "แจ้งเตือนจากระบบ"
    : heading;

  const fallbackSubheading = (!subheading || !subheading.trim())
    ? "การดำเนินการล่าสุดของคุณบนระบบ BusitPlus"
    : subheading;

  const html = notificationEmailTemplate(email, {
    heading: fallbackHeading,
    subheading: fallbackSubheading,
    message: fallbackMessage
  });

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  await transporter.sendMail({
    from: `"BusitPlus Notification" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: fallbackSubject,
    html
  });
}



module.exports = {
  sendOTP,
  verifyOTP,
  sendEmail,
};
