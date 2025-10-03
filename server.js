const xss = require('xss');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const express = require('express');
const bcrypt = require('bcrypt');
const moment = require('moment');
const validator = require('validator');
const fileType = require('file-type');
const cookieParser = require("cookie-parser");
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const sharp = require('sharp');

const YAML = require('yamljs');
const swaggerUi = require('swagger-ui-express');

require('dotenv').config();

const db = require('./Server_Services/databaseClient');
const requestLogger = require('./Log_Services/requestLogger');
const RateLimiter = require('./Rate_Limiter/LimitTime_Login');
const GenerateTokens = require('./Jwt_Tokens/Tokens_Generator');
const VerifyTokens = require('./Jwt_Tokens/Tokens_Verification');
const { sendOTP, verifyOTP, sendEmail } = require('./OTP_Services/otpService');
const { generateResetToken, verifyResetToken, deleteResetToken } = require('./Jwt_Tokens/ResetTokens_Manager');
const VerifyTokens_Website = require('./Jwt_Tokens/Tokens_Verification_Website');

const app = express();
const saltRounds = 14;
const isProduction = process.env.ENV_MODE === "1";

const allowedOrigins = [
  process.env.WEB_CLIENT_URL_DEV,
  process.env.WEB_CLIENT_URL_PROD,
  process.env.WEB_CLIENT_URL_PROD_2,
  null
];

const uploadDir = path.join(__dirname, 'images');
const uploadDir_Profile = path.join(__dirname, 'images/users-profile-images');
const uploadDir_Certificate = path.join(__dirname, 'images/certificate-files');
const uploadDir_Activity = path.join(__dirname, 'images/activities-images');

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

if (!fs.existsSync(uploadDir_Profile)) {
  fs.mkdirSync(uploadDir_Profile, { recursive: true });
}

if (!fs.existsSync(uploadDir_Certificate)) {
  fs.mkdirSync(uploadDir_Certificate, { recursive: true });
}

if (!fs.existsSync(uploadDir_Activity)) {
  fs.mkdirSync(uploadDir_Activity, { recursive: true });
}

// Multer configuration
const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'image/pjpeg', 'application/octet-stream'];

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('ประเภทไฟล์ไม่ถูกต้อง'), false);
    }
    cb(null, true);
  }
});

const certificateUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg'];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('ประเภทไฟล์ไม่ถูกต้อง กรุณาอัปโลดไฟล์ JPG หรือ PNG'), false);
    }
    cb(null, true);
  }
});

const activityUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg'];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('ประเภทไฟล์ไม่ถูกต้อง กรุณาอัปโลดไฟล์ JPG หรือ PNG'), false);
    }
    cb(null, true);
  }
});

function sanitizeRequest(req, res, next) {
  for (let prop in req.body) {
    if (typeof req.body[prop] === 'string') {
      req.body[prop] = xss(req.body[prop]);
    }
  }

  for (let prop in req.query) {
    if (typeof req.query[prop] === 'string') {
      req.query[prop] = xss(req.query[prop]);
    }
  }

  for (let prop in req.params) {
    if (typeof req.params[prop] === 'string') {
      req.params[prop] = xss(req.params[prop]);
    }
  }

  next();
}

app.use(express.json());
app.use(sanitizeRequest);
app.use(requestLogger);
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());


const skipHelmetForImages = (req, res, next) => {
  if (req.path.startsWith('/api/images/')) {
    return next();
  }
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://unpkg.com"],
        "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
        "img-src": ["'self'", "data:", "blob:", "http://localhost:3000"],
        "font-src": ["'self'", "https://fonts.gstatic.com"],
        "connect-src": [
          "'self'",
          process.env.WEB_CLIENT_URL_DEV,
          process.env.WEB_CLIENT_URL_PROD,
          process.env.WEB_CLIENT_URL_PROD_2
        ],
        "frame-src": ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })(req, res, next);
};

app.use(skipHelmetForImages);

// CORS Configuration
app.use(cors({
  origin: (origin, callback) => {
    console.log('CORS origin:', origin);
    if (!origin) return callback(null, true);
    if (isProduction) {
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.log('Blocked by CORS:', origin);
        callback(new Error('Not allowed by CORS'));
      }
    } else {
      callback(null, true);
    }
  },
  credentials: true,
}));

////////////////////////////////// SWAGGER CONFIG ///////////////////////////////////////
const swaggerDocument = YAML.load('./swagger.yaml');

if (isProduction) {
  app.use('/api-docs', (req, res) => {
    res.status(403).json({ message: 'Swagger UI is disabled in production' });
  });
} else {
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, { explorer: true }));
}

////////////////////////////////// TEST API ///////////////////////////////////////
// Server Test
app.get('/api/health', (req, res) => {
  res.json({ message: "Server is Running.", status: true });
});

// Encrypt Test
app.post('/api/test/encrypt', RateLimiter(0.5 * 60 * 1000, 15), async (req, res) => {
  if (isProduction) {
    return res.status(403).json({ message: 'This API is not allowed in production.', status: false });
  }

  try {
    const { password } = req.body || {};
    if (!password) {
      return res.status(400).json({ message: 'Password is required.', status: false });
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    res.json({ message: hashedPassword, status: true });
  } catch (error) {
    console.error('Error encrypting password:', error);
    res.status(500).json({ message: 'Internal server error.', status: false });
  }
});

// Decrypt Test
app.post('/api/test/decrypt', RateLimiter(0.5 * 60 * 1000, 15), async (req, res) => {
  if (isProduction) {
    return res.status(403).json({ message: 'This API is not allowed in production.', status: false });
  }

  try {
    const { password, hash } = req.body || {};
    if (!password || !hash) {
      return res.status(400).json({ message: 'Password and hash are required.', status: false });
    }
    const isMatch = await bcrypt.compare(password, hash);
    if (isMatch) {
      return res.json({ message: 'The password is correct.', status: true });
    } else {
      return res.status(200).json({ message: 'The password is incorrect.', status: false });
    }
  } catch (error) {
    console.error('Error comparing password:', error);
    res.status(500).json({ message: 'Internal server error.', status: false });
  }
});

//Send OTP Test
app.post('/api/test/sendotp', async (req, res) => {
  if (isProduction) {
    return res.status(403).json({ message: 'This API is not allowed in production.', status: false });
  }

  const { email } = req.body || {};

  if (!email || typeof email !== 'string') {
    return res.status(400).json({ message: 'Please provide a valid email address.', status: false });
  }

  try {
    await sendOTP(email);
    res.status(200).json({ message: 'OTP sent successfully.', status: true });
  } catch (error) {
    if (error.message.includes('Exceeded the OTP request limit.')) {
      return res.status(429).json({ message: error.message, status: false });
    }
    res.status(500).json({ message: 'An error occurred while sending OTP.', status: false });
  }
});

//Verify OTP Test
app.post('/api/test/verifyotp', async (req, res) => {
  if (isProduction) {
    return res.status(403).json({ message: 'This API is not allowed in production.', status: false });
  }

  const { email, otp } = req.body || {};
  if (!email || !otp || typeof email !== 'string' || typeof otp !== 'string') {
    return res.status(400).json({ message: 'Please provide a valid email and OTP.', status: false });
  }
  try {
    const result = await verifyOTP(email, otp);
    if (result.success) {
      return res.status(200).json({ message: result.message, status: true });
    } else {
      return res.status(400).json({ message: result.message, status: false });
    }
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ message: 'An error occurred while sending email.', status: false });
  }
});

//Send Email Test
app.post('/api/test/sendemail', async (req, res) => {
  if (isProduction) {
    return res.status(403).json({ message: 'This API is not allowed in production.', status: false });
  }

  const { email } = req.body || {};

  if (!email || typeof email !== 'string') {
    return res.status(400).json({ message: 'Please provide a valid email address.', status: false });
  }

  try {
    await sendEmail(email);
    res.status(200).json({ message: 'OTP sent successfully.', status: true });
  } catch (error) {
    res.status(500).json({ message: 'An error occurred while sending email.', status: false });
  }
});

////////////////////////////////// Tokens API ///////////////////////////////////////
// Verify Token
app.post('/api/verifyToken', RateLimiter(0.5 * 60 * 1000, 15), VerifyTokens, (req, res) => {
  const userData = req.user;
  if (userData) {
    return res.status(200).json({
      Users_ID: userData.Users_ID,
      Users_Email: userData.Users_Email,
      Users_Username: userData.Users_Username,
      UsersType_ID: userData.UsersType_ID,
      Users_Type: userData.Users_Type,
      Login_Type: userData.Login_Type,
      message: 'Token is valid.',
      status: true,
    });
  }
  return res.status(402).json({ message: 'Invalid Token.', status: false });
});

// Verify Token for Website
app.post('/api/verifyToken-website', RateLimiter(0.5 * 60 * 1000, 15), VerifyTokens_Website, (req, res) => {
  const userData = req.user;

  if (!userData) {
    return res.status(401).json({ message: 'Invalid token.', status: false });
  }

  return res.status(200).json({
    Users_ID: userData.Users_ID,
    Users_Email: userData.Users_Email,
    Users_Username: userData.Users_Username,
    UsersType_ID: userData.UsersType_ID,
    Users_Type: userData.Users_Type,
    Login_Type: userData.Login_Type,
    message: 'Token is valid.',
    status: true,
  });
});

////////////////////////////////// System API ///////////////////////////////////////
//reset password by password API
app.post('/api/system/resetpassword', RateLimiter(0.5 * 60 * 1000, 12), async (req, res) => {
  const { Users_Email, Current_Password, New_Password } = req.body || {};
  if (!Users_Email || !Current_Password || !New_Password ||
    typeof Users_Email !== 'string' || typeof Current_Password !== 'string' || typeof New_Password !== 'string') {
    return res.status(400).json({ message: 'Please fill in the correct parameters as required.', status: false });
  }

  if (!validator.isEmail(Users_Email)) {
    return res.status(400).json({ message: 'Please provide a valid email address.', status: false });
  }

  try {
    const sql = "SELECT Users_ID, Users_Password FROM users WHERE Users_Email = ? AND Users_IsActive = 1";
    db.query(sql, [Users_Email], async (err, result) => {
      if (err) {
        console.error('Database error (reset password)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length === 0) {
        return res.status(404).json({ message: 'User not found.', status: false });
      }

      const user = result[0];
      const passwordMatch = await bcrypt.compare(Current_Password, user.Users_Password);
      if (!passwordMatch) {
        return res.status(401).json({ message: 'Current password is incorrect.', status: false });
      }

      const hashedPassword = await bcrypt.hash(New_Password, saltRounds);
      const updateSql = "UPDATE users SET Users_Password = ? WHERE Users_ID = ?";
      db.query(updateSql, [hashedPassword, user.Users_ID], (err, updateResult) => {
        if (err) {
          console.error('Database error (update password)', err);
          return res.status(500).json({ message: 'An error occurred while updating the password.', status: false });
        }

        if (updateResult.affectedRows > 0) {
          return res.status(200).json({ message: 'Password reset successfully.', status: true });
        } else {
          return res.status(500).json({ message: 'Password reset failed.', status: false });
        }
      });
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Reset Password with OTP Request
app.post('/api/system/resetpassword-request-otp', async (req, res) => {
  const { Users_Email } = req.body || {};

  if (!Users_Email || typeof Users_Email !== 'string' || !validator.isEmail(Users_Email)) {
    return res.status(400).json({ message: 'Please provide a valid email address.', status: false });
  }

  try {
    const sql = "SELECT Users_ID FROM users WHERE Users_Email = ? AND Users_IsActive = 1";
    db.query(sql, [Users_Email], async (err, result) => {
      if (err) {
        console.error('Database error (request OTP)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.length === 0) {
        return res.status(200).json({ message: 'Unable to send OTP, please try again later.', status: false });
      }

      try {
        await sendOTP(Users_Email, 'resetpassword');
        return res.status(200).json({ message: 'OTP has been sent to your email.', status: true });
      } catch (sendErr) {
        console.error('Send OTP error:', sendErr);
        return res.status(500).json({ message: 'Failed to send OTP.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error (request OTP):', error);
    return res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Reset Password with OTP Verification
app.post('/api/system/resetpassword-verify-otp', async (req, res) => {
  const { Users_Email, otp } = req.body || {};

  if (!Users_Email || !otp || typeof Users_Email !== 'string' || typeof otp !== 'string') {
    return res.status(400).json({ message: 'Please provide all required fields.', status: false });
  }

  if (!validator.isEmail(Users_Email)) {
    return res.status(400).json({ message: 'Please provide a valid email address.', status: false });
  }

  try {
    const otpResult = await verifyOTP(Users_Email, otp);
    if (!otpResult.success) {
      return res.status(400).json({ message: otpResult.message, status: false });
    }

    const resetToken = await generateResetToken(Users_Email);
    if (!resetToken) {
      return res.status(500).json({ message: 'Failed to generate reset token.', status: false });
    }

    return res.status(200).json({ token: resetToken, message: 'OTP verified successfully. Use the token to reset your password.', status: true });

  } catch (error) {
    console.error('Catch error (verify otp password)', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Reset Password with ResetToken
app.post('/api/system/resetpassword-resettoken', RateLimiter(0.5 * 60 * 1000, 12), async (req, res) => {
  const { Users_Email, Users_Password, token } = req.body || {};
  if (!Users_Email || !Users_Password || !token ||
    typeof Users_Email !== 'string' || typeof Users_Password !== 'string' || typeof token !== 'string') {
    return res.status(400).json({ message: 'Please fill in the correct parameters as required.', status: false });
  }
  if (!validator.isEmail(Users_Email)) {
    return res.status(400).json({ message: 'Please provide a valid email address.', status: false });
  }

  if (Users_Password.length < 8 || Users_Password.length > 63) {
    return res.status(400).json({ message: 'New password must be between 8 and 63 characters.', status: false });
  }

  try {
    const isValidToken = await verifyResetToken(Users_Email, token);
    if (!isValidToken) {
      return res.status(400).json({ message: 'Invalid or expired reset token.', status: false });
    }
    const sql = "SELECT Users_ID FROM users WHERE Users_Email = ? AND Users_IsActive = 1";
    db.query(sql, [Users_Email], async (err, result) => {
      if (err) {
        console.error('Database error (reset password)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length === 0) {
        return res.status(404).json({ message: 'User not found.', status: false });
      }

      const user = result[0];
      const hashedPassword = await bcrypt.hash(Users_Password, saltRounds);
      const updateSql = "UPDATE users SET Users_Password = ? WHERE Users_ID = ?";
      db.query(updateSql, [hashedPassword, user.Users_ID], async (err, updateResult) => {
        if (err) {
          console.error('Database error (update password)', err);
          return res.status(500).json({ message: 'An error occurred on the server.', status: false });
        }

        if (updateResult.affectedRows > 0) {
          await deleteResetToken(token);
          res.status(200).json({ message: 'Password reset successfully.', status: true });
          const notifyMsg = 'บัญชีของคุณได้รับการอัปเดตรหัสผ่านเรียบร้อยแล้ว หากคุณไม่ได้ทำรายการนี้ โปรดติดต่อฝ่ายสนับสนุนโดยด่วน';
          try {
            await sendEmail(Users_Email, "แจ้งเตือน: คุณได้เปลี่ยนรหัสผ่าน", "หากไม่ใช่คุณ กรุณาติดต่อทีมงานด่วน", "เปลี่ยนรหัสผ่านสำเร็จ", notifyMsg);

          } catch (emailError) {
            console.error('Error sending notification email:', emailError);
          }
        } else {
          return res.status(500).json({ message: 'Password reset failed.', status: false });
        }
      });
    });
  } catch (error) {
    console.error('Catch error (reset password)', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

////////////////////////////////// Authentication API ///////////////////////////////////////
//API Login Application
app.post('/api/login/application', RateLimiter(1 * 60 * 1000, 5), async (req, res) => {
  let { Users_Email, Users_Password } = req.body || {};

  if (!Users_Email || !Users_Password ||
    typeof Users_Email !== 'string' || typeof Users_Password !== 'string') {
    return res.status(400).json({ message: 'Please fill in the correct parameters as required.', status: false });
  }

  Users_Email = xss(validator.escape(Users_Email));
  Users_Password = xss(Users_Password)

  try {
    const sql = "SELECT Users_ID, Users_Email, Users_Username, Users_Password, Users_Type " +
      "FROM users WHERE (Users_Username = ? OR Users_Email = ?) AND (Users_Type = 'teacher' OR Users_Type = 'student') AND Users_IsActive = 1";
    db.query(sql, [Users_Email, Users_Email], async (err, result) => {
      if (err) {
        console.error('Database error (users)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length === 0) {
        return res.status(401).json({ message: "Email or password is incorrect.", status: false });
      }

      const user = result[0];
      const passwordMatch = await bcrypt.compare(Users_Password, user.Users_Password);
      if (!passwordMatch) {
        return res.status(401).json({ message: "Email or password is incorrect.", status: false });
      }

      // Check Users_Type
      let sql_users_type, users_type_name_id;
      if (user.Users_Type === 'student') {
        sql_users_type = "SELECT Student_ID FROM student WHERE Users_ID = ?";
        users_type_name_id = 'Student_ID';
      } else if (user.Users_Type === 'teacher') {
        sql_users_type = "SELECT Teacher_ID FROM teacher WHERE Users_ID = ?";
        users_type_name_id = 'Teacher_ID';
      } else {
        return res.status(400).json({ message: 'Invalid user type.', status: false });
      }

      db.query(sql_users_type, [user.Users_ID], async (err, result_users_type) => {
        if (err) {
          console.error('Database error (user type)', err);
          return res.status(500).json({ message: 'An error occurred on the server.', status: false });
        }

        if (result_users_type.length === 0) {
          return res.status(404).json({ message: 'User type details not found.', status: false });
        }

        const userType = result_users_type[0];
        const UsersType_ID = userType[users_type_name_id];

        const token = GenerateTokens(user.Users_ID,
          user.Users_Email, user.Users_Username, UsersType_ID, user.Users_Type, 'application');

        const responseData = {
          token: token,
          message: "The login was successful.",
          status: true
        };
        res.status(200).json(responseData);
      });
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Login Web Admin
app.post('/api/login/website', RateLimiter(1 * 60 * 1000, 5), async (req, res) => {
  let { Users_Email, Users_Password } = req.body || {};

  if (!Users_Email || !Users_Password ||
    typeof Users_Email !== 'string' || typeof Users_Password !== 'string') {
    return res.status(400).json({ message: 'Please fill in the correct parameters as required.', status: false });
  }

  Users_Email = xss(validator.escape(Users_Email));
  Users_Password = xss(Users_Password);

  try {
    const sql = `SELECT Users_ID, Users_Email, Users_Username, Users_Password, Users_Type
      FROM users WHERE (Users_Username = ? OR Users_Email = ?) AND (Users_Type = 'teacher' OR Users_Type = 'staff') AND Users_IsActive = 1`;

    db.query(sql, [Users_Email, Users_Email], async (err, result) => {
      if (err) {
        console.error('Database error (users)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length === 0) {
        return res.status(401).json({ message: "Email or password is incorrect.", status: false });
      }

      const user = result[0];
      const passwordMatch = await bcrypt.compare(Users_Password, user.Users_Password);
      if (!passwordMatch) {
        return res.status(401).json({ message: "Email or password is incorrect.", status: false });
      }

      // Check Users_Type
      let sql_users_type, users_type_name_id;
      if (user.Users_Type === 'teacher') {
        sql_users_type = "SELECT Teacher_ID FROM teacher WHERE Users_ID = ?";
        users_type_name_id = 'Teacher_ID';
      } else if (user.Users_Type === 'staff') {
        sql_users_type = "SELECT Staff_ID FROM staff WHERE Users_ID = ?";
        users_type_name_id = 'Staff_ID';
      } else {
        return res.status(400).json({ message: 'Invalid user type.', status: false });
      }

      db.query(sql_users_type, [user.Users_ID], async (err, result_users_type) => {
        if (err) {
          console.error('Database error (user type)', err);
          return res.status(500).json({ message: 'An error occurred on the server.', status: false });
        }

        if (result_users_type.length === 0) {
          return res.status(404).json({ message: 'User type details not found.', status: false });
        }

        const userType = result_users_type[0];
        const UsersType_ID = userType[users_type_name_id];

        const token = GenerateTokens(
          user.Users_ID,
          user.Users_Email,
          user.Users_Username,
          UsersType_ID,
          user.Users_Type,
          'website'
        );

        res.cookie("token", token, {
          httpOnly: true,
          secure: isProduction,
          sameSite: isProduction ? "None" : "Lax",
          domain: isProduction ? process.env.COOKIE_DOMAIN_PROD : undefined,
          maxAge: 60 * 60 * 1000
        });

        res.status(200).json({
          message: "The login was successful.",
          status: true
        });
      });
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Logout Web Admin
app.post('/api/logout-website', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'None' : 'Lax',
    domain: isProduction ? process.env.COOKIE_DOMAIN_PROD : undefined
  });
  res.status(200).json({ message: 'Logged out successfully.', status: true });
});

////////////////////////////////// Timestamp API ///////////////////////////////////////
//API Timestamp Insert for Application
app.post('/api/timestamp/insert', RateLimiter(0.5 * 60 * 1000, 15), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const usersID = userData.Users_ID;

  const { Timestamp_Name, TimestampType_ID } = req.body || {};

  const Timestamp_IP_Address = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || null;
  const Timestamp_UserAgent = req.headers['user-agent'] || null;

  if (!Timestamp_Name || !usersID || !TimestampType_ID) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }
  if (typeof usersID !== 'number' || typeof TimestampType_ID !== 'number') {
    return res.status(400).json({ message: "Users_ID and TimestampType_ID must be numbers.", status: false });
  }
  if (typeof Timestamp_Name !== 'string') {
    return res.status(400).json({ message: "Timestamp_Name must be a string.", status: false });
  }

  try {
    const sql = `
      INSERT INTO timestamp (Timestamp_Name, Timestamp_IP_Address, Timestamp_UserAgent, Users_ID, TimestampType_ID)
      VALUES (?, ?, ?, ?, ?)
    `;
    db.query(sql, [Timestamp_Name, Timestamp_IP_Address, Timestamp_UserAgent, usersID, TimestampType_ID], (err, result) => {
      if (err) {
        console.error('Database error (timestamp)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.affectedRows > 0) {
        return res.status(200).json({ message: 'Timestamp inserted successfully.', status: true });
      } else {
        return res.status(501).json({ message: 'Timestamp not inserted.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API Timestamp Insert for Website
app.post('/api/timestamp/website/insert', RateLimiter(0.5 * 60 * 1000, 15), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const usersID = userData.Users_ID;

  const { Timestamp_Name, TimestampType_ID } = req.body || {};

  const Timestamp_IP_Address = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || null;
  const Timestamp_UserAgent = req.headers['user-agent'] || null;

  if (!Timestamp_Name || !usersID || !TimestampType_ID) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }
  if (typeof usersID !== 'number' || typeof TimestampType_ID !== 'number') {
    return res.status(400).json({ message: "Users_ID and TimestampType_ID must be numbers.", status: false });
  }
  if (typeof Timestamp_Name !== 'string') {
    return res.status(400).json({ message: "Timestamp_Name must be a string.", status: false });
  }

  try {
    const sql = `
      INSERT INTO timestamp (Timestamp_Name, Timestamp_IP_Address, Timestamp_UserAgent, Users_ID, TimestampType_ID)
      VALUES (?, ?, ?, ?, ?)
    `;
    db.query(sql, [Timestamp_Name, Timestamp_IP_Address, Timestamp_UserAgent, usersID, TimestampType_ID], (err, result) => {
      if (err) {
        console.error('Database error (timestamp)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.affectedRows > 0) {
        return res.status(200).json({ message: 'Timestamp inserted successfully.', status: true });
      } else {
        return res.status(501).json({ message: 'Timestamp not inserted.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API Timestamp Get All Data website admin
app.get('/api/timestamp/get', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  try {
    const sql = `SELECT ts.Timestamp_ID, ts.Timestamp_RegisTime, ts.Timestamp_Name ,ts.Timestamp_UserAgent ,
      ts.Timestamp_IP_Address ,ts.TimestampType_ID, ts.Users_ID, u.Users_Email, u.Users_Type ,tst.TimestampType_Name FROM
      (((timestamp ts INNER JOIN timestamptype tst ON ts.TimestampType_ID = tst.TimestampType_ID ) INNER JOIN users u ON ts.Users_ID = u.Users_ID )) 
      WHERE ts.Timestamp_RegisTime >= CURDATE() - INTERVAL 90 DAY ORDER BY ts.Timestamp_RegisTime DESC`;
    db.query(sql, (err, result) => {
      if (err) {
        console.error('Database error (timestamp)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.length > 0) {
        return res.status(200).json({
          message: "Get timestamps successfully.",
          status: true,
          data: result
        });

      } else {
        return res.status(404).json({ message: 'No timestamps found for this type.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API Timestamp Get by Users_ID of Website
app.get('/api/timestamp/get/users/:Users_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens_Website, async (req, res) => {
  const Users_ID = req.params.Users_ID;
  const userData = req.user;
  const AdminID = userData.Users_ID;
  const Login_Type = userData?.Login_Type;
  const Users_Type = userData?.Users_Type;

  if (!AdminID || typeof AdminID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Paramiter.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed in the application.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed for staff users.", status: false });
  }

  if (!Users_ID) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  try {
    const sql = "SELECT ts.Timestamp_ID, ts.Timestamp_Name, ts.Users_ID, ts.Timestamp_RegisTime, ts.TimestampType_ID, tst.TimestampType_Name " +
      "FROM (timestamp ts INNER JOIN timestamptype tst ON ts.TimestampType_ID = tst.TimestampType_ID ) WHERE Users_ID = ? ORDER BY ts.Timestamp_RegisTime DESC";
    db.query(sql, [Users_ID], (err, result) => {
      if (err) {
        console.error('Database error (timestamp)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.length > 0) {
        const ResultData = result;
        return res.status(200).json(ResultData);
      } else {
        return res.status(404).json({ message: 'No timestamps found for this user.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API Timestamp Get by TimestampType_ID
app.get('/api/timestamp/get/type/:TimestampType_ID', RateLimiter(0.5 * 60 * 1000, 12), async (req, res) => {
  const TimestampType_ID = req.params.TimestampType_ID;

  if (!TimestampType_ID) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  try {
    const sql = "SELECT ts.Timestamp_ID, ts.Users_ID, ts.Timestamp_RegisTime, ts.TimestampType_ID, tst.TimestampType_Name " +
      "FROM (timestamp ts INNER JOIN timestamptype tst ON ts.TimestampType_ID = tst.TimestampType_ID ) WHERE tst.TimestampType_ID = ? ORDER BY ts.Timestamp_RegisTime DESC";
    db.query(sql, [TimestampType_ID], (err, result) => {
      if (err) {
        console.error('Database error (timestamp)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.length > 0) {
        const ResultData = result;
        return res.status(200).json(ResultData);
      } else {
        return res.status(404).json({ message: 'No timestamps found for this type.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API Timestamp Get by TimestampType_ID
app.get('/api/timestamp/get/type/:TimestampType_ID', RateLimiter(0.5 * 60 * 1000, 12), async (req, res) => {
  // เพิ่ม cache control
  res.set({
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'
  });

  const TimestampType_ID = req.params.TimestampType_ID;

  if (!TimestampType_ID) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  try {
    const sql = "SELECT ts.Timestamp_ID, ts.Users_ID, ts.Timestamp_RegisTime, ts.TimestampType_ID, tst.TimestampType_Name " +
      "FROM (timestamp ts INNER JOIN timestamptype tst ON ts.TimestampType_ID = tst.TimestampType_ID ) WHERE tst.TimestampType_ID = ? ORDER BY ts.Timestamp_RegisTime DESC";
    db.query(sql, [TimestampType_ID], (err, result) => {
      if (err) {
        console.error('Database error (timestamp)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.length > 0) {
        const ResultData = result;
        return res.status(200).json(ResultData);
      } else {
        return res.status(404).json({ message: 'No timestamps found for this type.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API Timestamp users Get by Search of Website
app.get('/api/users/search', RateLimiter(0.5 * 60 * 1000, 10), VerifyTokens_Website, async (req, res) => {
  res.set({
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'
  });

  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  const { email, ip } = req.query;

  if (!email && !ip) {
    return res.status(400).json({ message: "Please provide either email or ip parameter.", status: false });
  }

  try {
    let sql;
    let searchParam;

    if (email) {
      sql = `SELECT u.Users_ID, u.Users_Email, u.Users_Type, CASE WHEN u.Users_Type = 'student' THEN
        CONCAT(s.Student_FirstName, ' ', s.Student_LastName) WHEN u.Users_Type = 'teacher' THEN CONCAT(t.Teacher_FirstName, ' ', t.Teacher_LastName)
        WHEN u.Users_Type = 'staff' THEN CONCAT(st.Staff_FirstName, ' ', st.Staff_LastName) END as Full_Name FROM users u LEFT JOIN student s ON u.Users_ID = s.Users_ID
        LEFT JOIN teacher t ON u.Users_ID = t.Users_ID LEFT JOIN staff st ON u.Users_ID = st.Users_ID WHERE u.Users_Email = ?`;
      searchParam = email;
    } else if (ip) {
      sql = `SELECT DISTINCT u.Users_ID, u.Users_Email, u.Users_Type, CASE WHEN u.Users_Type = 'student' THEN 
        CONCAT(s.Student_FirstName, ' ', s.Student_LastName) WHEN u.Users_Type = 'teacher' THEN CONCAT(t.Teacher_FirstName, ' ', t.Teacher_LastName)
        WHEN u.Users_Type = 'staff' THEN CONCAT(st.Staff_FirstName, ' ', st.Staff_LastName) END as Full_Name FROM users u LEFT JOIN student s ON u.Users_ID = s.Users_ID
        LEFT JOIN teacher t ON u.Users_ID = t.Users_ID LEFT JOIN staff st ON u.Users_ID = st.Users_ID INNER JOIN timestamp ts ON u.Users_ID = ts.Users_ID
        WHERE ts.Timestamp_IP_Address = ?`;
      searchParam = ip;
    }

    db.query(sql, [searchParam], (err, result) => {
      if (err) {
        console.error('Database error (user search)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length > 0) {
        return res.status(200).json({
          message: "User found successfully.",
          status: true,
          user: result[0],
          totalUsers: result.length
        });
      } else {
        return res.status(404).json({
          message: `No user found for this ${email ? 'email' : 'IP address'}.`,
          status: false
        });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API Timestamp Get by Search of Website
app.get('/api/timestamp/search', RateLimiter(0.5 * 60 * 1000, 10), VerifyTokens_Website, async (req, res) => {
  res.set({
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'
  });

  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  const { email, ip, user_type, event_type, date_from, date_to, limit = 100 } = req.query;
  try {
    let sql = `SELECT ts.Timestamp_ID, ts.Timestamp_RegisTime, ts.Timestamp_Name, ts.Timestamp_UserAgent, 
      ts.Timestamp_IP_Address, ts.TimestampType_ID, ts.Users_ID, u.Users_Email, u.Users_Type, tst.TimestampType_Name FROM 
      timestamp ts INNER JOIN timestamptype tst ON ts.TimestampType_ID = tst.TimestampType_ID INNER JOIN users u ON ts.Users_ID = u.Users_ID WHERE 1=1`;

    const params = [];

    if (email) {
      sql += ' AND u.Users_Email = ?';
      params.push(email);
    }

    if (ip) {
      sql += ' AND ts.Timestamp_IP_Address = ?';
      params.push(ip);
    }

    if (user_type) {
      sql += ' AND u.Users_Type = ?';
      params.push(user_type);
    }

    if (event_type) {
      sql += ' AND tst.TimestampType_Name = ?';
      params.push(event_type);
    }

    if (date_from) {
      sql += ' AND DATE(ts.Timestamp_RegisTime) >= ?';
      params.push(date_from);
    }

    if (date_to) {
      sql += ' AND DATE(ts.Timestamp_RegisTime) <= ?';
      params.push(date_to);
    }

    sql += ' AND ts.Timestamp_RegisTime >= CURDATE() - INTERVAL 90 DAY';
    sql += ' ORDER BY ts.Timestamp_RegisTime DESC LIMIT ?';
    params.push(parseInt(limit));

    db.query(sql, params, (err, result) => {
      if (err) {
        console.error('Database error (timestamp search)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      return res.status(200).json({
        message: "Search completed successfully.",
        status: true,
        data: result,
        total: result.length,
        searchCriteria: {
          email, ip, user_type, event_type, date_from, date_to, limit
        }
      });
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});


//////////////////////////////////Admin DataEdit API///////////////////////////////////////
//API DataEdit Insert for Website
app.post('/api/dataedit/website/insert', RateLimiter(0.5 * 60 * 1000, 15), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  const { DataEdit_ThisId, DataEdit_Name, DataEdit_SourceTable, DataEditType_ID } = req.body || {};
  const DataEdit_IP_Address = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || null;
  const DataEdit_UserAgent = req.headers['user-agent'] || null;
  const usersID = userData.Users_ID;

  if (!DataEdit_ThisId || !DataEdit_SourceTable || !DataEditType_ID || !usersID) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }
  if (typeof DataEdit_ThisId !== 'number' || typeof DataEditType_ID !== 'number' || typeof usersID !== 'number') {
    return res.status(400).json({ message: "DataEdit_ThisId, DataEditType_ID and Users_ID must be numbers.", status: false });
  }
  if (typeof DataEdit_SourceTable !== 'string') {
    return res.status(400).json({ message: "DataEdit_SourceTable must be a string.", status: false });
  }
  if (DataEdit_Name && typeof DataEdit_Name !== 'string') {
    return res.status(400).json({ message: "DataEdit_Name must be a string.", status: false });
  }

  const allowedSourceTables = ['Student', 'Teacher', 'Staff', 'Users', 'Activity'];
  if (!allowedSourceTables.includes(DataEdit_SourceTable)) {
    return res.status(400).json({
      message: `Invalid DataEdit_SourceTable. Allowed values: ${allowedSourceTables.join(', ')}`,
      status: false
    });
  }

  try {
    const getStaffSql = `SELECT Staff_ID FROM staff WHERE Users_ID = ?`;
    db.query(getStaffSql, [usersID], (err, staffResult) => {
      if (err) {
        console.error('Database error (get staff)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (staffResult.length === 0) {
        return res.status(404).json({ message: 'Staff not found.', status: false });
      }

      const staffID = staffResult[0].Staff_ID;

      const sql = `INSERT INTO dataedit (DataEdit_ThisId, DataEdit_Name, DataEdit_SourceTable, 
        DataEdit_IP_Address, DataEdit_UserAgent, Staff_ID, DataEditType_ID) VALUES (?, ?, ?, ?, ?, ?, ?)`;
      db.query(sql, [DataEdit_ThisId, DataEdit_Name, DataEdit_SourceTable, DataEdit_IP_Address, DataEdit_UserAgent, staffID, DataEditType_ID], (err, result) => {
        if (err) {
          console.error('Database error (dataedit)', err);
          return res.status(500).json({ message: 'An error occurred on the server.', status: false });
        }
        if (result.affectedRows > 0) {
          return res.status(200).json({ message: 'DataEdit inserted successfully.', status: true });
        } else {
          return res.status(501).json({ message: 'DataEdit not inserted.', status: false });
        }
      });
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API DataEdit Get All Data website admin
app.get('/api/dataedit/get', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  try {
    const sql = `SELECT de.DataEdit_ID, de.DataEdit_ThisId, de.DataEdit_RegisTime, de.DataEdit_Name, 
      de.DataEdit_SourceTable, de.DataEdit_UserAgent, de.DataEdit_IP_Address, de.DataEditType_ID, de.Staff_ID, 
      s.Staff_Code, s.Staff_FirstName, s.Staff_LastName, u.Users_Email, u.Users_Type, det.DataEditType_Name FROM dataedit de 
      INNER JOIN dataEditType det ON de.DataEditType_ID = det.DataEditType_ID INNER JOIN staff s ON de.Staff_ID = s.Staff_ID 
      INNER JOIN users u ON s.Users_ID = u.Users_ID WHERE de.DataEdit_RegisTime >= CURDATE() - INTERVAL 90 DAY ORDER BY de.DataEdit_RegisTime DESC`;

    db.query(sql, (err, result) => {
      if (err) {
        console.error('Database error (dataedit)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.length > 0) {
        return res.status(200).json({ message: "Get data edits successfully.", status: true, data: result });
      } else {
        return res.status(404).json({ message: 'No data edits found.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API DataEdit Get by Staff_ID
app.get('/api/dataedit/get/staff/:Staff_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens_Website, async (req, res) => {
  const Staff_ID = req.params.Staff_ID;
  const userData = req.user;
  const AdminID = userData.Users_ID;
  const Login_Type = userData?.Login_Type;
  const Users_Type = userData?.Users_Type;

  if (!AdminID || typeof AdminID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Parameter.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed for staff users.", status: false });
  }

  if (!Staff_ID) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  try {
    const sql = `SELECT de.DataEdit_ID, de.DataEdit_ThisId, de.DataEdit_RegisTime, de.DataEdit_Name, 
      de.DataEdit_SourceTable, de.DataEdit_UserAgent, de.DataEdit_IP_Address, de.DataEditType_ID, de.Staff_ID, 
      s.Staff_Code, s.Staff_FirstName, s.Staff_LastName, u.Users_Email, u.Users_Type, det.DataEditType_Name FROM dataedit de 
      INNER JOIN dataEditType det ON de.DataEditType_ID = det.DataEditType_ID INNER JOIN staff s ON de.Staff_ID = s.Staff_ID 
      INNER JOIN users u ON s.Users_ID = u.Users_ID WHERE de.Staff_ID = ? ORDER BY de.DataEdit_RegisTime DESC`;

    db.query(sql, [Staff_ID], (err, result) => {
      if (err) {
        console.error('Database error (dataedit)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.length > 0) {
        return res.status(200).json({ message: "Get data edits successfully.", status: true, data: result });
      } else {
        return res.status(404).json({ message: 'No data edits found for this staff.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API DataEdit Get by DataEditType_ID
app.get('/api/dataedit/get/type/:DataEditType_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens_Website, async (req, res) => {
  const DataEditType_ID = req.params.DataEditType_ID;
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  if (!DataEditType_ID) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  try {
    const sql = `SELECT de.DataEdit_ID, de.DataEdit_ThisId, de.DataEdit_RegisTime, de.DataEdit_Name, 
      de.DataEdit_SourceTable, de.DataEdit_UserAgent, de.DataEdit_IP_Address, de.DataEditType_ID, de.Staff_ID, 
      s.Staff_Code, s.Staff_FirstName, s.Staff_LastName, u.Users_Email, u.Users_Type, det.DataEditType_Name FROM dataedit de 
      INNER JOIN dataEditType det ON de.DataEditType_ID = det.DataEditType_ID INNER JOIN staff s ON de.Staff_ID = s.Staff_ID 
      INNER JOIN users u ON s.Users_ID = u.Users_ID WHERE det.DataEditType_ID = ? ORDER BY de.DataEdit_RegisTime DESC`;

    db.query(sql, [DataEditType_ID], (err, result) => {
      if (err) {
        console.error('Database error (dataedit)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.length > 0) {
        return res.status(200).json({ message: "Get data edits successfully.", status: true, data: result });
      } else {
        return res.status(404).json({ message: 'No data edits found for this type.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API DataEdit Get by SourceTable
app.get('/api/dataedit/get/source/:SourceTable', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens_Website, async (req, res) => {
  const SourceTable = req.params.SourceTable;
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  if (!SourceTable) {
    return res.status(400).json({ message: "Please provide SourceTable parameter.", status: false });
  }

  const allowedSourceTables = ['Student', 'Teacher', 'Staff', 'Users', 'Activity'];
  if (!allowedSourceTables.includes(SourceTable)) {
    return res.status(400).json({
      message: `Invalid SourceTable. Allowed values: ${allowedSourceTables.join(', ')}`,
      status: false
    });
  }

  try {
    const sql = `SELECT de.DataEdit_ID, de.DataEdit_ThisId, de.DataEdit_RegisTime, de.DataEdit_Name, 
      de.DataEdit_SourceTable, de.DataEdit_UserAgent, de.DataEdit_IP_Address, de.DataEditType_ID, de.Staff_ID, 
      s.Staff_Code, s.Staff_FirstName, s.Staff_LastName, u.Users_Email, u.Users_Type, det.DataEditType_Name FROM 
      dataedit de INNER JOIN dataEditType det ON de.DataEditType_ID = det.DataEditType_ID INNER JOIN staff s ON de.Staff_ID = s.Staff_ID 
      INNER JOIN users u ON s.Users_ID = u.Users_ID WHERE de.DataEdit_SourceTable = ? AND de.DataEdit_RegisTime >= CURDATE() - INTERVAL 90 DAY
      ORDER BY de.DataEdit_RegisTime DESC`;

    db.query(sql, [SourceTable], (err, result) => {
      if (err) {
        console.error('Database error (dataedit)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.length > 0) {
        return res.status(200).json({
          message: `Get data edits for ${SourceTable} successfully.`,
          status: true,
          data: result,
          sourceTable: SourceTable
        });
      } else {
        return res.status(404).json({ message: `No data edits found for ${SourceTable}.`, status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API DataEdit Search
app.get('/api/dataedit/search', RateLimiter(0.5 * 60 * 1000, 10), VerifyTokens_Website, async (req, res) => {
  res.set({
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'
  });

  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  const { email, ip, staff_code, edit_type, source_table, date_from, date_to, limit = 100 } = req.query;

  if (source_table) {
    const allowedSourceTables = ['Student', 'Teacher', 'Staff', 'Users', 'Activity'];
    if (!allowedSourceTables.includes(source_table)) {
      return res.status(400).json({
        message: `Invalid source_table. Allowed values: ${allowedSourceTables.join(', ')}`,
        status: false
      });
    }
  }

  try {
    let sql = `SELECT de.DataEdit_ID, de.DataEdit_ThisId, de.DataEdit_RegisTime, de.DataEdit_Name, 
      de.DataEdit_SourceTable, de.DataEdit_UserAgent, de.DataEdit_IP_Address, de.DataEditType_ID, de.Staff_ID, 
      s.Staff_Code, s.Staff_FirstName, s.Staff_LastName, u.Users_Email, u.Users_Type, det.DataEditType_Name FROM dataedit de 
      INNER JOIN dataEditType det ON de.DataEditType_ID = det.DataEditType_ID INNER JOIN staff s ON de.Staff_ID = s.Staff_ID 
      INNER JOIN users u ON s.Users_ID = u.Users_ID WHERE 1=1`;

    const params = [];
    if (email) {
      sql += ' AND u.Users_Email = ?';
      params.push(email);
    }

    if (ip) {
      sql += ' AND de.DataEdit_IP_Address = ?';
      params.push(ip);
    }

    if (staff_code) {
      sql += ' AND s.Staff_Code = ?';
      params.push(staff_code);
    }

    if (edit_type) {
      sql += ' AND det.DataEditType_Name = ?';
      params.push(edit_type);
    }

    if (source_table) {
      sql += ' AND de.DataEdit_SourceTable = ?';
      params.push(source_table);
    }

    if (date_from) {
      sql += ' AND DATE(de.DataEdit_RegisTime) >= ?';
      params.push(date_from);
    }

    if (date_to) {
      sql += ' AND DATE(de.DataEdit_RegisTime) <= ?';
      params.push(date_to);
    }

    sql += ' AND de.DataEdit_RegisTime >= CURDATE() - INTERVAL 90 DAY';
    sql += ' ORDER BY de.DataEdit_RegisTime DESC LIMIT ?';
    params.push(parseInt(limit));

    db.query(sql, params, (err, result) => {
      if (err) {
        console.error('Database error (dataedit search)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      return res.status(200).json({
        message: "Search completed successfully.",
        status: true,
        data: result,
        total: result.length,
        searchCriteria: {
          email, ip, staff_code, edit_type, source_table, date_from, date_to, limit
        }
      });
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API Staff Search
app.get('/api/staff/search', RateLimiter(0.5 * 60 * 1000, 10), VerifyTokens_Website, async (req, res) => {
  res.set({
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0'
  });

  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  const { email, staff_code, ip } = req.query;

  if (!email && !staff_code && !ip) {
    return res.status(400).json({ message: "Please provide either email, staff_code, or ip parameter.", status: false });
  }

  try {
    let sql;
    let searchParam;

    if (email) {
      sql = `SELECT s.Staff_ID, s.Staff_Code, s.Staff_FirstName, s.Staff_LastName, u.Users_ID, 
        u.Users_Email, u.Users_Type FROM staff s INNER JOIN users u ON s.Users_ID = u.Users_ID WHERE u.Users_Email = ?`;
      searchParam = email;
    } else if (staff_code) {
      sql = `SELECT s.Staff_ID, s.Staff_Code, s.Staff_FirstName, s.Staff_LastName, 
        u.Users_ID, u.Users_Email, u.Users_Type FROM staff s INNER JOIN users u ON s.Users_ID = u.Users_ID WHERE s.Staff_Code = ?`;
      searchParam = staff_code;
    } else if (ip) {
      sql = `SELECT DISTINCT s.Staff_ID, s.Staff_Code, s.Staff_FirstName, s.Staff_LastName, 
        u.Users_ID, u.Users_Email, u.Users_Type FROM staff s INNER JOIN users u ON s.Users_ID = u.Users_ID 
        INNER JOIN dataedit de ON s.Staff_ID = de.Staff_ID WHERE de.DataEdit_IP_Address = ?`;
      searchParam = ip;
    }

    db.query(sql, [searchParam], (err, result) => {
      if (err) {
        console.error('Database error (staff search)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length > 0) {
        return res.status(200).json({
          message: "Staff found successfully.",
          status: true,
          staff: result[0],
          totalStaff: result.length
        });
      } else {
        return res.status(404).json({
          message: `No staff found for this ${email ? 'email' : staff_code ? 'staff code' : 'IP address'}.`,
          status: false
        });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API Get DataEdit Statistics
app.get('/api/dataedit/stats', RateLimiter(0.5 * 60 * 1000, 10), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  try {
    const statsQueries = [
      `SELECT COUNT(*) as total FROM dataedit WHERE DataEdit_RegisTime >= CURDATE() - INTERVAL 90 DAY`,
      `SELECT DataEdit_SourceTable, COUNT(*) as count FROM dataedit 
       WHERE DataEdit_RegisTime >= CURDATE() - INTERVAL 90 DAY 
       GROUP BY DataEdit_SourceTable`,
      `SELECT det.DataEditType_Name, COUNT(*) as count FROM dataedit de 
       INNER JOIN dataEditType det ON de.DataEditType_ID = det.DataEditType_ID 
       WHERE de.DataEdit_RegisTime >= CURDATE() - INTERVAL 90 DAY 
       GROUP BY det.DataEditType_Name`,
      `SELECT COUNT(DISTINCT Staff_ID) as uniqueStaff FROM dataedit 
       WHERE DataEdit_RegisTime >= CURDATE() - INTERVAL 90 DAY`
    ];

    const promises = statsQueries.map(query => {
      return new Promise((resolve, reject) => {
        db.query(query, (err, result) => {
          if (err) reject(err);
          else resolve(result);
        });
      });
    });

    const [totalResult, sourceTableResult, editTypeResult, uniqueStaffResult] = await Promise.all(promises);

    return res.status(200).json({
      message: "Statistics retrieved successfully.",
      status: true,
      stats: {
        total: totalResult[0].total,
        uniqueStaff: uniqueStaffResult[0].uniqueStaff,
        bySourceTable: sourceTableResult,
        byEditType: editTypeResult
      }
    });

  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//////////////////////////////////Admin Website API///////////////////////////////////////
// API Get Data Admin by VerifyTokens of Admin Website
app.get('/api/admin/data/get', RateLimiter(0.5 * 60 * 1000, 24), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const usersTypeID = userData.UsersType_ID;
  const usersType = userData.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed in the website.", status: false });
  }

  if (!usersType || !usersTypeID) {
    return res.status(400).json({ message: "Missing user type or ID.", status: false });
  }

  try {
    const usersType_upper = usersType.charAt(0).toUpperCase() + usersType.slice(1);
    const tableName = db.escapeId(usersType);
    const columnName = db.escapeId(`${usersType_upper}_ID`);

    let sql;

    if (usersType === 'teacher') {
      sql = `SELECT ty.*, u.Users_Email, u.Users_ImageFile, dp.Department_Name, f.Faculty_Name FROM (((${tableName} ty 
        INNER JOIN department dp ON ty.Department_ID = dp.Department_ID) INNER JOIN faculty f ON dp.Faculty_ID = f.Faculty_ID) 
        INNER JOIN users u ON ty.Users_ID = u.Users_ID) WHERE ${columnName} = ? LIMIT 1`;
    } else if (usersType === 'staff') {
      sql = `SELECT * FROM ${tableName} WHERE ${columnName} = ? LIMIT 1`;
    } else {
      return res.status(400).json({ message: "Invalid user type.", status: false });
    }

    db.query(sql, [usersTypeID], (err, result) => {
      if (err) {
        console.error('Database error (profile data)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length > 0) {
        const profileData = result[0];
        profileData['Users_Type_Table'] = usersType;
        profileData['message'] = 'Profile data retrieved successfully.';
        profileData['status'] = true;
        res.status(200).json(profileData);
      } else {
        return res.status(404).json({ message: 'No profile data found for this user.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API Edit Student Admin Website
app.put('/api/admin/student/update/:Users_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_ID = userData?.Users_ID;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (!Requester_Users_ID || typeof Requester_Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid token information.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  const Target_Users_ID = parseInt(req.params.Users_ID, 10);
  if (!Target_Users_ID || isNaN(Target_Users_ID)) {
    return res.status(400).json({ message: "Missing or invalid Users_ID parameter.", status: false });
  }

  let { Student_Phone, Student_Birthdate, Student_Religion, Student_MedicalProblem } = req.body || {};

  if (Student_Phone) {
    if (!validator.isMobilePhone(Student_Phone, 'any', { strictMode: false })) {
      return res.status(400).json({ message: "Invalid phone number format.", status: false });
    }

    if (Student_Phone.length > 20 || Student_Phone.length < 8) {
      return res.status(400).json({ message: "Phone number length must be between 8 and 20 digits.", status: false });
    }

    if (!/^\d+$/.test(Student_Phone)) {
      return res.status(400).json({ message: "Phone number must contain only digits.", status: false });
    }
  }

  if (Student_Birthdate) {
    const birthdateMoment = moment(Student_Birthdate, 'DD-MM-YYYY', true);
    if (!birthdateMoment.isValid()) {
      return res.status(400).json({ message: "Invalid birthdate format. Use DD-MM-YYYY.", status: false });
    }
    Student_Birthdate = birthdateMoment.format('YYYY-MM-DD');
  }

  if (Student_Religion && Student_Religion.length > 63) {
    return res.status(400).json({ message: "Religion text too long (max 63 characters).", status: false });
  }

  if (Student_MedicalProblem && Student_MedicalProblem.length > 511) {
    return res.status(400).json({ message: "Medical problem text too long (max 511 characters).", status: false });
  }

  const allowedFields = { Student_Phone, Student_Birthdate, Student_Religion, Student_MedicalProblem };
  const fieldsToUpdate = [];
  const values = [];
  const modifiedFields = [];

  for (const [key, value] of Object.entries(allowedFields)) {
    if (value !== undefined) {
      fieldsToUpdate.push(`${key} = ?`);
      values.push(value);
      modifiedFields.push(key);
    }
  }

  if (fieldsToUpdate.length === 0) {
    return res.status(400).json({ message: "No fields provided for update.", status: false });
  }

  const sqlCheck = "SELECT Student_ID FROM student WHERE Users_ID = ?";
  db.query(sqlCheck, [Target_Users_ID], (err, result) => {
    if (err) {
      console.error("Database error (student check)", err);
      return res.status(500).json({ message: "Database error occurred.", status: false });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "Student profile not found.", status: false });
    }

    const Student_ID = result[0].Student_ID;
    const sqlUpdate = `UPDATE student SET ${fieldsToUpdate.join(", ")} WHERE Student_ID = ?`;
    values.push(Student_ID);

    db.query(sqlUpdate, values, (err, updateResult) => {
      if (err) {
        console.error("Database error (student update)", err);
        return res.status(500).json({ message: "Database error occurred.", status: false });
      }

      if (updateResult.affectedRows > 0) {
        return res.status(200).json({
          Users_ID: Target_Users_ID,
          updated_by: Requester_Users_ID, updated_fields: modifiedFields, message: "Student profile updated successfully.", status: true
        });
      } else {
        return res.status(404).json({ message: "No changes made or student not found.", status: false });
      }
    });
  });
});

//API Edit Teacher Admin Website
app.put('/api/admin/teacher/update/:Users_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_ID = userData?.Users_ID;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (!Requester_Users_ID || typeof Requester_Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid token information.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  const Target_Users_ID = parseInt(req.params.Users_ID, 10);
  if (!Target_Users_ID || isNaN(Target_Users_ID)) {
    return res.status(400).json({ message: "Missing or invalid Users_ID parameter.", status: false });
  }

  let { Teacher_Phone, Teacher_Birthdate, Teacher_Religion, Teacher_MedicalProblem } = req.body || {};

  if (Teacher_Phone) {
    if (!validator.isMobilePhone(Teacher_Phone, 'any', { strictMode: false })) {
      return res.status(400).json({ message: "Invalid phone number format.", status: false });
    }

    if (Teacher_Phone.length > 20 || Teacher_Phone.length < 8) {
      return res.status(400).json({ message: "Phone number length must be between 8 and 20 digits.", status: false });
    }

    if (!/^\d+$/.test(Teacher_Phone)) {
      return res.status(400).json({ message: "Phone number must contain only digits.", status: false });
    }
  }

  if (Teacher_Birthdate) {
    const birthdateMoment = moment(Teacher_Birthdate, 'DD-MM-YYYY', true);
    if (!birthdateMoment.isValid()) {
      return res.status(400).json({ message: "Invalid birthdate format. Use DD-MM-YYYY.", status: false });
    }
    Teacher_Birthdate = birthdateMoment.format('YYYY-MM-DD');
  }

  if (Teacher_Religion && Teacher_Religion.length > 63) {
    return res.status(400).json({ message: "Religion text too long (max 63 characters).", status: false });
  }

  if (Teacher_MedicalProblem && Teacher_MedicalProblem.length > 511) {
    return res.status(400).json({ message: "Medical problem text too long (max 511 characters).", status: false });
  }

  const allowedFields = { Teacher_Phone, Teacher_Birthdate, Teacher_Religion, Teacher_MedicalProblem };
  const fieldsToUpdate = [];
  const values = [];
  const modifiedFields = [];

  for (const [key, value] of Object.entries(allowedFields)) {
    if (value !== undefined) {
      fieldsToUpdate.push(`${key} = ?`);
      values.push(value);
      modifiedFields.push(key);
    }
  }

  if (fieldsToUpdate.length === 0) {
    return res.status(400).json({ message: "No fields provided for update.", status: false });
  }

  const sqlCheck = "SELECT Teacher_ID FROM teacher WHERE Users_ID = ?";
  db.query(sqlCheck, [Target_Users_ID], (err, result) => {
    if (err) {
      console.error("Database error (teacher check)", err);
      return res.status(500).json({ message: "Database error occurred.", status: false });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "Teacher profile not found.", status: false });
    }

    const Teacher_ID = result[0].Teacher_ID;
    const sqlUpdate = `UPDATE teacher SET ${fieldsToUpdate.join(", ")} WHERE Teacher_ID = ?`;
    values.push(Teacher_ID);

    db.query(sqlUpdate, values, (err, updateResult) => {
      if (err) {
        console.error("Database error (teacher update)", err);
        return res.status(500).json({ message: "Database error occurred.", status: false });
      }

      if (updateResult.affectedRows > 0) {
        return res.status(200).json({
          Users_ID: Target_Users_ID,
          updated_by: Requester_Users_ID, updated_fields: modifiedFields, message: "Teacher profile updated successfully.", status: true
        });
      } else {
        return res.status(404).json({ message: "No changes made or teacher not found.", status: false });
      }
    });
  });
});

//API get Other Phone Number by Users_ID of Admin Website
app.get('/api/admin/otherphone/get/:Users_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_ID = userData?.Users_ID;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (!Requester_Users_ID || typeof Requester_Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid token information.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  const Target_Users_ID = parseInt(req.params.Users_ID, 10);
  if (!Target_Users_ID || isNaN(Target_Users_ID)) {
    return res.status(400).json({ message: "Missing or invalid Users_ID parameter.", status: false });
  }

  try {
    const sql = "SELECT OtherPhone_ID, Users_ID, OtherPhone_Name, OtherPhone_Phone FROM otherphone WHERE Users_ID = ?";
    db.query(sql, [Target_Users_ID], (err, result) => {
      if (err) {
        console.error('Database error while getting other phones for Users_ID:', Users_ID, err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length > 0) {
        res.status(200).json({ data: result, message: 'Other phone numbers retrieved successfully.', status: true });
      } else {
        return res.status(404).json({ data: [], message: 'No other phone numbers found for this user.', status: false, });
      }
    });
  } catch (error) {
    console.error('Unexpected error while retrieving other phones', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API get Other Phone Number by OtherPhone_ID of Admin Website
app.get('/api/admin/otherphone/getbyphoneid/:OtherPhone_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_ID = userData?.Users_ID;
  const Users_Type = userData?.Users_Type;
  const OtherPhone_ID = req.params.OtherPhone_ID;
  const Login_Type = userData?.Login_Type;

  if (!Requester_Users_ID || typeof Requester_Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid token information.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }


  if (!OtherPhone_ID || isNaN(Number(OtherPhone_ID))) {
    return res.status(400).json({ message: "Invalid OtherPhone_ID parameter.", status: false });
  }

  try {
    const sql = "SELECT OtherPhone_ID, Users_ID, OtherPhone_Name, OtherPhone_Phone FROM otherphone WHERE OtherPhone_ID = ?";
    db.query(sql, [OtherPhone_ID], (err, result) => {
      if (err) {
        console.error('Database error (get by ID)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length > 0) {
        const results = result[0];
        const phoneData = results;
        phoneData['message'] = 'Other phone number retrieved successfully.';
        phoneData['status'] = true;
        res.status(200).json(phoneData);
      } else {
        return res.status(404).json({ message: 'Other phone number not found or access denied.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error (get by ID)', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Get Users Data by Users_ID of Admin Website
app.get('/api/admin/data/:Users_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_ID = userData?.Users_ID;
  const Requester_Users_Type = userData?.Users_Type;
  const Users_ID = req.params.Users_ID;
  const Login_Type = userData?.Login_Type;

  if (!Requester_Users_ID || typeof Requester_Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid token information.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  if (!Users_ID || isNaN(Number(Users_ID))) {
    return res.status(400).json({ message: "Invalid Users_ID parameter.", status: false });
  }

  try {
    const checkSql = "SELECT Users_Type FROM users WHERE Users_ID = ?";
    db.query(checkSql, [Users_ID], (err, checkResult) => {
      if (err) {
        console.error('Database error (check user type)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (checkResult.length === 0) {
        return res.status(404).json({ message: 'User not found.', status: false });
      }

      const usersType = checkResult[0].Users_Type;
      const usersType_upper = usersType.charAt(0).toUpperCase() + usersType.slice(1);
      const tableName = db.escapeId(usersType);
      const columnName = db.escapeId(`${usersType_upper}_ID`);
      const usersTypeIDColumnName = `${usersType_upper}_ID`;

      const checkUserTypeSql = `SELECT ${columnName} FROM ${tableName} WHERE Users_ID = ?`;
      db.query(checkUserTypeSql, [Users_ID], (err, userTypeResult) => {
        if (err) {
          console.error('Database error (check user type in specific table)', err);
          return res.status(500).json({ message: 'An error occurred on the server.', status: false });
        }

        if (userTypeResult.length === 0) {
          return res.status(404).json({ message: 'User type details not found.', status: false });
        }

        const usersTypeID = userTypeResult[0][usersTypeIDColumnName];
        if (!usersTypeID) {
          return res.status(404).json({ message: 'User type ID not found.', status: false });
        }

        let sql;
        if (usersType === 'student') {
          sql = `SELECT ty.*, u.Users_Email, u.Users_ImageFile ,t.Teacher_FirstName, t.Teacher_LastName, dp.Department_Name, f.Faculty_Name FROM
            ((((${tableName} ty INNER JOIN department dp ON ty.Department_ID = dp.Department_ID) INNER JOIN faculty f ON dp.Faculty_ID = f.Faculty_ID)
            INNER JOIN teacher t ON ty.Teacher_ID = t.Teacher_ID) INNER JOIN users u ON ty.Users_ID = u.Users_ID) WHERE ${columnName} = ? LIMIT 1;`;
        } else if (usersType === 'teacher') {
          sql = `SELECT ty.*, u.Users_Email, u.Users_ImageFile, dp.Department_Name, f.Faculty_Name FROM (((${tableName} ty 
            INNER JOIN department dp ON ty.Department_ID = dp.Department_ID) INNER JOIN faculty f ON dp.Faculty_ID = f.Faculty_ID) 
            INNER JOIN users u ON ty.Users_ID = u.Users_ID) WHERE ${columnName} = ? LIMIT 1`;
        } else if (usersType === 'staff') {
          sql = `SELECT * FROM ${tableName} WHERE ${columnName} = ? LIMIT 1`;
        } else {
          return res.status(400).json({ message: "Invalid user type.", status: false });
        }

        db.query(sql, [usersTypeID], (err, result) => {
          if (err) {
            console.error('Database error (profile data)', err);
            return res.status(500).json({ message: 'An error occurred on the server.', status: false });
          }

          if (result.length > 0) {
            const profileData = result[0];
            profileData['Users_Type_Table'] = usersType;
            profileData['message'] = 'Profile data retrieved successfully.';
            profileData['status'] = true;
            res.status(200).json(profileData);
          } else {
            return res.status(404).json({ message: 'No profile data found for this user.', status: false });
          }
        });
      });
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Register Student Admin Website
app.post('/api/admin/users/student/add', RateLimiter(1 * 60 * 1000, 5), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_ID = userData?.Users_ID;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  let { Users_Email, Users_Password, Student_Code, Student_FirstName, Student_LastName, Student_Phone,
    Student_AcademicYear, Student_Birthdate, Student_Religion, Student_MedicalProblem, Teacher_ID, Department_ID } = req.body || {};

  if (!Users_Email || !Users_Password || !Student_Code ||
    !Student_FirstName || !Student_LastName || !Student_AcademicYear || !Teacher_ID || !Department_ID) {
    return res.status(400).json({
      message: `Please fill in all required fields: Users_Email, Users_Password, 
        Student_Code, Student_FirstName, Student_LastName, Student_AcademicYear, Teacher_ID, Department_ID`,
      status: false
    });
  }

  if (!Requester_Users_ID || typeof Requester_Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid token information.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  Users_Email = xss(Users_Email.trim());
  if (!validator.isEmail(Users_Email)) {
    return res.status(400).json({ message: 'Invalid email format.', status: false });
  }

  let Users_Username = Users_Email.split('@')[0];
  Users_Username = xss(Users_Username.trim());

  const usernameRegex = /^[a-zA-Z0-9.\-]+$/;
  if (!usernameRegex.test(Users_Username) || Users_Username.length < 2 || Users_Username.length > 60) {
    return res.status(400).json({
      message: 'Email username part (before @) must be 2-60 characters and can contain letters, numbers, and dot (.) only.',
      status: false
    });
  }

  Users_Password = xss(Users_Password);
  if (!validator.isStrongPassword(Users_Password, { minLength: 8, minNumbers: 1, minSymbols: 0, minUppercase: 0, minLowercase: 0 })) {
    return res.status(400).json({ message: 'Password is not strong enough.', status: false });
  }

  Student_Code = xss(Student_Code.trim());
  if (!/^\d{12}-\d{1}$/.test(Student_Code)) {
    return res.status(400).json({
      message: 'Student code must be in format: 12 digits followed by - and 1 digit (e.g., 026530461001-6)',
      status: false
    });
  }

  Student_FirstName = xss(Student_FirstName.trim());
  Student_LastName = xss(Student_LastName.trim());
  Student_Phone = Student_Phone ? xss(Student_Phone.trim()) : null;
  Student_Religion = Student_Religion ? xss(Student_Religion.trim()) : null;
  Student_MedicalProblem = Student_MedicalProblem ? xss(Student_MedicalProblem.trim()) : null;

  let academicYear = parseInt(Student_AcademicYear);
  if (isNaN(academicYear)) {
    return res.status(400).json({ message: 'Academic year must be a valid number.', status: false });
  }
  if (academicYear > 2400) {
    academicYear = academicYear - 543;
  }
  const currentChristianYear = new Date().getFullYear();
  if (academicYear < 1950 || academicYear > currentChristianYear + 10) {
    return res.status(400).json({ message: 'Invalid academic year.', status: false });
  }
  Student_AcademicYear = academicYear;

  if (Student_Birthdate) {
    Student_Birthdate = xss(Student_Birthdate.trim());
    const dateRegex = /^\d{1,2}[-\/]\d{1,2}[-\/]\d{4}$/;

    if (dateRegex.test(Student_Birthdate)) {
      const parts = Student_Birthdate.split(/[-\/]/);
      const day = parts[0].padStart(2, '0');
      const month = parts[1].padStart(2, '0');
      const buddhistYear = parseInt(parts[2]);
      let christianYear = buddhistYear;
      if (buddhistYear > 2400) {
        christianYear = buddhistYear - 543;
      }

      Student_Birthdate = `${christianYear}-${month}-${day}`;
      const birthDate = new Date(Student_Birthdate);
      const today = new Date();
      if (birthDate > today) {
        return res.status(400).json({ message: 'Birthdate cannot be in the future.', status: false });
      }
    } else {
      return res.status(400).json({
        message: 'Invalid birthdate format. Use dd-mm-yyyy or dd/mm/yyyy (e.g., 15-01-2545 or 15/01/1995)',
        status: false
      });
    }
  } else {
    Student_Birthdate = null;
  }

  Teacher_ID = parseInt(Teacher_ID);
  Department_ID = parseInt(Department_ID);

  if (isNaN(Teacher_ID) || isNaN(Department_ID)) {
    return res.status(400).json({ message: 'Teacher_ID and Department_ID must be valid numbers.', status: false });
  }

  try {
    const hashedPassword = await bcrypt.hash(Users_Password, saltRounds);

    // Start Transaction
    db.query('START TRANSACTION', async (err) => {
      if (err) {
        console.error('Transaction Start Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }

      const checkDuplicateSql = `SELECT CASE WHEN EXISTS(SELECT 1 FROM users WHERE Users_Email = ? OR Users_Username = ?) 
        THEN 'email_username' WHEN EXISTS(SELECT 1 FROM student WHERE Student_Code = ?) THEN 'student_code' ELSE NULL END as duplicate_type`;

      db.query(checkDuplicateSql, [Users_Email, Users_Username, Student_Code], (err, duplicateResult) => {
        if (err) {
          db.query('ROLLBACK', () => { });
          console.error('Check Duplicate Error:', err);
          return res.status(500).json({ message: 'Database error', status: false });
        }

        const duplicateType = duplicateResult[0]?.duplicate_type;
        if (duplicateType) {
          db.query('ROLLBACK', () => { });
          if (duplicateType === 'email_username') {
            return res.status(409).json({ message: 'Email or username already exists.', status: false });
          } else if (duplicateType === 'student_code') {
            return res.status(409).json({ message: 'Student code already exists.', status: false });
          }
        }

        const checkTeacherSql = 'SELECT Teacher_ID FROM teacher WHERE Teacher_ID = ? AND Teacher_IsResign = FALSE';
        db.query(checkTeacherSql, [Teacher_ID], (err, teacherResult) => {
          if (err) {
            db.query('ROLLBACK', () => { });
            console.error('Check Teacher Error:', err);
            return res.status(500).json({ message: 'Database error', status: false });
          }

          if (teacherResult.length === 0) {
            db.query('ROLLBACK', () => { });
            return res.status(400).json({ message: 'Invalid Teacher_ID or teacher is resigned.', status: false });
          }

          const checkDepartmentSql = 'SELECT Department_ID FROM department WHERE Department_ID = ?';
          db.query(checkDepartmentSql, [Department_ID], (err, deptResult) => {
            if (err) {
              db.query('ROLLBACK', () => { });
              console.error('Check Department Error:', err);
              return res.status(500).json({ message: 'Database error', status: false });
            }

            if (deptResult.length === 0) {
              db.query('ROLLBACK', () => { });
              return res.status(400).json({ message: 'Invalid Department_ID.', status: false });
            }

            const sqlUser = `INSERT INTO users (Users_Email, Users_Username, Users_Password, Users_Type) VALUES (?, ?, ?, 'student')`;
            db.query(sqlUser, [Users_Email, Users_Username, hashedPassword], (err, userResult) => {
              if (err) {
                db.query('ROLLBACK', () => { });
                console.error('Insert Users Error:', err);
                return res.status(500).json({ message: 'Database error', status: false });
              }

              const Users_ID = userResult.insertId;
              const sqlStudent = `INSERT INTO student (Student_Code, Student_FirstName, Student_LastName, 
                Student_Phone, Student_AcademicYear, Student_Birthdate, Student_Religion, Student_MedicalProblem, 
                Users_ID, Teacher_ID, Department_ID) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

              db.query(sqlStudent, [
                Student_Code, Student_FirstName, Student_LastName, Student_Phone, Student_AcademicYear,
                Student_Birthdate, Student_Religion, Student_MedicalProblem, Users_ID, Teacher_ID, Department_ID
              ], (err, studentResult) => {
                if (err) {
                  db.query('ROLLBACK', () => { });
                  console.error('Insert Student Error:', err);
                  return res.status(500).json({ message: 'Database error', status: false });
                }

                // Commit Transaction
                db.query('COMMIT', (err) => {
                  if (err) {
                    db.query('ROLLBACK', () => { });
                    console.error('Commit Error:', err);
                    return res.status(500).json({ message: 'Database error', status: false });
                  }

                  res.status(201).json({
                    message: 'Student registered successfully.',
                    status: true,
                    data: {
                      Users_ID: Users_ID,
                      Student_ID: studentResult.insertId,
                      Student_Code: Student_Code,
                      Student_FirstName: Student_FirstName,
                      Student_LastName: Student_LastName,
                      Users_Email: Users_Email,
                      Users_Username: Users_Username
                    }
                  });
                });
              });
            });
          });
        });
      });
    });
  } catch (err) {
    console.error('Register Student Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Register Teacher Admin Website
app.post('/api/admin/users/teacher/add', RateLimiter(1 * 60 * 1000, 5), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_ID = userData?.Users_ID;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  let { Users_Email, Users_Password, Teacher_Code, Teacher_FirstName, Teacher_LastName,
    Teacher_Phone, Teacher_Birthdate, Teacher_Religion, Teacher_MedicalProblem, Teacher_IsDean, Department_ID } = req.body || {};

  if (!Users_Email || !Users_Password || !Teacher_Code || !Teacher_FirstName || !Teacher_LastName || !Department_ID) {
    return res.status(400).json({
      message: 'Please fill in all required fields: Users_Email, Users_Password, Teacher_Code, Teacher_FirstName, Teacher_LastName, Department_ID',
      status: false
    });
  }

  if (!Requester_Users_ID || typeof Requester_Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid token information.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  Users_Email = xss(Users_Email.trim());
  if (!validator.isEmail(Users_Email)) {
    return res.status(400).json({ message: 'Invalid email format.', status: false });
  }

  let Users_Username = Users_Email.split('@')[0];
  Users_Username = xss(Users_Username.trim());

  const usernameRegex = /^[a-zA-Z0-9.\-]+$/;
  if (!usernameRegex.test(Users_Username) || Users_Username.length < 2 || Users_Username.length > 60) {
    return res.status(400).json({
      message: 'Email username part (before @) must be 2-60 characters and can contain letters, numbers, and dot (.) only.',
      status: false
    });
  }

  Users_Password = xss(Users_Password);
  if (!validator.isStrongPassword(Users_Password, { minLength: 8, minNumbers: 1, minSymbols: 0, minUppercase: 0, minLowercase: 0 })) {
    return res.status(400).json({ message: 'Password is not strong enough.', status: false });
  }

  Teacher_Code = xss(Teacher_Code.trim());
  const TeacherCodeRegex = /^\d{12}-\d{1}$/;
  if (!TeacherCodeRegex.test(Teacher_Code)) {
    return res.status(400).json({
      message: 'Teacher code must be in format: 12 digits followed by - and 1 digit (e.g., 026530461001-6)',
      status: false
    });
  }

  Teacher_FirstName = xss(Teacher_FirstName.trim());
  Teacher_LastName = xss(Teacher_LastName.trim());
  Teacher_Phone = Teacher_Phone ? xss(Teacher_Phone.trim()) : null;
  Teacher_Religion = Teacher_Religion ? xss(Teacher_Religion.trim()) : null;
  Teacher_MedicalProblem = Teacher_MedicalProblem ? xss(Teacher_MedicalProblem.trim()) : null;

  if (Teacher_Birthdate) {
    Teacher_Birthdate = xss(Teacher_Birthdate.trim());
    const dateRegex = /^\d{1,2}[-\/]\d{1,2}[-\/]\d{4}$/;

    if (dateRegex.test(Teacher_Birthdate)) {
      const parts = Teacher_Birthdate.split(/[-\/]/);
      const day = parts[0].padStart(2, '0');
      const month = parts[1].padStart(2, '0');
      const buddhistYear = parseInt(parts[2]);

      let christianYear = buddhistYear;
      if (buddhistYear > 2400) {
        christianYear = buddhistYear - 543;
      }

      Teacher_Birthdate = `${christianYear}-${month}-${day}`;
      const birthDate = new Date(Teacher_Birthdate);
      const today = new Date();
      if (birthDate > today) {
        return res.status(400).json({ message: 'Birthdate cannot be in the future.', status: false });
      }

      const age = today.getFullYear() - birthDate.getFullYear();
      const monthDiff = today.getMonth() - birthDate.getMonth();
      const actualAge = (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate()))
        ? age - 1 : age;

      if (actualAge < 20) {
        return res.status(400).json({ message: 'Teacher must be at least 20 years old.', status: false });
      }
    } else {
      return res.status(400).json({
        message: 'Invalid birthdate format. Use dd-mm-yyyy or dd/mm/yyyy (e.g., 15-01-2545 or 15/01/1995)',
        status: false
      });
    }
  } else {
    Teacher_Birthdate = null;
  }

  Teacher_IsDean = Teacher_IsDean ? Boolean(Teacher_IsDean) : false;
  Department_ID = parseInt(Department_ID);

  if (isNaN(Department_ID)) {
    return res.status(400).json({ message: 'Department_ID must be a valid number.', status: false });
  }

  try {
    const hashedPassword = await bcrypt.hash(Users_Password, saltRounds);

    // Start Transaction
    db.query('START TRANSACTION', async (err) => {
      if (err) {
        console.error('Transaction Start Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }

      const checkDuplicateSql = `SELECT CASE WHEN EXISTS(SELECT 1 FROM users 
        WHERE Users_Email = ? OR Users_Username = ?) THEN 'email_username' WHEN EXISTS 
        (SELECT 1 FROM teacher WHERE Teacher_Code = ?) THEN 'teacher_code' ELSE NULL END as duplicate_type`;

      db.query(checkDuplicateSql, [Users_Email, Users_Username, Teacher_Code], (err, duplicateResult) => {
        if (err) {
          db.query('ROLLBACK', () => { });
          console.error('Check Duplicate Error:', err);
          return res.status(500).json({ message: 'Database error', status: false });
        }

        const duplicateType = duplicateResult[0]?.duplicate_type;
        if (duplicateType) {
          db.query('ROLLBACK', () => { });
          if (duplicateType === 'email_username') {
            return res.status(409).json({ message: 'Email or username already exists.', status: false });
          } else if (duplicateType === 'teacher_code') {
            return res.status(409).json({ message: 'Teacher code already exists.', status: false });
          }
        }

        const checkDepartmentSql = 'SELECT Department_ID, Faculty_ID FROM department WHERE Department_ID = ?';
        db.query(checkDepartmentSql, [Department_ID], (err, deptResult) => {
          if (err) {
            db.query('ROLLBACK', () => { });
            console.error('Check Department Error:', err);
            return res.status(500).json({ message: 'Database error', status: false });
          }

          if (deptResult.length === 0) {
            db.query('ROLLBACK', () => { });
            return res.status(400).json({ message: 'Invalid Department_ID.', status: false });
          }

          const Faculty_ID = deptResult[0].Faculty_ID;
          const checkDeanProcess = () => {
            if (Teacher_IsDean) {
              const checkDeanSql = `SELECT t.Teacher_ID FROM teacher t INNER JOIN department d ON 
              t.Department_ID = d.Department_ID WHERE d.Faculty_ID = ? AND t.Teacher_IsDean = TRUE AND t.Teacher_IsResign = FALSE`;

              db.query(checkDeanSql, [Faculty_ID], (err, deanResult) => {
                if (err) {
                  db.query('ROLLBACK', () => { });
                  console.error('Check Dean Error:', err);
                  return res.status(500).json({ message: 'Database error', status: false });
                }

                if (deanResult.length > 0) {
                  db.query('ROLLBACK', () => { });
                  return res.status(400).json({ message: 'This faculty already has a dean. Please remove the current dean first or set Teacher_IsDean to false.', status: false });
                }
                insertTeacher();
              });
            } else {
              insertTeacher();
            }
          };

          const insertTeacher = () => {
            const sqlUser = `INSERT INTO users (Users_Email, Users_Username, Users_Password, Users_Type) VALUES (?, ?, ?, 'teacher')`;
            db.query(sqlUser, [Users_Email, Users_Username, hashedPassword], (err, userResult) => {
              if (err) {
                db.query('ROLLBACK', () => { });
                console.error('Insert Users Error:', err);
                return res.status(500).json({ message: 'Database error', status: false });
              }

              const Users_ID = userResult.insertId;
              const sqlTeacher = `INSERT INTO teacher (Teacher_Code, Teacher_FirstName, 
                Teacher_LastName, Teacher_Phone, Teacher_Birthdate, Teacher_Religion, Teacher_MedicalProblem, 
                Teacher_IsDean, Users_ID, Department_ID) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

              db.query(sqlTeacher, [
                Teacher_Code, Teacher_FirstName, Teacher_LastName, Teacher_Phone, Teacher_Birthdate,
                Teacher_Religion, Teacher_MedicalProblem, Teacher_IsDean, Users_ID, Department_ID
              ], (err, teacherResult) => {
                if (err) {
                  db.query('ROLLBACK', () => { });
                  console.error('Insert Teacher Error:', err);
                  return res.status(500).json({ message: 'Database error', status: false });
                }

                // Commit Transaction
                db.query('COMMIT', (err) => {
                  if (err) {
                    db.query('ROLLBACK', () => { });
                    console.error('Commit Error:', err);
                    return res.status(500).json({ message: 'Database error', status: false });
                  }

                  res.status(201).json({
                    message: 'Teacher registered successfully.',
                    status: true,
                    data: {
                      Users_ID: Users_ID,
                      Teacher_ID: teacherResult.insertId,
                      Teacher_Code: Teacher_Code,
                      Teacher_FirstName: Teacher_FirstName,
                      Teacher_LastName: Teacher_LastName,
                      Teacher_IsDean: Teacher_IsDean,
                      Users_Email: Users_Email,
                      Users_Username: Users_Username,
                      Department_ID: Department_ID
                    }
                  });
                });
              });
            });
          };
          checkDeanProcess();
        });
      });
    });
  } catch (err) {
    console.error('Register Teacher Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Register Staff Admin Website**
app.post('/api/admin/users/staff/add', RateLimiter(1 * 60 * 1000, 5), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_ID = userData?.Users_ID;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  let { Users_Email, Users_Password, Staff_Code, Staff_FirstName, Staff_LastName, Staff_Phone } = req.body || {};

  if (!Users_Email || !Users_Password || !Staff_Code || !Staff_FirstName || !Staff_LastName) {
    return res.status(400).json({
      message: 'Please fill in all required fields: Users_Email, Users_Password, Staff_Code, Staff_FirstName, Staff_LastName',
      status: false
    });
  }

  if (!Requester_Users_ID || typeof Requester_Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid token information.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  Users_Email = xss(Users_Email.trim());
  if (!validator.isEmail(Users_Email)) {
    return res.status(400).json({ message: 'Invalid email format.', status: false });
  }

  let Users_Username = Users_Email.split('@')[0];
  Users_Username = xss(Users_Username.trim());

  const usernameRegex = /^[a-zA-Z0-9.\-]+$/;
  if (!usernameRegex.test(Users_Username) || Users_Username.length < 2 || Users_Username.length > 60) {
    return res.status(400).json({
      message: 'Email username part (before @) must be 2-60 characters and can contain letters, numbers, and dot (.) only.',
      status: false
    });
  }

  Users_Password = xss(Users_Password);
  if (!validator.isStrongPassword(Users_Password, { minLength: 8, minNumbers: 1, minSymbols: 0, minUppercase: 0, minLowercase: 0 })) {
    return res.status(400).json({ message: 'Password is not strong enough.', status: false });
  }

  Staff_Code = xss(Staff_Code.trim());
  if (!/^\d{12}-\d{1}$/.test(Staff_Code)) {
    return res.status(400).json({
      message: 'Staff code must be in format: 12 digits followed by - and 1 digit (e.g., 026530461001-6)',
      status: false
    });
  }

  Staff_FirstName = xss(Staff_FirstName.trim());
  Staff_LastName = xss(Staff_LastName.trim());
  Staff_Phone = Staff_Phone ? xss(Staff_Phone.trim()) : null;

  try {
    const hashedPassword = await bcrypt.hash(Users_Password, saltRounds);

    // Start Transaction
    db.query('START TRANSACTION', async (err) => {
      if (err) {
        console.error('Transaction Start Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }

      const checkDuplicateSql = `SELECT CASE WHEN EXISTS(SELECT 1 FROM users WHERE Users_Email = ? OR Users_Username = ?) 
        THEN 'email_username' WHEN EXISTS(SELECT 1 FROM staff WHERE Staff_Code = ?) THEN 'staff_code' ELSE NULL END as duplicate_type`;

      db.query(checkDuplicateSql, [Users_Email, Users_Username, Staff_Code], (err, duplicateResult) => {
        if (err) {
          db.query('ROLLBACK', () => { });
          console.error('Check Duplicate Error:', err);
          return res.status(500).json({ message: 'Database error', status: false });
        }

        const duplicateType = duplicateResult[0]?.duplicate_type;
        if (duplicateType) {
          db.query('ROLLBACK', () => { });
          if (duplicateType === 'email_username') {
            return res.status(409).json({ message: 'Email or username already exists.', status: false });
          } else if (duplicateType === 'staff_code') {
            return res.status(409).json({ message: 'Staff code already exists.', status: false });
          }
        }

        const sqlUser = `INSERT INTO users (Users_Email, Users_Username, Users_Password, Users_Type) VALUES (?, ?, ?, 'staff')`;
        db.query(sqlUser, [Users_Email, Users_Username, hashedPassword], (err, userResult) => {
          if (err) {
            db.query('ROLLBACK', () => { });
            console.error('Insert Users Error:', err);
            return res.status(500).json({ message: 'Database error', status: false });
          }

          const Users_ID = userResult.insertId;
          const sqlStaff = `INSERT INTO staff (Staff_Code, Staff_FirstName, Staff_LastName, Staff_Phone, Users_ID) 
            VALUES (?, ?, ?, ?, ?)`;

          db.query(sqlStaff, [Staff_Code, Staff_FirstName, Staff_LastName, Staff_Phone, Users_ID], (err, staffResult) => {
            if (err) {
              db.query('ROLLBACK', () => { });
              console.error('Insert Staff Error:', err);
              return res.status(500).json({ message: 'Database error', status: false });
            }

            // Commit Transaction
            db.query('COMMIT', (err) => {
              if (err) {
                db.query('ROLLBACK', () => { });
                console.error('Commit Error:', err);
                return res.status(500).json({ message: 'Database error', status: false });
              }

              res.status(201).json({
                message: 'Staff registered successfully.',
                status: true,
                data: {
                  Users_ID: Users_ID,
                  Staff_ID: staffResult.insertId,
                  Staff_Code: Staff_Code,
                  Staff_FirstName: Staff_FirstName,
                  Staff_LastName: Staff_LastName,
                  Users_Email: Users_Email,
                  Users_Username: Users_Username
                }
              });
            });
          });
        });
      });
    });
  } catch (err) {
    console.error('Register Staff Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Register Student from CSV website admin
app.post('/api/admin/users/student/import', RateLimiter(1 * 60 * 1000, 1001), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_ID = userData?.Users_ID;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  let { Users_Email, Users_Password, Student_Code, Student_FirstName,
    Student_LastName, Student_Phone, Student_AcademicYear, Student_Birthdate,
    Student_Religion, Student_MedicalProblem, Faculty_Name, Department_Name, Teacher_Code } = req.body || {};

  if (!Users_Email || !Users_Password || !Student_Code || !Student_FirstName ||
    !Student_LastName || !Student_AcademicYear || !Faculty_Name || !Department_Name || !Teacher_Code) {
    return res.status(400).json({
      message: 'Please fill in all required fields for CSV import', status: false
    });
  }

  if (!Requester_Users_ID || typeof Requester_Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid token information.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  Users_Email = xss(Users_Email.trim());
  if (!validator.isEmail(Users_Email)) {
    return res.status(400).json({ message: 'Invalid email format.', status: false });
  }

  let Users_Username = Users_Email.split('@')[0];
  Users_Username = xss(Users_Username.trim());

  const usernameRegex = /^[a-zA-Z0-9.\-]+$/;
  if (!usernameRegex.test(Users_Username) || Users_Username.length < 2 || Users_Username.length > 60) {
    return res.status(400).json({
      message: 'Email username part (before @) must be 2-60 characters and can contain letters, numbers, and dot (.) only.',
      status: false
    });
  }

  Users_Password = xss(Users_Password);
  if (!validator.isStrongPassword(Users_Password, { minLength: 8, minNumbers: 1, minSymbols: 0, minUppercase: 0, minLowercase: 0 })) {
    return res.status(400).json({ message: 'Password is not strong enough.', status: false });
  }

  Student_Code = xss(Student_Code.trim());
  if (!/^\d{12}-\d{1}$/.test(Student_Code)) {
    return res.status(400).json({
      message: 'Student code must be in format: 12 digits followed by - and 1 digit (e.g., 026530461001-6)',
      status: false
    });
  }

  Student_FirstName = xss(Student_FirstName.trim());
  Student_LastName = xss(Student_LastName.trim());
  Student_Phone = Student_Phone ? xss(Student_Phone.trim()) : null;
  Student_Religion = Student_Religion ? xss(Student_Religion.trim()) : null;
  Student_MedicalProblem = Student_MedicalProblem ? xss(Student_MedicalProblem.trim()) : null;
  let academicYear = parseInt(Student_AcademicYear);
  if (isNaN(academicYear)) {
    return res.status(400).json({ message: 'Academic year must be a valid number.', status: false });
  }
  if (academicYear > 2400) {
    academicYear = academicYear - 543;
  }
  const currentChristianYear = new Date().getFullYear();
  if (academicYear < 1950 || academicYear > currentChristianYear + 10) {
    return res.status(400).json({ message: 'Invalid academic year.', status: false });
  }
  Student_AcademicYear = academicYear;
  if (Student_Birthdate) {
    Student_Birthdate = xss(Student_Birthdate.trim());
    const dateRegex = /^\d{1,2}[-\/]\d{1,2}[-\/]\d{4}$/;

    if (dateRegex.test(Student_Birthdate)) {
      const parts = Student_Birthdate.split(/[-\/]/);
      const day = parts[0].padStart(2, '0');
      const month = parts[1].padStart(2, '0');
      const buddhistYear = parseInt(parts[2]);
      let christianYear = buddhistYear;
      if (buddhistYear > 2400) {
        christianYear = buddhistYear - 543;
      }
      Student_Birthdate = `${christianYear}-${month}-${day}`;
    }
  } else {
    Student_Birthdate = null;
  }

  Faculty_Name = xss(Faculty_Name.trim());
  Department_Name = xss(Department_Name.trim());
  Teacher_Code = xss(Teacher_Code.trim());

  try {
    const hashedPassword = await bcrypt.hash(Users_Password, saltRounds);

    // Transaction
    db.query('START TRANSACTION', async (err) => {
      if (err) {
        console.error('Transaction Start Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }
      const facultySql = 'SELECT Faculty_ID FROM faculty WHERE Faculty_Name = ?';
      db.query(facultySql, [Faculty_Name], (err, facultyResult) => {
        if (err) {
          db.query('ROLLBACK', () => { });
          console.error('Find Faculty Error:', err);
          return res.status(500).json({ message: 'Database error', status: false });
        }

        if (facultyResult.length === 0) {
          db.query('ROLLBACK', () => { });
          return res.status(400).json({ message: `Faculty '${Faculty_Name}' not found.`, status: false });
        }

        const Faculty_ID = facultyResult[0].Faculty_ID;
        const departmentSql = 'SELECT Department_ID FROM department WHERE Department_Name = ? AND Faculty_ID = ?';
        db.query(departmentSql, [Department_Name, Faculty_ID], (err, deptResult) => {
          if (err) {
            db.query('ROLLBACK', () => { });
            console.error('Find Department Error:', err);
            return res.status(500).json({ message: 'Database error', status: false });
          }

          if (deptResult.length === 0) {
            db.query('ROLLBACK', () => { });
            return res.status(400).json({ message: `Department '${Department_Name}' not found in faculty '${Faculty_Name}'.`, status: false });
          }

          const Department_ID = deptResult[0].Department_ID;
          const teacherSql = 'SELECT Teacher_ID FROM teacher WHERE Teacher_Code = ? AND Teacher_IsResign = FALSE';
          db.query(teacherSql, [Teacher_Code], (err, teacherResult) => {
            if (err) {
              db.query('ROLLBACK', () => { });
              console.error('Find Teacher Error:', err);
              return res.status(500).json({ message: 'Database error', status: false });
            }

            if (teacherResult.length === 0) {
              db.query('ROLLBACK', () => { });
              return res.status(400).json({ message: `Teacher with code '${Teacher_Code}' not found or resigned.`, status: false });
            }

            const Teacher_ID = teacherResult[0].Teacher_ID;
            const sqlUser = `INSERT INTO users (Users_Email, Users_Username, Users_Password, Users_Type) VALUES (?, ?, ?, 'student')`;
            db.query(sqlUser, [Users_Email, Users_Username, hashedPassword], (err, userResult) => {
              if (err) {
                db.query('ROLLBACK', () => { });
                if (err.code === 'ER_DUP_ENTRY') {
                  return res.status(409).json({ message: 'Email or username already exists.', status: false });
                }
                console.error('Insert Users Error:', err);
                return res.status(500).json({ message: 'Database error', status: false });
              }

              const Users_ID = userResult.insertId;
              const sqlStudent = `INSERT INTO student (Student_Code, Student_FirstName, 
                Student_LastName, Student_Phone, Student_AcademicYear, Student_Birthdate, Student_Religion, 
                Student_MedicalProblem, Users_ID, Teacher_ID, Department_ID) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

              db.query(sqlStudent, [
                Student_Code, Student_FirstName, Student_LastName, Student_Phone, Student_AcademicYear,
                Student_Birthdate, Student_Religion, Student_MedicalProblem, Users_ID, Teacher_ID, Department_ID
              ], (err, studentResult) => {
                if (err) {
                  db.query('ROLLBACK', () => { });
                  if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ message: 'Student code already exists.', status: false });
                  }
                  console.error('Insert Student Error:', err);
                  return res.status(500).json({ message: 'Database error', status: false });
                }

                // Commit Transaction
                db.query('COMMIT', (err) => {
                  if (err) {
                    db.query('ROLLBACK', () => { });
                    console.error('Commit Error:', err);
                    return res.status(500).json({ message: 'Database error', status: false });
                  }

                  res.status(201).json({
                    message: 'Student imported successfully.',
                    status: true,
                    data: {
                      Users_ID: Users_ID,
                      Student_ID: studentResult.insertId,
                      Student_Code: Student_Code,
                      Student_FirstName: Student_FirstName,
                      Student_LastName: Student_LastName,
                      Users_Email: Users_Email,
                      Users_Username: Users_Username
                    }
                  });
                });
              });
            });
          });
        });
      });
    });
  } catch (err) {
    console.error('Import Student Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Register Teacher from CSV website admin
app.post('/api/admin/users/teacher/import', RateLimiter(1 * 60 * 1000, 1001), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_ID = userData?.Users_ID;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  let { Users_Email, Users_Password, Teacher_Code, Teacher_FirstName, Teacher_LastName, Teacher_Phone,
    Teacher_Birthdate, Teacher_Religion, Teacher_MedicalProblem, Teacher_IsDean, Faculty_Name, Department_Name } = req.body || {};

  if (!Users_Email || !Users_Password || !Teacher_Code || !Teacher_FirstName || !Teacher_LastName || !Faculty_Name || !Department_Name) {
    return res.status(400).json({
      message: 'Please fill in all required fields for CSV import', status: false
    });
  }

  if (!Requester_Users_ID || typeof Requester_Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid token information.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  Users_Email = xss(Users_Email.trim());
  if (!validator.isEmail(Users_Email)) {
    return res.status(400).json({ message: 'Invalid email format.', status: false });
  }

  let Users_Username = Users_Email.split('@')[0];
  Users_Username = xss(Users_Username.trim());

  const usernameRegex = /^[a-zA-Z0-9.\-]+$/;
  if (!usernameRegex.test(Users_Username) || Users_Username.length < 2 || Users_Username.length > 60) {
    return res.status(400).json({
      message: 'Email username part (before @) must be 2-60 characters and can contain letters, numbers, and dot (.) only.',
      status: false
    });
  }

  Users_Password = xss(Users_Password);
  if (!validator.isStrongPassword(Users_Password, { minLength: 8, minNumbers: 1, minSymbols: 0, minUppercase: 0, minLowercase: 0 })) {
    return res.status(400).json({ message: 'Password is not strong enough.', status: false });
  }

  Teacher_Code = xss(Teacher_Code.trim());
  const TeacherCodeRegex = /^\d{12}-\d{1}$/;
  if (!TeacherCodeRegex.test(Teacher_Code)) {
    return res.status(400).json({
      message: 'Teacher code must be in format: 12 digits followed by - and 1 digit (e.g., 026530461001-6)',
      status: false
    });
  }

  Teacher_FirstName = xss(Teacher_FirstName.trim());
  Teacher_LastName = xss(Teacher_LastName.trim());
  Teacher_Phone = Teacher_Phone ? xss(Teacher_Phone.trim()) : null;
  Teacher_Religion = Teacher_Religion ? xss(Teacher_Religion.trim()) : null;
  Teacher_MedicalProblem = Teacher_MedicalProblem ? xss(Teacher_MedicalProblem.trim()) : null;
  if (Teacher_Birthdate) {
    Teacher_Birthdate = xss(Teacher_Birthdate.trim());
    const dateRegex = /^\d{1,2}[-\/]\d{1,2}[-\/]\d{4}$/;

    if (dateRegex.test(Teacher_Birthdate)) {
      const parts = Teacher_Birthdate.split(/[-\/]/);
      const day = parts[0].padStart(2, '0');
      const month = parts[1].padStart(2, '0');
      const buddhistYear = parseInt(parts[2]);

      let christianYear = buddhistYear;
      if (buddhistYear > 2400) {
        christianYear = buddhistYear - 543;
      }

      Teacher_Birthdate = `${christianYear}-${month}-${day}`;
      const birthDate = new Date(Teacher_Birthdate);
      const today = new Date();
      if (birthDate > today) {
        return res.status(400).json({ message: 'Birthdate cannot be in the future.', status: false });
      }

      const age = today.getFullYear() - birthDate.getFullYear();
      const monthDiff = today.getMonth() - birthDate.getMonth();
      const actualAge = (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate()))
        ? age - 1 : age;

      if (actualAge < 20) {
        return res.status(400).json({ message: 'Teacher must be at least 20 years old.', status: false });
      }
    }
  } else {
    Teacher_Birthdate = null;
  }

  Teacher_IsDean = Teacher_IsDean ? Boolean(Teacher_IsDean === 'true' || Teacher_IsDean === true) : false;
  Faculty_Name = xss(Faculty_Name.trim());
  Department_Name = xss(Department_Name.trim());

  try {
    const hashedPassword = await bcrypt.hash(Users_Password, saltRounds);

    // Transaction
    db.query('START TRANSACTION', async (err) => {
      if (err) {
        console.error('Transaction Start Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }
      const facultySql = 'SELECT Faculty_ID FROM faculty WHERE Faculty_Name = ?';
      db.query(facultySql, [Faculty_Name], (err, facultyResult) => {
        if (err) {
          db.query('ROLLBACK', () => { });
          console.error('Find Faculty Error:', err);
          return res.status(500).json({ message: 'Database error', status: false });
        }

        if (facultyResult.length === 0) {
          db.query('ROLLBACK', () => { });
          return res.status(400).json({ message: `Faculty '${Faculty_Name}' not found.`, status: false });
        }

        const Faculty_ID = facultyResult[0].Faculty_ID;
        const departmentSql = 'SELECT Department_ID FROM department WHERE Department_Name = ? AND Faculty_ID = ?';
        db.query(departmentSql, [Department_Name, Faculty_ID], (err, deptResult) => {
          if (err) {
            db.query('ROLLBACK', () => { });
            console.error('Find Department Error:', err);
            return res.status(500).json({ message: 'Database error', status: false });
          }

          if (deptResult.length === 0) {
            db.query('ROLLBACK', () => { });
            return res.status(400).json({ message: `Department '${Department_Name}' not found in faculty '${Faculty_Name}'.`, status: false });
          }

          const Department_ID = deptResult[0].Department_ID;
          const checkDeanProcess = () => {
            if (Teacher_IsDean) {
              const checkDeanSql = `SELECT t.Teacher_ID FROM teacher t INNER JOIN department d ON 
                t.Department_ID = d.Department_ID WHERE d.Faculty_ID = ? AND t.Teacher_IsDean = TRUE AND t.Teacher_IsResign = FALSE`;

              db.query(checkDeanSql, [Faculty_ID], (err, deanResult) => {
                if (err) {
                  db.query('ROLLBACK', () => { });
                  console.error('Check Dean Error:', err);
                  return res.status(500).json({ message: 'Database error', status: false });
                }

                if (deanResult.length > 0) {
                  db.query('ROLLBACK', () => { });
                  return res.status(400).json({ message: 'This faculty already has a dean.', status: false });
                }
                insertTeacher();
              });
            } else {
              insertTeacher();
            }
          };

          const insertTeacher = () => {
            const sqlUser = `INSERT INTO users (Users_Email, Users_Username, Users_Password, Users_Type) VALUES (?, ?, ?, 'teacher')`;
            db.query(sqlUser, [Users_Email, Users_Username, hashedPassword], (err, userResult) => {
              if (err) {
                db.query('ROLLBACK', () => { });
                if (err.code === 'ER_DUP_ENTRY') {
                  return res.status(409).json({ message: 'Email or username already exists.', status: false });
                }
                console.error('Insert Users Error:', err);
                return res.status(500).json({ message: 'Database error', status: false });
              }

              const Users_ID = userResult.insertId;
              const sqlTeacher = `INSERT INTO teacher (Teacher_Code, Teacher_FirstName, 
                Teacher_LastName, Teacher_Phone, Teacher_Birthdate, Teacher_Religion, Teacher_MedicalProblem, 
                Teacher_IsDean, Users_ID, Department_ID) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

              db.query(sqlTeacher, [
                Teacher_Code, Teacher_FirstName, Teacher_LastName, Teacher_Phone, Teacher_Birthdate,
                Teacher_Religion, Teacher_MedicalProblem, Teacher_IsDean, Users_ID, Department_ID
              ], (err, teacherResult) => {
                if (err) {
                  db.query('ROLLBACK', () => { });
                  if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ message: 'Teacher code already exists.', status: false });
                  }
                  console.error('Insert Teacher Error:', err);
                  return res.status(500).json({ message: 'Database error', status: false });
                }

                // Commit Transaction
                db.query('COMMIT', (err) => {
                  if (err) {
                    db.query('ROLLBACK', () => { });
                    console.error('Commit Error:', err);
                    return res.status(500).json({ message: 'Database error', status: false });
                  }

                  res.status(201).json({
                    message: 'Teacher imported successfully.',
                    status: true,
                    data: {
                      Users_ID: Users_ID,
                      Teacher_ID: teacherResult.insertId,
                      Teacher_Code: Teacher_Code,
                      Teacher_FirstName: Teacher_FirstName,
                      Teacher_LastName: Teacher_LastName,
                      Teacher_IsDean: Teacher_IsDean,
                      Users_Email: Users_Email,
                      Users_Username: Users_Username,
                      Department_ID: Department_ID
                    }
                  });
                });
              });
            });
          };

          checkDeanProcess();
        });
      });
    });
  } catch (err) {
    console.error('Import Teacher Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Register Staff from CSV website admin**
app.post('/api/admin/users/staff/import', RateLimiter(1 * 60 * 1000, 1001), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_ID = userData?.Users_ID;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  let { Users_Email, Users_Password, Staff_Code, Staff_FirstName, Staff_LastName, Staff_Phone } = req.body || {};

  if (!Users_Email || !Users_Password || !Staff_Code || !Staff_FirstName || !Staff_LastName) {
    return res.status(400).json({
      message: 'Please fill in all required fields for CSV import',
      status: false
    });
  }

  if (!Requester_Users_ID || typeof Requester_Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid token information.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  Users_Email = xss(Users_Email.trim());
  if (!validator.isEmail(Users_Email)) {
    return res.status(400).json({ message: 'Invalid email format.', status: false });
  }

  let Users_Username = Users_Email.split('@')[0];
  Users_Username = xss(Users_Username.trim());

  const usernameRegex = /^[a-zA-Z0-9.\-]+$/;
  if (!usernameRegex.test(Users_Username) || Users_Username.length < 2 || Users_Username.length > 60) {
    return res.status(400).json({
      message: 'Email username part (before @) must be 2-60 characters and can contain letters, numbers, and dot (.) only.',
      status: false
    });
  }

  Users_Password = xss(Users_Password);
  if (!validator.isStrongPassword(Users_Password, { minLength: 8, minNumbers: 1, minSymbols: 0, minUppercase: 0, minLowercase: 0 })) {
    return res.status(400).json({ message: 'Password is not strong enough.', status: false });
  }

  Staff_Code = xss(Staff_Code.trim());
  const StaffCodeRegex = /^\d{12}-\d{1}$/;
  if (!StaffCodeRegex.test(Staff_Code)) {
    return res.status(400).json({
      message: 'Staff code must be in format: 12 digits followed by - and 1 digit (e.g., 026530461001-6)',
      status: false
    });
  }

  Staff_FirstName = xss(Staff_FirstName.trim());
  Staff_LastName = xss(Staff_LastName.trim());
  Staff_Phone = Staff_Phone ? xss(Staff_Phone.trim()) : null;

  try {
    const hashedPassword = await bcrypt.hash(Users_Password, saltRounds);

    // Transaction
    db.query('START TRANSACTION', async (err) => {
      if (err) {
        console.error('Transaction Start Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }

      const sqlUser = `INSERT INTO users (Users_Email, Users_Username, Users_Password, Users_Type) VALUES (?, ?, ?, 'staff')`;
      db.query(sqlUser, [Users_Email, Users_Username, hashedPassword], (err, userResult) => {
        if (err) {
          db.query('ROLLBACK', () => { });
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Email or username already exists.', status: false });
          }
          console.error('Insert Users Error:', err);
          return res.status(500).json({ message: 'Database error', status: false });
        }

        const Users_ID = userResult.insertId;
        const sqlStaff = `INSERT INTO staff (Staff_Code, Staff_FirstName, Staff_LastName, Staff_Phone, Users_ID) 
          VALUES (?, ?, ?, ?, ?)`;

        db.query(sqlStaff, [Staff_Code, Staff_FirstName, Staff_LastName, Staff_Phone, Users_ID], (err, staffResult) => {
          if (err) {
            db.query('ROLLBACK', () => { });
            if (err.code === 'ER_DUP_ENTRY') {
              return res.status(409).json({ message: 'Staff code already exists.', status: false });
            }
            console.error('Insert Staff Error:', err);
            return res.status(500).json({ message: 'Database error', status: false });
          }

          // Commit Transaction
          db.query('COMMIT', (err) => {
            if (err) {
              db.query('ROLLBACK', () => { });
              console.error('Commit Error:', err);
              return res.status(500).json({ message: 'Database error', status: false });
            }

            res.status(201).json({
              message: 'Staff imported successfully.',
              status: true,
              data: {
                Users_ID: Users_ID,
                Staff_ID: staffResult.insertId,
                Staff_Code: Staff_Code,
                Staff_FirstName: Staff_FirstName,
                Staff_LastName: Staff_LastName,
                Users_Email: Users_Email,
                Users_Username: Users_Username
              }
            });
          });
        });
      });
    });
  } catch (err) {
    console.error('Import Staff Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Get All Faculties website admin
app.get('/api/admin/faculties', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff' && Requester_Users_Type !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  try {
    const sql = `SELECT Faculty_ID, Faculty_Name FROM faculty ORDER BY Faculty_Name ASC`;

    db.query(sql, (err, results) => {
      if (err) {
        console.error('Get Faculties Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }

      res.status(200).json({
        message: 'Faculties retrieved successfully.',
        status: true,
        data: results,
        count: results.length
      });
    });
  } catch (err) {
    console.error('Get Faculties Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Get All Departments website admin
app.get('/api/admin/departments', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff' && Requester_Users_Type !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  try {
    const sql = `SELECT d.Department_ID, d.Department_Name, d.Faculty_ID, f.Faculty_Name 
      FROM department d INNER JOIN faculty f ON d.Faculty_ID = f.Faculty_ID ORDER BY f.Faculty_Name ASC, d.Department_Name ASC`;

    db.query(sql, (err, results) => {
      if (err) {
        console.error('Get Departments Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }

      res.status(200).json({
        message: 'Departments retrieved successfully.', status: true,
        data: results, count: results.length
      });
    });
  } catch (err) {
    console.error('Get Departments Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Get Departments by Faculty ID website admin
app.get('/api/admin/faculties/:facultyId/departments', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const facultyId = parseInt(req.params.facultyId);

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff' && Requester_Users_Type !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  if (isNaN(facultyId) || facultyId <= 0) {
    return res.status(400).json({ message: 'Invalid Faculty ID.', status: false });
  }

  try {
    const checkFacultySql = `SELECT Faculty_ID, Faculty_Name FROM faculty WHERE Faculty_ID = ?`;

    db.query(checkFacultySql, [facultyId], (err, facultyResult) => {
      if (err) {
        console.error('Check Faculty Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }

      if (facultyResult.length === 0) {
        return res.status(404).json({ message: 'Faculty not found.', status: false });
      }

      const sql = `SELECT Department_ID, Department_Name, 
        Faculty_ID FROM department WHERE Faculty_ID = ? ORDER BY Department_Name ASC`;

      db.query(sql, [facultyId], (err, results) => {
        if (err) {
          console.error('Get Departments by Faculty Error:', err);
          return res.status(500).json({ message: 'Database error', status: false });
        }

        res.status(200).json({
          message: 'Departments retrieved successfully.', status: true,
          faculty: facultyResult[0], data: results, count: results.length
        });
      });
    });
  } catch (err) {
    console.error('Get Departments by Faculty Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Get Teachers by Department ID website admin
app.get('/api/admin/departments/:departmentId/teachers', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const departmentId = parseInt(req.params.departmentId);

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff' && Requester_Users_Type !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  if (isNaN(departmentId) || departmentId <= 0) {
    return res.status(400).json({ message: 'Invalid Department ID.', status: false });
  }

  try {
    const checkDepartmentSql = `SELECT d.Department_ID, d.Department_Name, d.Faculty_ID, 
      f.Faculty_Name FROM department d INNER JOIN faculty f ON d.Faculty_ID = f.Faculty_ID WHERE d.Department_ID = ?`;

    db.query(checkDepartmentSql, [departmentId], (err, departmentResult) => {
      if (err) {
        console.error('Check Department Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }

      if (departmentResult.length === 0) {
        return res.status(404).json({ message: 'Department not found.', status: false });
      }

      const sql = `SELECT t.Teacher_ID, t.Teacher_Code, t.Teacher_FirstName, t.Teacher_LastName,
       t.Teacher_Phone, t.Teacher_Birthdate, t.Teacher_Religion, t.Teacher_MedicalProblem, t.Teacher_RegisTime, 
       t.Teacher_IsResign, t.Teacher_IsDean, t.Users_ID, t.Department_ID, u.Users_Email, u.Users_Username, u.Users_RegisTime, 
       u.Users_ImageFile, u.Users_IsActive FROM teacher t INNER JOIN users u ON t.Users_ID = u.Users_ID WHERE t.Department_ID = ? 
       AND t.Teacher_IsResign = FALSE ORDER BY t.Teacher_IsDean DESC, t.Teacher_FirstName ASC, t.Teacher_LastName ASC`;

      db.query(sql, [departmentId], (err, results) => {
        if (err) {
          console.error('Get Teachers by Department Error:', err);
          return res.status(500).json({ message: 'Database error', status: false });
        }

        const teachers = results.map(teacher => ({
          Teacher_ID: teacher.Teacher_ID,
          Teacher_Code: teacher.Teacher_Code,
          Teacher_FirstName: teacher.Teacher_FirstName,
          Teacher_LastName: teacher.Teacher_LastName,
          Teacher_FullName: `${teacher.Teacher_FirstName} ${teacher.Teacher_LastName}`,
          Teacher_Phone: teacher.Teacher_Phone,
          Teacher_Birthdate: teacher.Teacher_Birthdate,
          Teacher_Religion: teacher.Teacher_Religion,
          Teacher_MedicalProblem: teacher.Teacher_MedicalProblem,
          Teacher_RegisTime: teacher.Teacher_RegisTime,
          Teacher_IsDean: teacher.Teacher_IsDean,
          Teacher_IsResign: teacher.Teacher_IsResign,
          Department_ID: teacher.Department_ID,
          Users: {
            Users_ID: teacher.Users_ID,
            Users_Email: teacher.Users_Email,
            Users_Username: teacher.Users_Username,
            Users_RegisTime: teacher.Users_RegisTime,
            Users_ImageFile: teacher.Users_ImageFile,
            Users_IsActive: teacher.Users_IsActive
          }
        }));

        res.status(200).json({
          message: 'Teachers retrieved successfully.',
          status: true,
          department: departmentResult[0],
          data: teachers,
          count: teachers.length
        });
      });
    });
  } catch (err) {
    console.error('Get Teachers by Department Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Get Department Statistics (Teachers and Students count) for Website Admin
app.get('/api/admin/departments/:departmentId/stats', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const departmentId = parseInt(req.params.departmentId);

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff' && Requester_Users_Type !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only staff and teachers can perform this action.", status: false });
  }

  if (isNaN(departmentId) || departmentId <= 0) {
    return res.status(400).json({ message: 'Invalid Department ID.', status: false });
  }

  try {
    const checkDepartmentSql = `SELECT d.Department_ID, d.Department_Name, d.Faculty_ID, 
      f.Faculty_Name FROM department d INNER JOIN faculty f ON d.Faculty_ID = f.Faculty_ID WHERE d.Department_ID = ?`;

    db.query(checkDepartmentSql, [departmentId], (err, departmentResult) => {
      if (err) {
        console.error('Check Department Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }

      if (departmentResult.length === 0) {
        return res.status(404).json({ message: 'Department not found.', status: false });
      }

      const teacherCountSql = `SELECT COUNT(*) as teacher_count FROM teacher WHERE Department_ID = ? AND Teacher_IsResign = FALSE`;
      const studentCountSql = `SELECT COUNT(*) as student_count FROM student WHERE Department_ID = ? AND Student_IsGraduated = FALSE`;

      db.query(teacherCountSql, [departmentId], (teacherErr, teacherResults) => {
        if (teacherErr) {
          console.error('Get Teachers Count Error:', teacherErr);
          return res.status(500).json({ message: 'Database error while counting teachers', status: false });
        }

        db.query(studentCountSql, [departmentId], (studentErr, studentResults) => {
          if (studentErr) {
            console.error('Get Students Count Error:', studentErr);
            return res.status(500).json({ message: 'Database error while counting students', status: false });
          }

          const teacherCount = teacherResults[0]?.teacher_count || 0;
          const studentCount = studentResults[0]?.student_count || 0;
          const totalPersonnel = teacherCount + studentCount;

          res.status(200).json({
            message: 'Department statistics retrieved successfully.',
            status: true,
            department: departmentResult[0],
            data: {
              teacher_count: teacherCount,
              student_count: studentCount,
              total_personnel: totalPersonnel,
              teacher_ratio: totalPersonnel > 0 ? ((teacherCount / totalPersonnel) * 100).toFixed(1) : 0,
              student_ratio: totalPersonnel > 0 ? ((studentCount / totalPersonnel) * 100).toFixed(1) : 0
            }
          });
        });
      });
    });

  } catch (err) {
    console.error('Get Department Statistics Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Get All Departments Statistics for Website Admin
app.get('/api/admin/departments/stats/all', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff' && Requester_Users_Type !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only staff and teachers can perform this action.", status: false });
  }

  try {
    const sql = `SELECT 
      d.Department_ID, d.Department_Name, d.Faculty_ID,f.Faculty_Name,COALESCE(t.teacher_count, 0) as teacher_count, 
        COALESCE(s.student_count, 0) as student_count FROM department d INNER JOIN faculty f ON d.Faculty_ID = f.Faculty_ID 
        LEFT JOIN ( SELECT Department_ID, COUNT(*) as teacher_count FROM teacher WHERE Teacher_IsResign = FALSE GROUP BY Department_ID) 
        t ON d.Department_ID = t.Department_ID LEFT JOIN ( SELECT Department_ID, COUNT(*) as student_count FROM student WHERE 
        Student_IsGraduated = FALSE GROUP BY Department_ID) s ON d.Department_ID = s.Department_ID ORDER BY f.Faculty_Name ASC, d.Department_Name ASC`;

    db.query(sql, (err, results) => {
      if (err) {
        console.error('Get All Departments Statistics Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }

      const departmentsWithStats = results.map(dept => ({
        Department_ID: dept.Department_ID,
        Department_Name: dept.Department_Name,
        Faculty_ID: dept.Faculty_ID,
        Faculty_Name: dept.Faculty_Name,
        teacher_count: dept.teacher_count,
        student_count: dept.student_count,
        total_personnel: dept.teacher_count + dept.student_count,
        teacher_ratio: (dept.teacher_count + dept.student_count) > 0 ?
          ((dept.teacher_count / (dept.teacher_count + dept.student_count)) * 100).toFixed(1) : 0,
        student_ratio: (dept.teacher_count + dept.student_count) > 0 ?
          ((dept.student_count / (dept.teacher_count + dept.student_count)) * 100).toFixed(1) : 0
      }));

      const totalStats = departmentsWithStats.reduce((acc, dept) => ({
        total_departments: acc.total_departments + 1,
        total_teachers: acc.total_teachers + dept.teacher_count,
        total_students: acc.total_students + dept.student_count,
        total_personnel: acc.total_personnel + dept.total_personnel
      }), {
        total_departments: 0,
        total_teachers: 0,
        total_students: 0,
        total_personnel: 0
      });

      res.status(200).json({
        message: 'All departments statistics retrieved successfully.',
        status: true,
        data: departmentsWithStats,
        summary: {
          ...totalStats,
          faculties_count: [...new Set(departmentsWithStats.map(d => d.Faculty_ID))].length,
          avg_teachers_per_dept: totalStats.total_departments > 0 ?
            (totalStats.total_teachers / totalStats.total_departments).toFixed(1) : 0,
          avg_students_per_dept: totalStats.total_departments > 0 ?
            (totalStats.total_students / totalStats.total_departments).toFixed(1) : 0,
          teacher_student_ratio: totalStats.total_students > 0 ?
            `1:${Math.round(totalStats.total_students / totalStats.total_teachers)}` : 'N/A'
        },
        count: departmentsWithStats.length
      });
    });

  } catch (err) {
    console.error('Get All Departments Statistics Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Get User Detail by ID for Website Admin**
app.get('/api/admin/users/:id', RateLimiter(1 * 60 * 1000, 150), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const userId = parseInt(req.params.id);

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  if (!userId || isNaN(userId)) {
    return res.status(400).json({ message: "Invalid user ID provided.", status: false });
  }

  try {
    const userSql = `SELECT u.Users_ID, u.Users_Email, u.Users_Username, u.Users_RegisTime, 
      u.Users_ImageFile, u.Users_Type, u.Users_IsActive 
      FROM users u WHERE u.Users_ID = ?`;

    db.query(userSql, [userId], (err, userResults) => {
      if (err) {
        console.error('Get User Detail Error:', err);
        return res.status(500).json({ message: 'Database error while fetching user details.', status: false });
      }

      if (userResults.length === 0) {
        return res.status(404).json({ message: 'User not found.', status: false });
      }

      const user = userResults[0];

      const userDetail = {
        id: user.Users_ID,
        email: user.Users_Email,
        username: user.Users_Username,
        userType: user.Users_Type,
        isActive: user.Users_IsActive,
        regisTime: user.Users_RegisTime,
        imageFile: user.Users_ImageFile
      };

      res.status(200).json({
        message: 'User details retrieved successfully.',
        status: true,
        data: userDetail
      });
    });

  } catch (err) {
    console.error('Get User Detail Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while fetching user details.',
      status: false
    });
  }
});

// API Get All Teachers with Pagination, Filtering, and Search of Website Admin
app.get('/api/admin/teachers', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff' && Requester_Users_Type !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only staff and teachers can perform this action.", status: false });
  }

  const includeResigned = req.query.includeResigned === 'true';
  const departmentId = req.query.departmentId ? parseInt(req.query.departmentId) : null;
  const facultyId = req.query.facultyId ? parseInt(req.query.facultyId) : null;
  const search = req.query.search ? req.query.search.trim() : '';

  try {
    let whereConditions = [];
    let queryParams = [];

    if (!includeResigned) {
      whereConditions.push('t.Teacher_IsResign = FALSE');
    }

    if (facultyId) {
      whereConditions.push('f.Faculty_ID = ?');
      queryParams.push(facultyId);
    }

    if (departmentId) {
      whereConditions.push('t.Department_ID = ?');
      queryParams.push(departmentId);
    }

    if (search) {
      whereConditions.push(`(t.Teacher_FirstName LIKE ? OR t.Teacher_LastName LIKE ? OR t.Teacher_Code LIKE ? OR u.Users_Email LIKE ?)`);
      const searchTerm = `%${search}%`;
      queryParams.push(searchTerm, searchTerm, searchTerm, searchTerm);
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

    const sql = `SELECT t.Teacher_ID, t.Teacher_Code, t.Teacher_FirstName, t.Teacher_LastName, 
      t.Teacher_Phone, t.Teacher_Birthdate, t.Teacher_Religion, t.Teacher_MedicalProblem, 
      t.Teacher_RegisTime, t.Teacher_IsResign, t.Teacher_IsDean, t.Users_ID, t.Department_ID, 
      d.Department_Name, f.Faculty_ID, f.Faculty_Name, u.Users_Email, u.Users_Username, 
      u.Users_RegisTime, u.Users_ImageFile, u.Users_IsActive FROM teacher t 
      INNER JOIN users u ON t.Users_ID = u.Users_ID INNER JOIN department d ON t.Department_ID = d.Department_ID 
      INNER JOIN faculty f ON d.Faculty_ID = f.Faculty_ID ${whereClause} 
      ORDER BY t.Teacher_IsDean DESC, f.Faculty_Name ASC, d.Department_Name ASC, 
      t.Teacher_FirstName ASC, t.Teacher_LastName ASC`;

    db.query(sql, queryParams, (err, results) => {
      if (err) {
        console.error('Get Teachers Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }

      const teachers = results.map(teacher => ({
        Teacher_ID: teacher.Teacher_ID,
        Teacher_Code: teacher.Teacher_Code,
        Teacher_FirstName: teacher.Teacher_FirstName,
        Teacher_LastName: teacher.Teacher_LastName,
        Teacher_FullName: `${teacher.Teacher_FirstName} ${teacher.Teacher_LastName}`,
        Teacher_Phone: teacher.Teacher_Phone,
        Teacher_Birthdate: teacher.Teacher_Birthdate,
        Teacher_Religion: teacher.Teacher_Religion,
        Teacher_MedicalProblem: teacher.Teacher_MedicalProblem,
        Teacher_RegisTime: teacher.Teacher_RegisTime,
        Teacher_IsDean: teacher.Teacher_IsDean,
        Teacher_IsResign: teacher.Teacher_IsResign,
        Department: {
          Department_ID: teacher.Department_ID,
          Department_Name: teacher.Department_Name,
          Faculty_ID: teacher.Faculty_ID,
          Faculty_Name: teacher.Faculty_Name
        },
        Users: {
          Users_ID: teacher.Users_ID,
          Users_Email: teacher.Users_Email,
          Users_Username: teacher.Users_Username,
          Users_RegisTime: teacher.Users_RegisTime,
          Users_ImageFile: teacher.Users_ImageFile,
          Users_IsActive: teacher.Users_IsActive
        }
      }));

      res.status(200).json({
        message: 'Teachers retrieved successfully.',
        status: true,
        data: teachers,
        count: teachers.length
      });
    });
  } catch (err) {
    console.error('Get Teachers Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Get Teacher Detail by ID for Website Admin
app.get('/api/admin/teachers/:id', RateLimiter(1 * 60 * 1000, 150), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const teacherId = parseInt(req.params.id);

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff' && Requester_Users_Type !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only staff and teachers can perform this action.", status: false });
  }

  if (!teacherId || isNaN(teacherId)) {
    return res.status(400).json({ message: "Invalid teacher ID provided.", status: false });
  }

  try {
    const teacherSql = `SELECT t.Teacher_ID, t.Teacher_Code, t.Teacher_FirstName, t.Teacher_LastName, 
      t.Teacher_Phone, t.Teacher_Birthdate, t.Teacher_Religion, t.Teacher_MedicalProblem, 
      t.Teacher_RegisTime, t.Teacher_IsResign, t.Teacher_IsDean, t.Users_ID, t.Department_ID, 
      d.Department_Name, f.Faculty_ID, f.Faculty_Name, u.Users_Email, u.Users_Username, 
      u.Users_RegisTime, u.Users_ImageFile, u.Users_IsActive FROM teacher t 
      INNER JOIN users u ON t.Users_ID = u.Users_ID INNER JOIN department d ON t.Department_ID = d.Department_ID 
      INNER JOIN faculty f ON d.Faculty_ID = f.Faculty_ID WHERE t.Teacher_ID = ?`;

    db.query(teacherSql, [teacherId], (err, teacherResults) => {
      if (err) {
        console.error('Get Teacher Detail Error:', err);
        return res.status(500).json({ message: 'Database error while fetching teacher details.', status: false });
      }

      if (teacherResults.length === 0) {
        return res.status(404).json({ message: 'Teacher not found.', status: false });
      }

      const teacher = teacherResults[0];
      const otherPhonesSql = `SELECT OtherPhone_ID, OtherPhone_Name, OtherPhone_Phone FROM otherphone WHERE Users_ID = ? ORDER BY OtherPhone_ID ASC`;

      db.query(otherPhonesSql, [teacher.Users_ID], (err, phoneResults) => {
        if (err) {
          console.error('Get Other Phones Error:', err);
          phoneResults = [];
        }

        const otherPhones = phoneResults.map(phone => ({
          id: phone.OtherPhone_ID,
          name: phone.OtherPhone_Name,
          phone: phone.OtherPhone_Phone
        }));

        if (otherPhones.length === 0) {
          otherPhones.push({ name: '', phone: '' });
        }

        const teacherDetail = {
          id: teacher.Teacher_ID,
          email: teacher.Users_Email,
          username: teacher.Users_Username,
          userType: 'teacher',
          Users_ID: teacher.Users_ID,
          isActive: teacher.Users_IsActive,
          regisTime: teacher.Users_RegisTime,
          imageFile: teacher.Users_ImageFile,
          teacher: {
            code: teacher.Teacher_Code,
            firstName: teacher.Teacher_FirstName,
            lastName: teacher.Teacher_LastName,
            phone: teacher.Teacher_Phone,
            otherPhones: otherPhones,
            birthdate: teacher.Teacher_Birthdate,
            religion: teacher.Teacher_Religion,
            medicalProblem: teacher.Teacher_MedicalProblem,
            department: teacher.Department_Name,
            faculty: teacher.Faculty_Name,
            isDean: teacher.Teacher_IsDean,
            isResigned: teacher.Teacher_IsResign,
            regisTime: teacher.Teacher_RegisTime
          },
          department: {
            id: teacher.Department_ID,
            name: teacher.Department_Name,
            faculty: {
              id: teacher.Faculty_ID,
              name: teacher.Faculty_Name
            }
          }
        };

        res.status(200).json({
          message: 'Teacher details retrieved successfully.',
          status: true,
          data: teacherDetail
        });
      });
    });

  } catch (err) {
    console.error('Get Teacher Detail Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while fetching teacher details.',
      status: false
    });
  }
});

// API Update Teacher Detail by ID for Website Admin
app.put('/api/admin/teachers/:id', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const teacherId = parseInt(req.params.id);
  const updateData = req.body;

  if (!userData) {
    return res.status(401).json({ message: "Authentication required.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  if (!teacherId || isNaN(teacherId)) {
    return res.status(400).json({ message: "Invalid teacher ID provided.", status: false });
  }

  if (!updateData.teacher) {
    return res.status(400).json({ message: "Teacher data is required.", status: false });
  }

  const {
    code, firstName, lastName, phone, otherPhones, birthdate, religion,
    medicalProblem, isDean, isResigned
  } = updateData.teacher;

  if (!firstName || !lastName) {
    return res.status(400).json({ message: "First name and last name are required.", status: false });
  }

  const convertBooleanToInt = (value) => {
    if (value === true || value === 'true' || value === 1 || value === '1') {
      return 1;
    }
    return 0;
  };

  const formatDateForMySQL = (dateString) => {
    if (!dateString) return null;
    try {
      const date = new Date(dateString);
      if (isNaN(date.getTime())) return null;
      const year = date.getFullYear();
      const month = String(date.getMonth() + 1).padStart(2, '0');
      const day = String(date.getDate()).padStart(2, '0');
      return `${year}-${month}-${day}`;
    } catch (error) {
      console.error('Date formatting error:', error);
      return null;
    }
  };

  const formattedBirthdate = formatDateForMySQL(birthdate);

  try {
    const queryDatabase = (sql, params = []) => {
      return new Promise((resolve, reject) => {
        db.query(sql, params, (err, results) => {
          if (err) {
            console.error('Database query error:', err);
            reject(err);
          } else {
            resolve(results);
          }
        });
      });
    };

    await queryDatabase('START TRANSACTION');

    try {
      const checkSql = `SELECT Users_ID FROM teacher WHERE Teacher_ID = ?`;
      const checkResults = await queryDatabase(checkSql, [teacherId]);

      if (checkResults.length === 0) {
        await queryDatabase('ROLLBACK');
        return res.status(404).json({ message: 'Teacher not found.', status: false });
      }

      const usersId = checkResults[0].Users_ID;
      const updateTeacherSql = `UPDATE teacher SET Teacher_Code = ?, Teacher_FirstName = ?, 
        Teacher_LastName = ?, Teacher_Phone = ?, Teacher_Birthdate = ?, Teacher_Religion = ?, 
        Teacher_MedicalProblem = ?, Teacher_IsDean = ?, Teacher_IsResign = ? WHERE Teacher_ID = ?`;

      const teacherParams = [
        code || null,
        firstName,
        lastName,
        phone || null,
        formattedBirthdate,
        religion || null,
        medicalProblem || null,
        convertBooleanToInt(isDean),
        convertBooleanToInt(isResigned),
        teacherId
      ];

      await queryDatabase(updateTeacherSql, teacherParams);
      if (otherPhones && Array.isArray(otherPhones)) {
        await queryDatabase(`DELETE FROM otherphone WHERE Users_ID = ?`, [usersId]);
        const validPhones = otherPhones.filter(phone =>
          phone.name?.trim() || phone.phone?.trim()
        );

        if (validPhones.length > 0) {
          const insertPhonesSql = `INSERT INTO otherphone (OtherPhone_Name, OtherPhone_Phone, Users_ID) VALUES ?`;
          const phoneValues = validPhones.map(phone => [
            phone.name?.trim() || '',
            phone.phone?.trim() || '',
            usersId
          ]);

          await queryDatabase(insertPhonesSql, [phoneValues]);
        }
      }

      await queryDatabase('COMMIT');

      const response = {
        message: 'Teacher details updated successfully.',
        status: true,
        data: {
          teacherId: teacherId,
          updated: true,
          timestamp: new Date().toISOString()
        }
      };

      res.status(200).json(response);

    } catch (transactionError) {
      console.error('Transaction error:', transactionError);
      await queryDatabase('ROLLBACK');
      res.status(500).json({
        message: 'Database transaction failed.',
        status: false
      });
    }

  } catch (err) {
    console.error('Unexpected error in teacher update:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while updating teacher details.',
      status: false
    });
  }
});

// API Get Teachers for Advisor Dropdown
app.get('/api/admin/teacher-advisors', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (!userData) {
    return res.status(401).json({ message: "Authentication required.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. Website access required.", status: false });
  }

  if (!Requester_Users_Type || !['staff', 'teacher'].includes(Requester_Users_Type)) {
    return res.status(403).json({ message: "Permission denied. Staff, teacher, or admin access required.", status: false });
  }

  try {
    const sql = `SELECT t.Teacher_ID, t.Teacher_FirstName, t.Teacher_LastName, t.Teacher_Code, 
      d.Department_Name, f.Faculty_Name FROM teacher t INNER JOIN department d ON t.Department_ID = d.Department_ID 
      INNER JOIN faculty f ON d.Faculty_ID = f.Faculty_ID WHERE t.Teacher_IsResign = FALSE ORDER BY f.Faculty_Name ASC, 
      d.Department_Name ASC, t.Teacher_FirstName ASC, t.Teacher_LastName ASC`;

    const executeQuery = () => {
      return new Promise((resolve, reject) => {
        db.query(sql, (err, results) => {
          if (err) {
            reject(err);
          } else {
            resolve(results);
          }
        });
      });
    };

    const results = await executeQuery();
    if (!results || results.length === 0) {
      return res.status(200).json({
        message: 'No teachers found.',
        status: true,
        data: [],
        count: 0
      });
    }

    try {
      const teachers = results.map((teacher, index) => {
        const firstName = teacher.Teacher_FirstName || '';
        const lastName = teacher.Teacher_LastName || '';
        const departmentName = teacher.Department_Name || '';
        return {
          Teacher_ID: teacher.Teacher_ID,
          Teacher_Code: teacher.Teacher_Code || '',
          Teacher_Name: `${firstName} ${lastName}`.trim(),
          Teacher_FirstName: firstName,
          Teacher_LastName: lastName,
          Department_Name: departmentName,
          Faculty_Name: teacher.Faculty_Name || '',
          Display_Name: `${firstName} ${lastName} (${departmentName})`.trim()
        };
      });

      res.status(200).json({
        message: 'Teachers retrieved successfully.',
        status: true,
        data: teachers,
        count: teachers.length,
        debug: {
          endpoint: 'teacher-advisors',
          user_type: Requester_Users_Type,
          query_time: new Date().toISOString()
        }
      });

    } catch (processingError) {
      console.error('Error processing teachers data:', processingError);
      res.status(500).json({
        message: 'Error processing teachers data.',
        status: false,
      });
    }

  } catch (err) {
    console.error('Error fetching teacher advisors:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//admin teachers get teacherId
app.get('/api/admin/teachers/:teacherId', RateLimiter(1 * 60 * 1000, 100), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const teacherId = parseInt(req.params.teacherId);

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (!['staff', 'teacher', 'admin'].includes(Requester_Users_Type)) {
    return res.status(403).json({
      message: "Permission denied. Only staff, teachers, and administrators can perform this action.",
      status: false
    });
  }

  if (!teacherId || isNaN(teacherId)) {
    return res.status(400).json({
      message: "Invalid teacher ID provided.",
      status: false
    });
  }

  try {
    const sql = `SELECT t.Teacher_ID, t.Teacher_FirstName, t.Teacher_LastName, t.Teacher_Code, 
      d.Department_Name, f.Faculty_Name, t.Teacher_IsResign FROM teacher t INNER JOIN department d ON 
      t.Department_ID = d.Department_ID INNER JOIN faculty f ON d.Faculty_ID = f.Faculty_ID WHERE t.Teacher_ID = ?`;

    db.query(sql, [teacherId], (err, results) => {
      if (err) {
        console.error('Database query error for individual teacher:', err);
        return res.status(500).json({
          message: 'Database error.',
          status: false
        });
      }

      if (results.length === 0) {
        return res.status(404).json({
          message: 'Teacher not found.',
          status: false
        });
      }

      const teacher = results[0];
      const teacherData = {
        Teacher_ID: teacher.Teacher_ID,
        Teacher_Code: teacher.Teacher_Code || '',
        Teacher_Name: `${teacher.Teacher_FirstName || ''} ${teacher.Teacher_LastName || ''}`.trim(),
        Teacher_FirstName: teacher.Teacher_FirstName || '',
        Teacher_LastName: teacher.Teacher_LastName || '',
        Department_Name: teacher.Department_Name || '',
        Faculty_Name: teacher.Faculty_Name || '',
        Display_Name: `${teacher.Teacher_FirstName || ''} ${teacher.Teacher_LastName || ''} (${teacher.Department_Name || ''})`.trim(),
        isResigned: teacher.Teacher_IsResign || false
      };

      res.status(200).json({
        message: 'Teacher retrieved successfully.',
        status: true,
        data: teacherData
      });
    });

  } catch (err) {
    console.error('Unexpected error in individual teacher API:', err);
    res.status(500).json({
      message: 'An unexpected error occurred.',
      status: false
    });
  }
});

// API Update Student's Department, Faculty, and Advisor - Improved
app.put('/api/admin/students/:id/assignment', RateLimiter(1 * 60 * 1000, 50), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const studentId = parseInt(req.params.id);
  const { Department_ID, Teacher_ID } = req.body;

  if (!userData) {
    return res.status(401).json({
      message: "Authentication required.",
      status: false
    });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (!['staff', 'admin', 'teacher'].includes(Requester_Users_Type)) {
    return res.status(403).json({
      message: "Permission denied. Only staff, administrators, and teachers can change student assignments.",
      status: false
    });
  }

  if (!studentId || isNaN(studentId)) {
    return res.status(400).json({
      message: "Invalid student ID provided.",
      status: false
    });
  }

  if (Department_ID === null || Department_ID === undefined || isNaN(Department_ID)) {
    return res.status(400).json({
      message: "Department ID is required and must be a valid number.",
      status: false
    });
  }

  if (Teacher_ID === null || Teacher_ID === undefined || isNaN(Teacher_ID)) {
    return res.status(400).json({
      message: "Teacher ID is required and must be a valid number.",
      status: false
    });
  }

  try {
    const queryDatabase = (sql, params = []) => {
      return new Promise((resolve, reject) => {
        db.query(sql, params, (err, results) => {
          if (err) {
            reject(err);
          } else {
            resolve(results);
          }
        });
      });
    };

    await queryDatabase('START TRANSACTION');

    try {
      const checkStudentSql = `SELECT Student_ID, Users_ID FROM student WHERE Student_ID = ?`;
      const studentResults = await queryDatabase(checkStudentSql, [studentId]);

      if (studentResults.length === 0) {
        await queryDatabase('ROLLBACK');
        return res.status(404).json({
          message: 'Student not found.',
          status: false
        });
      }

      const checkDepartmentSql = `SELECT Department_ID, Faculty_ID FROM department WHERE Department_ID = ?`;
      const deptResults = await queryDatabase(checkDepartmentSql, [Department_ID]);

      if (deptResults.length === 0) {
        await queryDatabase('ROLLBACK');
        return res.status(400).json({
          message: 'Invalid Department ID.',
          status: false
        });
      }

      const checkTeacherSql = `SELECT Teacher_ID FROM teacher WHERE Teacher_ID = ? AND Department_ID = ? AND Teacher_IsResign = FALSE`;
      const teacherResults = await queryDatabase(checkTeacherSql, [Teacher_ID, Department_ID]);

      if (teacherResults.length === 0) {
        await queryDatabase('ROLLBACK');
        return res.status(400).json({
          message: 'Invalid Teacher ID or teacher does not belong to the selected department.',
          status: false
        });
      }

      const updateStudentSql = `UPDATE student SET Department_ID = ?, Teacher_ID = ? WHERE Student_ID = ?`;
      const updateResult = await queryDatabase(updateStudentSql, [Department_ID, Teacher_ID, studentId]);

      if (updateResult.affectedRows === 0) {
        await queryDatabase('ROLLBACK');
        return res.status(500).json({
          message: 'Failed to update student assignment.',
          status: false
        });
      }

      await queryDatabase('COMMIT');
      res.status(200).json({
        message: 'Student assignment updated successfully.',
        status: true,
        data: {
          studentId: studentId,
          Department_ID: Department_ID,
          Teacher_ID: Teacher_ID,
          updated: true
        }
      });

    } catch (transactionError) {
      await queryDatabase('ROLLBACK');
      throw transactionError;
    }

  } catch (err) {
    res.status(500).json({
      message: 'An unexpected error occurred while updating student assignment.',
      status: false
    });
  }
});

// API Update Teacher Status for Website Admin (Active/Inactive)**
app.patch('/api/admin/teachers/:id/status', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const teacherId = parseInt(req.params.id);
  const { isActive } = req.body;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can change user status.", status: false });
  }

  if (!teacherId || isNaN(teacherId) || teacherId <= 0 || teacherId > 2147483647) {
    return res.status(400).json({ message: "Invalid teacher ID provided.", status: false });
  }

  if (typeof isActive !== 'boolean') {
    return res.status(400).json({ message: "Invalid status value. Must be true or false.", status: false });
  }

  try {
    const checkSql = `SELECT t.Teacher_ID, t.Users_ID, u.Users_IsActive, t.Teacher_FirstName, t.Teacher_LastName FROM 
      teacher t INNER JOIN users u ON t.Users_ID = u.Users_ID WHERE t.Teacher_ID = ?`;

    db.query(checkSql, [teacherId], (err, checkResults) => {
      if (err) {
        console.error('Check Teacher Error:', err);
        return res.status(500).json({ message: 'Database error while checking teacher.', status: false });
      }

      if (checkResults.length === 0) {
        return res.status(404).json({ message: 'Teacher not found.', status: false });
      }

      const teacher = checkResults[0];
      if (teacher.Users_IsActive === isActive) {
        return res.status(400).json({ message: `Teacher is already ${isActive ? 'active' : 'inactive'}.`, status: false });
      }

      const updateSql = `UPDATE users SET Users_IsActive = ? WHERE Users_ID = ?`;
      db.query(updateSql, [isActive, teacher.Users_ID], (err, updateResult) => {
        if (err) {
          console.error('Update Status Error:', err);
          return res.status(500).json({ message: 'Database error while updating status.', status: false });
        }

        if (updateResult.affectedRows === 0) {
          return res.status(500).json({ message: 'Failed to update user status.', status: false });
        }

        res.status(200).json({
          message: `Teacher status updated successfully to ${isActive ? 'active' : 'inactive'}.`,
          status: true,
          data: {
            teacherId: teacherId,
            isActive: isActive,
            updatedBy: userData.Users_Username || userData.Users_Email,
            updatedAt: new Date().toISOString()
          }
        });
      });
    });
  } catch (err) {
    console.error('Update Teacher Status Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while updating teacher status.',
      status: false
    });
  }
});

// API Get Teacher Basic Info for Website Admin
app.get('/api/admin/teachers/:id/basic', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const teacherId = parseInt(req.params.id);

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff' && Requester_Users_Type !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only staff and teachers can access this information.", status: false });
  }

  if (!teacherId || isNaN(teacherId) || teacherId <= 0 || teacherId > 2147483647) {
    return res.status(400).json({ message: "Invalid teacher ID provided.", status: false });
  }

  try {
    const sql = `SELECT t.Teacher_ID, t.Teacher_Code, t.Teacher_FirstName, t.Teacher_LastName, 
      t.Teacher_IsDean, t.Teacher_IsResign, u.Users_IsActive, u.Users_Email, d.Department_Name, f.Faculty_Name 
      FROM teacher t INNER JOIN users u ON t.Users_ID = u.Users_ID INNER JOIN department d ON t.Department_ID = d.Department_ID 
      INNER JOIN faculty f ON d.Faculty_ID = f.Faculty_ID WHERE t.Teacher_ID = ?`;

    db.query(sql, [teacherId], (err, results) => {
      if (err) {
        console.error('Get Teacher Basic Info Error:', err);
        return res.status(500).json({ message: 'Database error while fetching teacher basic information.', status: false });
      }

      if (results.length === 0) {
        return res.status(404).json({ message: 'Teacher not found.', status: false });
      }

      const teacher = results[0];
      const basicInfo = {
        id: teacher.Teacher_ID,
        code: teacher.Teacher_Code,
        firstName: teacher.Teacher_FirstName,
        lastName: teacher.Teacher_LastName,
        fullName: `${teacher.Teacher_FirstName} ${teacher.Teacher_LastName}`,
        email: teacher.Users_Email,
        department: teacher.Department_Name,
        faculty: teacher.Faculty_Name,
        isActive: teacher.Users_IsActive,
        isDean: teacher.Teacher_IsDean,
        isResigned: teacher.Teacher_IsResign,
        userType: 'teacher'
      };

      res.status(200).json({ message: 'Teacher basic information retrieved successfully.', status: true, data: basicInfo });
    });

  } catch (err) {
    console.error('Get Teacher Basic Info Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while fetching teacher basic information.',
      status: false
    });
  }
});

// API Get All Students with Filtering, and Search of Website Admin
app.get('/api/admin/students', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff' && Requester_Users_Type !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  const includeGraduated = req.query.includeGraduated === 'true';
  const departmentId = req.query.departmentId ? parseInt(req.query.departmentId) : null;
  const facultyId = req.query.facultyId ? parseInt(req.query.facultyId) : null;
  const academicYear = req.query.academicYear ? parseInt(req.query.academicYear) : null;
  const search = req.query.search ? req.query.search.trim() : '';

  try {
    let whereConditions = [];
    let queryParams = [];

    if (!includeGraduated) {
      whereConditions.push('s.Student_IsGraduated = FALSE');
    }

    if (facultyId) {
      whereConditions.push('f.Faculty_ID = ?');
      queryParams.push(facultyId);
    }

    if (departmentId) {
      whereConditions.push('s.Department_ID = ?');
      queryParams.push(departmentId);
    }

    if (academicYear) {
      whereConditions.push('s.Student_AcademicYear = ?');
      queryParams.push(academicYear);
    }

    if (search) {
      whereConditions.push(`(s.Student_FirstName LIKE ? OR s.Student_LastName LIKE ? OR s.Student_Code LIKE ? OR u.Users_Email LIKE ?)`);
      const searchTerm = `%${search}%`;
      queryParams.push(searchTerm, searchTerm, searchTerm, searchTerm);
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';
    const sql = `SELECT s.Student_ID, s.Student_Code, s.Student_FirstName, s.Student_LastName, 
      s.Student_Phone, s.Student_AcademicYear, s.Student_Birthdate, s.Student_Religion, s.Student_MedicalProblem, 
      s.Student_RegisTime, s.Student_IsGraduated, s.Users_ID, s.Teacher_ID, s.Department_ID, d.Department_Name, f.Faculty_ID, 
      f.Faculty_Name, u.Users_Email, u.Users_Username, u.Users_RegisTime, u.Users_ImageFile, u.Users_IsActive FROM student s INNER JOIN 
      users u ON s.Users_ID = u.Users_ID INNER JOIN department d ON s.Department_ID = d.Department_ID INNER JOIN faculty f ON d.Faculty_ID = f.Faculty_ID 
      ${whereClause} ORDER BY f.Faculty_Name ASC, d.Department_Name ASC, s.Student_AcademicYear DESC, s.Student_FirstName ASC, s.Student_LastName ASC`;

    db.query(sql, queryParams, (err, results) => {
      if (err) {
        console.error('Get Students Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }

      const students = results.map(student => ({
        Student_ID: student.Student_ID,
        Student_Code: student.Student_Code,
        Student_FirstName: student.Student_FirstName,
        Student_LastName: student.Student_LastName,
        Student_FullName: `${student.Student_FirstName} ${student.Student_LastName}`,
        Student_Phone: student.Student_Phone,
        Student_AcademicYear: student.Student_AcademicYear,
        Student_Birthdate: student.Student_Birthdate,
        Student_Religion: student.Student_Religion,
        Student_MedicalProblem: student.Student_MedicalProblem,
        Student_RegisTime: student.Student_RegisTime,
        Student_IsGraduated: student.Student_IsGraduated,
        Department: {
          Department_ID: student.Department_ID,
          Department_Name: student.Department_Name,
          Faculty_ID: student.Faculty_ID,
          Faculty_Name: student.Faculty_Name
        },
        Users: {
          Users_ID: student.Users_ID,
          Users_Email: student.Users_Email,
          Users_Username: student.Users_Username,
          Users_RegisTime: student.Users_RegisTime,
          Users_ImageFile: student.Users_ImageFile,
          Users_IsActive: student.Users_IsActive
        }
      }));

      res.status(200).json({
        message: 'Students retrieved successfully.',
        status: true,
        data: students,
        count: students.length
      });
    });
  } catch (err) {
    console.error('Get Students Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Get Student Detail by ID for Website Admin
app.get('/api/admin/students/:id', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const studentId = parseInt(req.params.id);

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff' && Requester_Users_Type !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only staff and teachers can perform this action.", status: false });
  }

  if (!studentId || isNaN(studentId)) {
    return res.status(400).json({ message: "Invalid student ID provided.", status: false });
  }

  try {
    const studentSql = `SELECT s.Student_ID, s.Student_Code, s.Student_FirstName, s.Student_LastName, 
      s.Student_Phone, s.Student_AcademicYear, s.Student_Birthdate, s.Student_Religion, s.Student_MedicalProblem, 
      s.Student_RegisTime, s.Student_IsGraduated, s.Users_ID, s.Teacher_ID, s.Department_ID, d.Department_Name, f.Faculty_ID, 
      f.Faculty_Name, u.Users_Email, u.Users_Username, u.Users_RegisTime, u.Users_ImageFile, u.Users_IsActive, t.Teacher_FirstName AS Advisor_FirstName, 
      t.Teacher_LastName AS Advisor_LastName FROM student s INNER JOIN users u ON s.Users_ID = u.Users_ID INNER JOIN department d ON s.Department_ID = d.Department_ID 
      INNER JOIN faculty f ON d.Faculty_ID = f.Faculty_ID LEFT JOIN teacher t ON s.Teacher_ID = t.Teacher_ID WHERE s.Student_ID = ?`;
    db.query(studentSql, [studentId], (err, studentResults) => {
      if (err) {
        console.error('Get Student Detail Error:', err);
        return res.status(500).json({ message: 'Database error while fetching student details.', status: false });
      }

      if (studentResults.length === 0) {
        return res.status(404).json({ message: 'Student not found.', status: false });
      }

      const student = studentResults[0];
      const otherPhonesSql = `SELECT OtherPhone_ID, OtherPhone_Name, OtherPhone_Phone FROM otherphone WHERE Users_ID = ? ORDER BY OtherPhone_ID ASC`;
      db.query(otherPhonesSql, [student.Users_ID], (err, phoneResults) => {
        if (err) {
          console.error('Get Other Phones Error:', err);
          phoneResults = [];
        }

        const otherPhones = phoneResults.map(phone => ({
          id: phone.OtherPhone_ID,
          name: phone.OtherPhone_Name,
          phone: phone.OtherPhone_Phone
        }));

        if (otherPhones.length === 0) {
          otherPhones.push({ name: '', phone: '' });
        }

        const studentDetail = {
          id: student.Student_ID,
          email: student.Users_Email,
          username: student.Users_Username,
          userType: 'student',
          Users_ID: student.Users_ID,
          isActive: student.Users_IsActive,
          regisTime: student.Users_RegisTime,
          imageFile: student.Users_ImageFile,
          student: {
            code: student.Student_Code,
            firstName: student.Student_FirstName,
            lastName: student.Student_LastName,
            phone: student.Student_Phone,
            otherPhones: otherPhones,
            academicYear: student.Student_AcademicYear,
            birthdate: student.Student_Birthdate,
            religion: student.Student_Religion,
            medicalProblem: student.Student_MedicalProblem,
            department: student.Department_Name,
            faculty: student.Faculty_Name,
            advisor: student.Advisor_FirstName && student.Advisor_LastName
              ? `${student.Advisor_FirstName} ${student.Advisor_LastName}`
              : null,
            isGraduated: student.Student_IsGraduated,
            regisTime: student.Student_RegisTime
          },
          department: {
            id: student.Department_ID,
            name: student.Department_Name,
            faculty: {
              id: student.Faculty_ID,
              name: student.Faculty_Name
            }
          }
        };

        res.status(200).json({
          message: 'Student details retrieved successfully.',
          status: true,
          data: studentDetail
        });
      });
    });

  } catch (err) {
    console.error('Get Student Detail Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while fetching student details.',
      status: false
    });
  }
});

// API Update Student Detail by ID for Website Admin
app.put('/api/admin/students/:id', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const studentId = parseInt(req.params.id);
  const updateData = req.body;

  if (!userData) {
    return res.status(401).json({ message: "Authentication required.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (!['staff', 'teacher'].includes(Requester_Users_Type)) {
    return res.status(403).json({ message: "Permission denied. Only staff, teachers, and administrators can perform this action.", status: false });
  }

  if (!studentId || isNaN(studentId)) {
    return res.status(400).json({ message: "Invalid student ID provided.", status: false });
  }

  if (!updateData.student) {
    return res.status(400).json({ message: "Student data is required.", status: false });
  }

  const { code, firstName, lastName, phone, otherPhones,
    academicYear, birthdate, religion, medicalProblem, isGraduated } = updateData.student;

  if (!firstName || !lastName) {
    return res.status(400).json({ message: "First name and last name are required.", status: false });
  }

  const formatDateForMySQL = (dateString) => {
    if (!dateString) return null;

    try {
      const date = new Date(dateString);
      if (isNaN(date.getTime())) return null;

      const year = date.getFullYear();
      const month = String(date.getMonth() + 1).padStart(2, '0');
      const day = String(date.getDate()).padStart(2, '0');

      return `${year}-${month}-${day}`;
    } catch (error) {
      console.error('Date formatting error:', error);
      return null;
    }
  };

  const formattedBirthdate = formatDateForMySQL(birthdate);
  try {
    const queryDatabase = (sql, params = []) => {
      return new Promise((resolve, reject) => {
        const startTime = Date.now();
        db.query(sql, params, (err, results) => {
          const endTime = Date.now();
          if (err) {
            console.error('Database query error:', err);
            reject(err);
          } else {
            resolve(results);
          }
        });
      });
    };

    await queryDatabase('START TRANSACTION');
    try {
      const checkSql = `SELECT Users_ID FROM student WHERE Student_ID = ?`;
      const checkResults = await queryDatabase(checkSql, [studentId]);

      if (checkResults.length === 0) {
        await queryDatabase('ROLLBACK');
        return res.status(404).json({ message: 'Student not found.', status: false });
      }

      const usersId = checkResults[0].Users_ID;
      const updateStudentSql = `UPDATE student SET Student_Code = ?, Student_FirstName = ?, 
        Student_LastName = ?, Student_Phone = ?, Student_AcademicYear = ?, Student_Birthdate = ?,
        Student_Religion = ?, Student_MedicalProblem = ?, Student_IsGraduated = ? WHERE Student_ID = ?`;

      const studentParams = [
        code || null,
        firstName,
        lastName,
        phone || null,
        academicYear || null,
        formattedBirthdate,
        religion || null,
        medicalProblem || null,
        isGraduated || false,
        studentId
      ];

      await queryDatabase(updateStudentSql, studentParams);
      if (otherPhones && Array.isArray(otherPhones)) {
        const deletePhonesSql = `DELETE FROM otherphone WHERE Users_ID = ?`;
        await queryDatabase(deletePhonesSql, [usersId]);
        const validPhones = otherPhones.filter(phone =>
          phone.name?.trim() || phone.phone?.trim()
        );

        if (validPhones.length > 0) {
          const insertPhonesSql = `INSERT INTO otherphone (OtherPhone_Name, OtherPhone_Phone, Users_ID) VALUES ?`;
          const phoneValues = validPhones.map(phone => [
            phone.name?.trim() || '',
            phone.phone?.trim() || '',
            usersId
          ]);

          await queryDatabase(insertPhonesSql, [phoneValues]);
        }
      }

      await queryDatabase('COMMIT');
      const response = {
        message: 'Student details updated successfully.',
        status: true,
        data: {
          studentId: studentId,
          updated: true,
          timestamp: new Date().toISOString()
        }
      };

      res.status(200).json(response);
    } catch (transactionError) {
      console.error('Transaction error:', transactionError);
      await queryDatabase('ROLLBACK');
      res.status(500).json({ message: 'Database transaction failed.', status: false, });
    }

  } catch (err) {
    console.error('Unexpected error in student update:', err);
    res.status(500).json({ message: 'An unexpected error occurred while updating student details.', status: false, });
  }
});

// API Update Student Status for Website Admin (Active/Inactive)**
app.patch('/api/admin/students/:id/status', RateLimiter(1 * 60 * 1000, 30), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const studentId = parseInt(req.params.id);
  const { isActive } = req.body;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can change user status.", status: false });
  }

  if (!studentId || isNaN(studentId) || studentId <= 0 || studentId > 2147483647) {
    return res.status(400).json({ message: "Invalid student ID provided.", status: false });
  }

  if (typeof isActive !== 'boolean') {
    return res.status(400).json({ message: "Invalid status value. Must be true or false.", status: false });
  }

  try {
    const checkSql = `SELECT s.Student_ID, s.Users_ID, u.Users_IsActive, s.Student_FirstName, s.Student_LastName FROM 
      student s INNER JOIN users u ON s.Users_ID = u.Users_ID WHERE s.Student_ID = ?`;

    db.query(checkSql, [studentId], (err, checkResults) => {
      if (err) {
        console.error('Check Student Error:', err);
        return res.status(500).json({ message: 'Database error while checking student.', status: false });
      }

      if (checkResults.length === 0) {
        return res.status(404).json({ message: 'Student not found.', status: false });
      }

      const student = checkResults[0];
      if (student.Users_IsActive === isActive) {
        return res.status(400).json({ message: `Student is already ${isActive ? 'active' : 'inactive'}.`, status: false });
      }

      const updateSql = `UPDATE users SET Users_IsActive = ? WHERE Users_ID = ?`;
      db.query(updateSql, [isActive, student.Users_ID], (err, updateResult) => {
        if (err) {
          console.error('Update Status Error:', err);
          return res.status(500).json({ message: 'Database error while updating status.', status: false });
        }

        if (updateResult.affectedRows === 0) {
          return res.status(500).json({ message: 'Failed to update user status.', status: false });
        }

        res.status(200).json({
          message: `Student status updated successfully to ${isActive ? 'active' : 'inactive'}.`,
          status: true,
          data: {
            studentId: studentId,
            isActive: isActive,
            updatedBy: userData.Users_Username || userData.Users_Email,
            updatedAt: new Date().toISOString()
          }
        });
      });
    });
  } catch (err) {
    console.error('Update Student Status Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while updating student status.',
      status: false
    });
  }
});

// API Get Student Basic Info for Website Admin
app.get('/api/admin/students/:id/basic', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const studentId = parseInt(req.params.id);

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff' && Requester_Users_Type !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only staff and teachers can access this information.", status: false });
  }

  if (!studentId || isNaN(studentId) || studentId <= 0 || studentId > 2147483647) {
    return res.status(400).json({ message: "Invalid student ID provided.", status: false });
  }

  try {
    const sql = `SELECT s.Student_ID, s.Student_Code, s.Student_FirstName, s.Student_LastName, 
      s.Student_IsGraduated, u.Users_IsActive, u.Users_Email, d.Department_Name, f.Faculty_Name FROM student s 
      INNER JOIN users u ON s.Users_ID = u.Users_ID INNER JOIN department d ON s.Department_ID = d.Department_ID INNER JOIN 
      faculty f ON d.Faculty_ID = f.Faculty_ID WHERE s.Student_ID = ?`;

    db.query(sql, [studentId], (err, results) => {
      if (err) {
        console.error('Get Student Basic Info Error:', err);
        return res.status(500).json({ message: 'Database error while fetching student basic information.', status: false });
      }

      if (results.length === 0) {
        return res.status(404).json({ message: 'Student not found.', status: false });
      }

      const student = results[0];
      const basicInfo = {
        id: student.Student_ID,
        code: student.Student_Code,
        firstName: student.Student_FirstName,
        lastName: student.Student_LastName,
        fullName: `${student.Student_FirstName} ${student.Student_LastName}`,
        email: student.Users_Email,
        department: student.Department_Name,
        faculty: student.Faculty_Name,
        isActive: student.Users_IsActive,
        isGraduated: student.Student_IsGraduated,
        userType: 'student'
      };

      res.status(200).json({ message: 'Student basic information retrieved successfully.', status: true, data: basicInfo });
    });

  } catch (err) {
    console.error('Get Student Basic Info Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while fetching student basic information.',
      status: false
    });
  }
});

// API Change Password for Admin Website
app.put('/api/admin/users/:Users_ID/change-password', RateLimiter(1 * 60 * 1000, 5), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_ID = userData?.Users_ID;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const Target_Users_ID = parseInt(req.params.Users_ID, 10);

  if (!Requester_Users_ID || typeof Requester_Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid token information.", status: false });
  }

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can change user passwords.", status: false });
  }

  if (!Target_Users_ID || isNaN(Target_Users_ID)) {
    return res.status(400).json({ message: "Missing or invalid Users_ID parameter.", status: false });
  }

  let { newPassword } = req.body || {};

  if (!newPassword) {
    return res.status(400).json({ message: "New password is required.", status: false });
  }

  const isValidPassword = (password) => {
    if (password.length < 8) {
      return { valid: false, message: "Password must be at least 8 characters long." };
    }

    if (!/[a-zA-Z]/.test(password)) {
      return { valid: false, message: "Password must contain at least 1 letter." };
    }

    if (!/[0-9]/.test(password)) {
      return { valid: false, message: "Password must contain at least 1 number." };
    }

    return { valid: true };
  };

  const passwordValidation = isValidPassword(newPassword);
  if (!passwordValidation.valid) {
    return res.status(400).json({
      message: passwordValidation.message,
      status: false
    });
  }

  try {
    const checkUserSql = "SELECT Users_ID, Users_Type, Users_Email FROM users WHERE Users_ID = ?";
    db.query(checkUserSql, [Target_Users_ID], async (err, userResults) => {
      if (err) {
        console.error("Database error (check user):", err);
        return res.status(500).json({ message: "Database error occurred.", status: false });
      }

      if (userResults.length === 0) {
        return res.status(404).json({ message: "User not found.", status: false });
      }

      try {
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        const updatePasswordSql = "UPDATE users SET Users_Password = ? WHERE Users_ID = ?";
        db.query(updatePasswordSql, [hashedPassword, Target_Users_ID], (err, updateResult) => {
          if (err) {
            console.error("Database error (update password):", err);
            return res.status(500).json({ message: "Database error occurred.", status: false });
          }

          if (updateResult.affectedRows === 0) {
            return res.status(500).json({ message: "Failed to update password.", status: false });
          }

          return res.status(200).json({
            message: "Password changed successfully.",
            status: true,
            data: {
              Users_ID: Target_Users_ID,
              changedBy: Requester_Users_ID,
              changedAt: new Date().toISOString()
            }
          });
        });
      } catch (hashError) {
        console.error("Password hashing error:", hashError);
        return res.status(500).json({ message: "Password processing error.", status: false });
      }
    });
  } catch (error) {
    console.error("Change password error:", error);
    return res.status(500).json({ message: "An unexpected error occurred.", status: false });
  }
});

// API Get All Staff with Pagination, Filtering, and Search of Website Admin
app.get('/api/admin/staff', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  const includeResigned = req.query.includeResigned === 'true';
  const search = req.query.search ? req.query.search.trim() : '';

  try {
    let whereConditions = [];
    let queryParams = [];

    if (!includeResigned) {
      whereConditions.push('s.Staff_IsResign = FALSE');
    }

    if (search) {
      whereConditions.push(`(s.Staff_FirstName LIKE ? OR s.Staff_LastName LIKE ? OR s.Staff_Code LIKE ? OR u.Users_Email LIKE ?)`);
      const searchTerm = `%${search}%`;
      queryParams.push(searchTerm, searchTerm, searchTerm, searchTerm);
    }

    const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';

    const sql = `SELECT s.Staff_ID, s.Staff_Code, s.Staff_FirstName, s.Staff_LastName, 
      s.Staff_Phone, s.Staff_RegisTime, s.Staff_IsResign, s.Users_ID,
      u.Users_Email, u.Users_Username, u.Users_RegisTime, u.Users_ImageFile, u.Users_IsActive 
      FROM staff s 
      INNER JOIN users u ON s.Users_ID = u.Users_ID 
      ${whereClause} 
      ORDER BY s.Staff_FirstName ASC, s.Staff_LastName ASC`;

    db.query(sql, queryParams, (err, results) => {
      if (err) {
        console.error('Get Staff Error:', err);
        return res.status(500).json({ message: 'Database error', status: false });
      }

      const staff = results.map(staff => ({
        Staff_ID: staff.Staff_ID,
        Staff_Code: staff.Staff_Code,
        Staff_FirstName: staff.Staff_FirstName,
        Staff_LastName: staff.Staff_LastName,
        Staff_FullName: `${staff.Staff_FirstName} ${staff.Staff_LastName}`,
        Staff_Phone: staff.Staff_Phone,
        Staff_RegisTime: staff.Staff_RegisTime,
        Staff_IsResign: staff.Staff_IsResign,
        Users: {
          Users_ID: staff.Users_ID,
          Users_Email: staff.Users_Email,
          Users_Username: staff.Users_Username,
          Users_RegisTime: staff.Users_RegisTime,
          Users_ImageFile: staff.Users_ImageFile,
          Users_IsActive: staff.Users_IsActive
        }
      }));

      res.status(200).json({
        message: 'Staff retrieved successfully.',
        status: true,
        data: staff,
        count: staff.length
      });
    });
  } catch (err) {
    console.error('Get Staff Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Get Staff Detail by ID for Website Admin**
app.get('/api/admin/staff/:id', RateLimiter(1 * 60 * 1000, 150), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const staffId = parseInt(req.params.id);

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  if (!staffId || isNaN(staffId)) {
    return res.status(400).json({ message: "Invalid staff ID provided.", status: false });
  }

  try {
    const staffSql = `SELECT s.Staff_ID, s.Staff_Code, s.Staff_FirstName, s.Staff_LastName, 
      s.Staff_Phone, s.Staff_RegisTime, s.Staff_IsResign, s.Users_ID, 
      u.Users_Email, u.Users_Username, u.Users_RegisTime, u.Users_ImageFile, u.Users_IsActive 
      FROM staff s INNER JOIN users u ON s.Users_ID = u.Users_ID WHERE s.Staff_ID = ?`;

    db.query(staffSql, [staffId], (err, staffResults) => {
      if (err) {
        console.error('Get Staff Detail Error:', err);
        return res.status(500).json({ message: 'Database error while fetching staff details.', status: false });
      }

      if (staffResults.length === 0) {
        return res.status(404).json({ message: 'Staff not found.', status: false });
      }

      const staff = staffResults[0];
      const otherPhonesSql = `SELECT OtherPhone_ID, OtherPhone_Name, OtherPhone_Phone FROM otherphone WHERE Users_ID = ? ORDER BY OtherPhone_ID ASC`;

      db.query(otherPhonesSql, [staff.Users_ID], (err, phoneResults) => {
        if (err) {
          console.error('Get Other Phones Error:', err);
          phoneResults = [];
        }

        const otherPhones = phoneResults.map(phone => ({
          id: phone.OtherPhone_ID,
          name: phone.OtherPhone_Name,
          phone: phone.OtherPhone_Phone
        }));

        if (otherPhones.length === 0) {
          otherPhones.push({ name: '', phone: '' });
        }

        const staffDetail = {
          id: staff.Staff_ID,
          email: staff.Users_Email,
          username: staff.Users_Username,
          userType: 'staff',
          Users_ID: staff.Users_ID,
          isActive: staff.Users_IsActive,
          regisTime: staff.Users_RegisTime,
          imageFile: staff.Users_ImageFile,
          staff: {
            code: staff.Staff_Code,
            firstName: staff.Staff_FirstName,
            lastName: staff.Staff_LastName,
            phone: staff.Staff_Phone,
            otherPhones: otherPhones,
            isResigned: staff.Staff_IsResign,
            regisTime: staff.Staff_RegisTime
          }
        };

        res.status(200).json({
          message: 'Staff details retrieved successfully.',
          status: true,
          data: staffDetail
        });
      });
    });

  } catch (err) {
    console.error('Get Staff Detail Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while fetching staff details.',
      status: false
    });
  }
});

// API Update Staff Detail by ID for Website Admin
app.put('/api/admin/staff/:id', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const staffId = parseInt(req.params.id);
  const updateData = req.body;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can perform this action.", status: false });
  }

  if (!staffId || isNaN(staffId)) {
    return res.status(400).json({ message: "Invalid staff ID provided.", status: false });
  }

  if (!updateData.staff) {
    return res.status(400).json({ message: "Staff data is required.", status: false });
  }

  const { code, firstName, lastName, phone, otherPhones, isResigned } = updateData.staff;

  if (!firstName || !lastName) {
    return res.status(400).json({ message: "First name and last name are required.", status: false });
  }

  try {
    // Start transaction using MySQL query
    db.query('START TRANSACTION', (err) => {
      if (err) {
        console.error('Transaction Error:', err);
        return res.status(500).json({ message: 'Database transaction error.', status: false });
      }

      const checkSql = `SELECT Users_ID FROM staff WHERE Staff_ID = ?`;
      db.query(checkSql, [staffId], (err, checkResults) => {
        if (err) {
          return db.query('ROLLBACK', () => {
            console.error('Check Staff Error:', err);
            res.status(500).json({
              message: 'Database error while checking staff.',
              status: false
            });
          });
        }

        if (checkResults.length === 0) {
          return db.query('ROLLBACK', () => {
            res.status(404).json({
              message: 'Staff not found.',
              status: false
            });
          });
        }

        const usersId = checkResults[0].Users_ID;
        const updateStaffSql = `UPDATE staff SET Staff_Code = ?, Staff_FirstName = ?, 
          Staff_LastName = ?, Staff_Phone = ?, Staff_IsResign = ? WHERE Staff_ID = ?`;

        const staffParams = [code || null, firstName, lastName, phone || null, isResigned || false, staffId];

        db.query(updateStaffSql, staffParams, (err, updateResult) => {
          if (err) {
            return db.query('ROLLBACK', () => {
              console.error('Update Staff Error:', err);
              res.status(500).json({ message: 'Database error while updating staff.', status: false });
            });
          }

          if (otherPhones && Array.isArray(otherPhones)) {
            const deletePhonesSql = `DELETE FROM otherphone WHERE Users_ID = ?`;
            db.query(deletePhonesSql, [usersId], (err) => {
              if (err) {
                return db.query('ROLLBACK', () => {
                  console.error('Delete Other Phones Error:', err);
                  res.status(500).json({ message: 'Database error while deleting other phones.', status: false });
                });
              }

              const validPhones = otherPhones.filter(phone =>
                phone.name?.trim() || phone.phone?.trim()
              );

              if (validPhones.length > 0) {
                const insertPhonesSql = `INSERT INTO otherphone (OtherPhone_Name, OtherPhone_Phone, Users_ID) VALUES ?`;
                const phoneValues = validPhones.map(phone => [
                  phone.name?.trim() || '',
                  phone.phone?.trim() || '',
                  usersId
                ]);

                db.query(insertPhonesSql, [phoneValues], (err) => {
                  if (err) {
                    return db.query('ROLLBACK', () => {
                      console.error('Insert Other Phones Error:', err);
                      res.status(500).json({ message: 'Database error while inserting other phones.', status: false });
                    });
                  }

                  // Commit transaction
                  db.query('COMMIT', (err) => {
                    if (err) {
                      return db.query('ROLLBACK', () => {
                        console.error('Commit Error:', err);
                        res.status(500).json({ message: 'Database commit error.', status: false });
                      });
                    }

                    res.status(200).json({
                      message: 'Staff details updated successfully.',
                      status: true,
                      data: {
                        staffId: staffId,
                        updated: true
                      }
                    });
                  });
                });
              } else {
                db.query('COMMIT', (err) => {
                  if (err) {
                    return db.query('ROLLBACK', () => {
                      console.error('Commit Error:', err);
                      res.status(500).json({ message: 'Database commit error.', status: false });
                    });
                  }

                  res.status(200).json({
                    message: 'Staff details updated successfully.',
                    status: true,
                    data: {
                      staffId: staffId,
                      updated: true
                    }
                  });
                });
              }
            });
          } else {
            db.query('COMMIT', (err) => {
              if (err) {
                return db.query('ROLLBACK', () => {
                  console.error('Commit Error:', err);
                  res.status(500).json({
                    message: 'Database commit error.',
                    status: false
                  });
                });
              }
              res.status(200).json({
                message: 'Staff details updated successfully.',
                status: true,
                data: {
                  staffId: staffId,
                  updated: true
                }
              });
            });
          }
        });
      });
    });

  } catch (err) {
    console.error('Update Staff Detail Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while updating staff details.',
      status: false
    });
  }
});

// API Update Staff Status for Website Admin (Active/Inactive)**
app.patch('/api/admin/staff/:id/status', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Requester_Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const staffId = parseInt(req.params.id);
  const { isActive } = req.body;

  if (Login_Type !== 'website') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
  }

  if (Requester_Users_Type !== 'staff') {
    return res.status(403).json({ message: "Permission denied. Only staff can change user status.", status: false });
  }

  if (!staffId || isNaN(staffId) || staffId <= 0 || staffId > 2147483647) {
    return res.status(400).json({ message: "Invalid staff ID provided.", status: false });
  }

  if (typeof isActive !== 'boolean') {
    return res.status(400).json({ message: "Invalid status value. Must be true or false.", status: false });
  }

  try {
    const checkSql = `SELECT s.Staff_ID, s.Users_ID, u.Users_IsActive, s.Staff_FirstName, s.Staff_LastName FROM 
      staff s INNER JOIN users u ON s.Users_ID = u.Users_ID WHERE s.Staff_ID = ?`;

    db.query(checkSql, [staffId], (err, checkResults) => {
      if (err) {
        console.error('Check Staff Error:', err);
        return res.status(500).json({ message: 'Database error while checking staff.', status: false });
      }

      if (checkResults.length === 0) {
        return res.status(404).json({ message: 'Staff not found.', status: false });
      }

      const staff = checkResults[0];
      if (staff.Users_IsActive === isActive) {
        return res.status(400).json({ message: `Staff is already ${isActive ? 'active' : 'inactive'}.`, status: false });
      }

      const updateSql = `UPDATE users SET Users_IsActive = ? WHERE Users_ID = ?`;
      db.query(updateSql, [isActive, staff.Users_ID], (err, updateResult) => {
        if (err) {
          console.error('Update Status Error:', err);
          return res.status(500).json({ message: 'Database error while updating status.', status: false });
        }

        if (updateResult.affectedRows === 0) {
          return res.status(500).json({ message: 'Failed to update user status.', status: false });
        }

        res.status(200).json({
          message: `Staff status updated successfully to ${isActive ? 'active' : 'inactive'}.`,
          status: true,
          data: {
            staffId: staffId,
            isActive: isActive,
            updatedBy: userData.Users_Username || userData.Users_Email,
            updatedAt: new Date().toISOString()
          }
        });
      });
    });
  } catch (err) {
    console.error('Update Staff Status Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while updating staff status.',
      status: false
    });
  }
});

//////////////////////////////////Profile Application API///////////////////////////////////////
//API Edit Student Profile Application
app.put('/api/profile/student/update', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (!Users_ID || typeof Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Users_ID from token.", status: false });
  }

  if (Login_Type !== 'application') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed in the application.", status: false });
  }

  if (Users_Type?.toLowerCase() !== 'student') {
    return res.status(403).json({ message: "Permission denied. Only students can perform this action.", status: false });
  }

  let { Student_Phone, Student_Birthdate, Student_Religion, Student_MedicalProblem } = req.body || {};

  if (Student_Phone && !validator.isMobilePhone(Student_Phone, 'any', { strictMode: false })) {
    return res.status(400).json({ message: "Invalid phone number format.", status: false });
  }

  if (Student_Phone) {
    if (Student_Phone.length > 20 || Student_Phone.length < 8) {
      return res.status(400).json({ message: "Phone number length must be between 8 and 20 digits.", status: false });
    }

    if (!/^\d+$/.test(Student_Phone)) {
      return res.status(400).json({ message: "Phone number must contain only digits.", status: false });
    }
  }

  if (Student_Birthdate) {
    const birthdateMoment = moment(Student_Birthdate, 'DD-MM-YYYY', true);
    if (!birthdateMoment.isValid()) {
      return res.status(400).json({ message: "Invalid birthdate format. Use DD-MM-YYYY.", status: false });
    }
    Student_Birthdate = birthdateMoment.format('YYYY-MM-DD');
  }

  if (Student_Religion && Student_Religion.length > 63) {
    return res.status(400).json({ message: "Religion text too long (max 63 characters).", status: false });
  }

  if (Student_MedicalProblem && Student_MedicalProblem.length > 511) {
    return res.status(400).json({ message: "Medical problem text too long (max 511 characters).", status: false });
  }

  const allowedFields = { Student_Phone, Student_Birthdate, Student_Religion, Student_MedicalProblem };
  const fieldsToUpdate = [];
  const values = [];

  for (const [key, value] of Object.entries(allowedFields)) {
    if (value !== undefined) {
      fieldsToUpdate.push(`${key} = ?`);
      values.push(value);
    }
  }

  if (fieldsToUpdate.length === 0) {
    return res.status(400).json({ message: "No fields provided for update.", status: false });
  }

  const sqlCheck = "SELECT Student_ID FROM student WHERE Users_ID = ?";
  db.query(sqlCheck, [Users_ID], (err, result) => {
    if (err) {
      console.error("Database error (student check)", err);
      return res.status(500).json({ message: "Database error occurred.", status: false });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "Student profile not found.", status: false });
    }

    const Student_ID = result[0].Student_ID;
    const sqlUpdate = `UPDATE student SET ${fieldsToUpdate.join(", ")} WHERE Student_ID = ?`;
    values.push(Student_ID);

    db.query(sqlUpdate, values, (err, updateResult) => {
      if (err) {
        console.error("Database error (student update)", err);
        return res.status(500).json({ message: "Database error occurred.", status: false });
      }

      if (updateResult.affectedRows > 0) {
        return res.status(200).json({ message: "Student profile updated successfully.", status: true });
      } else {
        return res.status(404).json({ message: "No changes made or student not found.", status: false });
      }
    });
  });
});

//API Edit Teacher Profile Application
app.put('/api/profile/teacher/update', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (!Users_ID || typeof Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Users_ID from token.", status: false });
  }

  if (Login_Type !== 'application') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed in the application.", status: false });
  }

  if (Users_Type?.toLowerCase() !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only Teachers can perform this action.", status: false });
  }

  let { Teacher_Phone, Teacher_Birthdate, Teacher_Religion, Teacher_MedicalProblem } = req.body || {};

  if (Teacher_Phone && !validator.isMobilePhone(Teacher_Phone, 'any', { strictMode: false })) {
    return res.status(400).json({ message: "Invalid phone number format.", status: false });
  }

  if (Teacher_Phone) {
    if (Teacher_Phone.length > 20 || Teacher_Phone.length < 8) {
      return res.status(400).json({ message: "Phone number length must be between 8 and 20 digits.", status: false });
    }

    if (!/^\d+$/.test(Teacher_Phone)) {
      return res.status(400).json({ message: "Phone number must contain only digits.", status: false });
    }
  }

  if (Teacher_Birthdate) {
    const birthdateMoment = moment(Teacher_Birthdate, 'DD-MM-YYYY', true);
    if (!birthdateMoment.isValid()) {
      return res.status(400).json({ message: "Invalid birthdate format. Use DD-MM-YYYY.", status: false });
    }
    Teacher_Birthdate = birthdateMoment.format('YYYY-MM-DD');
  }

  if (Teacher_Religion && Teacher_Religion.length > 63) {
    return res.status(400).json({ message: "Religion text too long (max 63 characters).", status: false });
  }

  if (Teacher_MedicalProblem && Teacher_MedicalProblem.length > 511) {
    return res.status(400).json({ message: "Medical problem text too long (max 511 characters).", status: false });
  }

  const allowedFields = { Teacher_Phone, Teacher_Birthdate, Teacher_Religion, Teacher_MedicalProblem };

  const fieldsToUpdate = [];
  const values = [];

  for (const [key, value] of Object.entries(allowedFields)) {
    if (value !== undefined) {
      fieldsToUpdate.push(`${key} = ?`);
      values.push(value);
    }
  }

  if (fieldsToUpdate.length === 0) {
    return res.status(400).json({ message: "No fields provided for update.", status: false });
  }

  const sqlCheck = "SELECT Teacher_ID FROM teacher WHERE Users_ID = ?";
  db.query(sqlCheck, [Users_ID], (err, result) => {
    if (err) {
      console.error("Database error (teacher check)", err);
      return res.status(500).json({ message: "Database error occurred.", status: false });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "teacher profile not found.", status: false });
    }

    const Teacher_ID = result[0].Teacher_ID;
    const sqlUpdate = `UPDATE teacher SET ${fieldsToUpdate.join(", ")} WHERE Teacher_ID = ?`;
    values.push(Teacher_ID);

    db.query(sqlUpdate, values, (err, updateResult) => {
      if (err) {
        console.error("Database error (teacher update)", err);
        return res.status(500).json({ message: "Database error occurred.", status: false });
      }

      if (updateResult.affectedRows > 0) {
        return res.status(200).json({ message: "Teacher profile updated successfully.", status: true });
      } else {
        return res.status(404).json({ message: "No changes made or teacher not found.", status: false });
      }
    });
  });
});

//////////////////////////////////Image API///////////////////////////////////////
//API Get Profile Image by Filename
app.get('/api/images/profile-images/:filename', VerifyTokens, (req, res) => {
  try {
    const filename = path.basename(req.params.filename);

    if (!filename.match(/^[a-zA-Z0-9._-]+$/)) {
      return res.status(400).json({ message: 'Invalid filename', status: false });
    }

    const allowedExt = ['.jpg', '.jpeg', '.png'];
    const ext = path.extname(filename).toLowerCase();

    if (!allowedExt.includes(ext)) {
      return res.status(400).json({ message: 'Invalid file type', status: false });
    }

    const filePath = path.join(uploadDir_Profile, filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: 'Image not found', status: false });
    }

    res.type(ext);
    res.sendFile(filePath);
  } catch (err) {
    console.error('Error serving image:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// API get certificate image files
app.get('/api/images/certificate-files/:filename', VerifyTokens_Website, (req, res) => {
  try {
    const userData = req.user;
    const Users_Type = userData?.Users_Type;
    const Login_Type = userData?.Login_Type;

    if (Login_Type !== 'website') {
      return res.status(403).json({
        message: "Permission denied. This action is only allowed on the website.",
        status: false
      });
    }

    if (Users_Type !== 'staff') {
      return res.status(403).json({
        message: "Permission denied. Only staff can access certificate files.",
        status: false
      });
    }

    const filename = path.basename(req.params.filename);
    if (!filename.match(/^[a-zA-Z0-9._-]+$/)) {
      return res.status(400).json({ message: 'Invalid filename', status: false });
    }

    const allowedExt = ['.jpg', '.jpeg', '.png'];
    const ext = path.extname(filename).toLowerCase();
    if (!allowedExt.includes(ext)) {
      return res.status(400).json({ message: 'Invalid file type', status: false });
    }

    const filePath = path.join(uploadDir_Certificate, filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        message: 'Image not found',
        status: false
      });
    }

    res.type(ext);
    res.sendFile(filePath);

  } catch (err) {
    console.error('Error serving certificate image:', err);
    res.status(500).json({ message: 'Internal server error', status: false });
  }
});

//API Get Profile Image by Filename (Staff Only)
app.get('/api/images/profile-images-admin/:filename', VerifyTokens_Website, (req, res) => {
  try {
    const userData = req.user;
    const Users_Type = userData?.Users_Type;
    const Login_Type = userData?.Login_Type;

    if (Login_Type !== 'website') {
      return res.status(403).json({ message: "Permission denied. This action is only allowed on the website.", status: false });
    }

    if (Users_Type !== 'staff') {
      return res.status(403).json({ message: "Permission denied. Only staff can access profile images.", status: false });
    }

    const filename = path.basename(req.params.filename);
    if (!filename.match(/^[a-zA-Z0-9._-]+$/)) {
      return res.status(400).json({ message: 'Invalid filename', status: false });
    }
    const allowedExt = ['.jpg', '.jpeg', '.png'];
    const ext = path.extname(filename).toLowerCase();
    if (!allowedExt.includes(ext)) {
      return res.status(400).json({ message: 'Invalid file type', status: false });
    }

    const filePath = path.join(uploadDir_Profile, filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        message: 'Image not found',
        status: false
      });
    }
    res.type(ext);
    res.sendFile(filePath);

  } catch (err) {
    console.error('Error serving profile image:', err);
    res.status(500).json({ message: 'Internal server error', status: false });
  }
});

//API add Profile Image in Users of Application
app.post('/api/profile/upload/image', upload.single('Users_ImageFile'), RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;
  const Login_Type = userData?.Login_Type;

  if (!Users_ID || typeof Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Users_ID from token.", status: false });
  }

  if (Login_Type !== 'application') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed in the application.", status: false });
  }

  if (!req.file) {
    return res.status(400).json({ message: 'Please provide an image file.', status: false });
  }

  const detected = await fileType.fileTypeFromBuffer(req.file.buffer);
  if (!detected || !['image/jpeg', 'image/png'].includes(detected.mime)) {
    return res.status(400).json({ message: 'Invalid image file.' });
  }


  try {
    const userId = parseInt(Users_ID);
    if (!req.file || !userId || Number.isNaN(userId) || userId <= 0) {
      return res.status(400).json({ message: 'Please provide a valid an image file.' });
    }
    const detected = await fileType.fileTypeFromBuffer(req.file.buffer);
    if (!detected || !['image/jpeg', 'image/png'].includes(detected.mime)) {
      return res.status(400).json({ message: 'Invalid image file.' });
    }

    const processedBuffer = await sharp(req.file.buffer)
      .resize({ width: 400, height: 400, fit: 'inside' })
      .jpeg({ quality: 85 })
      .toBuffer();


    const filename = uuidv4() + '.jpg';
    const savePath = path.join(uploadDir_Profile, filename);

    db.query('SELECT Users_ImageFile FROM users WHERE Users_ID = ? LIMIT 1', [userId], (err, rows) => {
      if (err) {
        console.error('Database query error:', err);
        return res.status(500).json({ message: 'Database connection error.' });
      }

      const oldFilename = rows && rows.length > 0 ? rows[0].Users_ImageFile : null;

      if (oldFilename && typeof oldFilename === 'string' && oldFilename.trim() !== '') {
        const safeFilename = path.basename(oldFilename);
        const oldFilePath = path.join(uploadDir_Profile, safeFilename);

        if (oldFilePath.startsWith(uploadDir_Profile) && fs.existsSync(oldFilePath)) {
          try {
            fs.unlinkSync(oldFilePath);
            console.log(`Deleted old profile image: ${safeFilename}`);
          } catch (unlinkErr) {
            console.error('Failed to delete old image:', unlinkErr);
          }
        }
      } else {
        console.log('No old profile image to delete.');
      }

      fs.writeFileSync(savePath, processedBuffer);
      const updateSql = 'UPDATE users SET Users_ImageFile = ? WHERE Users_ID = ?';
      db.query(updateSql, [filename, userId], (updateErr, result) => {
        if (updateErr) {
          console.error('Database update error:', updateErr);
          return res.status(500).json({ message: 'Image uploaded but failed to update database.' });
        }

        if (result.affectedRows === 0) {
          return res.status(404).json({ message: 'User not found.' });
        }

        return res.status(200).json({
          message: 'Profile image uploaded successfully.',
          filename: filename
        });
      });
    });
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ message: 'Error occurred during image upload.' });
  }
});

//////////////////////////////////Signature API///////////////////////////////////////
//API Get all signatures**
app.get('/api/admin/signatures', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({
      message: "Permission denied. Only staff can access signatures.",
      status: false
    });
  }

  try {
    const sql = `SELECT Signature_ID, Signature_Name, Signature_ImageFile, Signature_RegisTime 
      FROM signature ORDER BY Signature_RegisTime DESC`;

    db.query(sql, (err, results) => {
      if (err) {
        console.error('Get Signatures Error:', err);
        return res.status(500).json({
          message: 'Database error while fetching signatures.',
          status: false
        });
      }

      res.status(200).json({
        message: 'Signatures retrieved successfully.',
        status: true,
        data: results
      });
    });
  } catch (err) {
    console.error('Get Signatures Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while fetching signatures.',
      status: false
    });
  }
});

//API Add new signature**
app.post('/api/admin/signatures', certificateUpload.single('signatureFile'), RateLimiter(1 * 60 * 1000, 30), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const { signatureName } = req.body;

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({
      message: "Permission denied. Only staff can add signatures.",
      status: false
    });
  }

  if (!signatureName || signatureName.trim() === '') {
    return res.status(400).json({
      message: 'กรุณาระบุชื่อลายเซ็น',
      status: false
    });
  }

  if (!req.file) {
    return res.status(400).json({
      message: 'กรุณาอัปโลดไฟล์ลายเซ็น',
      status: false
    });
  }

  try {
    const detected = await fileType.fileTypeFromBuffer(req.file.buffer);
    if (!detected || !['image/jpeg', 'image/png'].includes(detected.mime)) {
      return res.status(400).json({
        message: 'ไฟล์ต้องเป็นรูปภาพเท่านั้น (JPG, PNG)',
        status: false
      });
    }

    const processedBuffer = await sharp(req.file.buffer)
      .resize({ width: 800, height: 400, fit: 'inside' })
      .png({ quality: 90 })
      .toBuffer();

    const filename = `signature_${uuidv4()}.png`;
    const savePath = path.join(uploadDir_Certificate, filename);
    fs.writeFileSync(savePath, processedBuffer);

    const sql = `INSERT INTO signature (Signature_Name, Signature_ImageFile) VALUES (?, ?)`;
    db.query(sql, [signatureName.trim(), filename], (err, result) => {
      if (err) {
        console.error('Add Signature Error:', err);
        if (fs.existsSync(savePath)) {
          fs.unlinkSync(savePath);
        }
        return res.status(500).json({
          message: 'Database error while adding signature.',
          status: false
        });
      }

      res.status(201).json({
        message: 'เพิ่มลายเซ็นสำเร็จ',
        status: true,
        data: {
          Signature_ID: result.insertId,
          Signature_Name: signatureName.trim(),
          Signature_ImageFile: filename
        }
      });
    });
  } catch (err) {
    console.error('Add Signature Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while adding signature.',
      status: false
    });
  }
});

//API Update signature**
app.put('/api/admin/signatures/:id', certificateUpload.single('signatureFile'), RateLimiter(1 * 60 * 1000, 30), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const signatureId = parseInt(req.params.id);
  const { signatureName } = req.body;

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({
      message: "Permission denied. Only staff can update signatures.",
      status: false
    });
  }

  if (!signatureId || isNaN(signatureId)) {
    return res.status(400).json({
      message: "Invalid signature ID provided.",
      status: false
    });
  }

  if (!signatureName || signatureName.trim() === '') {
    return res.status(400).json({
      message: 'กรุณาระบุชื่อลายเซ็น',
      status: false
    });
  }

  try {
    const getCurrentSql = `SELECT Signature_ImageFile FROM signature WHERE Signature_ID = ?`;
    db.query(getCurrentSql, [signatureId], async (err, currentResult) => {
      if (err) {
        console.error('Get Current Signature Error:', err);
        return res.status(500).json({
          message: 'Database error while fetching current signature.',
          status: false
        });
      }

      if (currentResult.length === 0) {
        return res.status(404).json({
          message: 'ไม่พบลายเซ็นที่ต้องการแก้ไข',
          status: false
        });
      }

      let filename = currentResult[0].Signature_ImageFile;
      let updateSql = `UPDATE signature SET Signature_Name = ? WHERE Signature_ID = ?`;
      let updateParams = [signatureName.trim(), signatureId];

      if (req.file) {
        const detected = await fileType.fileTypeFromBuffer(req.file.buffer);
        if (!detected || !['image/jpeg', 'image/png'].includes(detected.mime)) {
          return res.status(400).json({
            message: 'ไฟล์ต้องเป็นรูปภาพเท่านั้น (JPG, PNG)',
            status: false
          });
        }

        const processedBuffer = await sharp(req.file.buffer)
          .resize({ width: 800, height: 400, fit: 'inside' })
          .png({ quality: 90 })
          .toBuffer();

        const newFilename = `signature_${uuidv4()}.png`;
        const savePath = path.join(uploadDir_Certificate, newFilename);
        fs.writeFileSync(savePath, processedBuffer);

        updateSql = `UPDATE signature SET Signature_Name = ?, Signature_ImageFile = ? WHERE Signature_ID = ?`;
        updateParams = [signatureName.trim(), newFilename, signatureId];
        filename = newFilename;
      }

      db.query(updateSql, updateParams, (err, result) => {
        if (err) {
          console.error('Update Signature Error:', err);
          return res.status(500).json({
            message: 'Database error while updating signature.',
            status: false
          });
        }

        if (result.affectedRows === 0) {
          return res.status(404).json({
            message: 'ไม่พบลายเซ็นที่ต้องการแก้ไข',
            status: false
          });
        }

        if (req.file && currentResult[0].Signature_ImageFile !== filename) {
          const oldFilePath = path.join(uploadDir_Certificate, currentResult[0].Signature_ImageFile);
          if (fs.existsSync(oldFilePath)) {
            fs.unlinkSync(oldFilePath);
          }
        }

        res.status(200).json({
          message: 'แก้ไขลายเซ็นสำเร็จ',
          status: true,
          data: {
            Signature_ID: signatureId,
            Signature_Name: signatureName.trim(),
            Signature_ImageFile: filename
          }
        });
      });
    });
  } catch (err) {
    console.error('Update Signature Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while updating signature.',
      status: false
    });
  }
});

//API Delete signature**
app.delete('/api/admin/signatures/:id', RateLimiter(1 * 60 * 1000, 30), VerifyTokens_Website, (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const signatureId = parseInt(req.params.id);

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({
      message: "Permission denied. Only staff can delete signatures.",
      status: false
    });
  }

  if (!signatureId || isNaN(signatureId)) {
    return res.status(400).json({
      message: "Invalid signature ID provided.",
      status: false
    });
  }

  try {
    const checkUsageSql = `SELECT COUNT(*) as count FROM template WHERE Signature_ID = ?`;
    db.query(checkUsageSql, [signatureId], (err, usageResult) => {
      if (err) {
        console.error('Check Signature Usage Error:', err);
        return res.status(500).json({
          message: 'Database error while checking signature usage.',
          status: false
        });
      }

      if (usageResult[0].count > 0) {
        return res.status(400).json({
          message: 'ไม่สามารถลบลายเซ็นนี้ได้ เนื่องจากมีแม่แบบที่ใช้งานอยู่',
          status: false
        });
      }

      const getSql = `SELECT Signature_ImageFile FROM signature WHERE Signature_ID = ?`;
      db.query(getSql, [signatureId], (err, result) => {
        if (err) {
          console.error('Get Signature Error:', err);
          return res.status(500).json({
            message: 'Database error while fetching signature.',
            status: false
          });
        }

        if (result.length === 0) {
          return res.status(404).json({
            message: 'ไม่พบลายเซ็นที่ต้องการลบ',
            status: false
          });
        }

        const imageFile = result[0].Signature_ImageFile;
        const deleteSql = `DELETE FROM signature WHERE Signature_ID = ?`;
        db.query(deleteSql, [signatureId], (err, deleteResult) => {
          if (err) {
            console.error('Delete Signature Error:', err);
            return res.status(500).json({
              message: 'Database error while deleting signature.',
              status: false
            });
          }

          if (deleteResult.affectedRows === 0) {
            return res.status(404).json({
              message: 'ไม่พบลายเซ็นที่ต้องการลบ',
              status: false
            });
          }

          const filePath = path.join(uploadDir_Certificate, imageFile);
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
          }

          res.status(200).json({
            message: 'ลบลายเซ็นสำเร็จ',
            status: true
          });
        });
      });
    });
  } catch (err) {
    console.error('Delete Signature Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while deleting signature.',
      status: false
    });
  }
});

//////////////////////////////////templates API///////////////////////////////////////
//API Get all templates**
app.get('/api/admin/templates', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({
      message: "Permission denied. Only staff can access templates.",
      status: false
    });
  }

  try {
    const sql = `SELECT t.Template_ID, t.Template_Name, t.Template_ImageFile, t.Template_PositionX, 
      t.Template_PositionY, t.Template_RegisTime, t.Signature_ID, s.Signature_Name, s.Signature_ImageFile 
      FROM template t LEFT JOIN signature s ON t.Signature_ID = s.Signature_ID ORDER BY t.Template_RegisTime DESC`;

    db.query(sql, (err, results) => {
      if (err) {
        console.error('Get Templates Error:', err);
        return res.status(500).json({
          message: 'Database error while fetching templates.',
          status: false
        });
      }

      res.status(200).json({
        message: 'Templates retrieved successfully.',
        status: true,
        data: results
      });
    });
  } catch (err) {
    console.error('Get Templates Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while fetching templates.',
      status: false
    });
  }
});

//API Add new template**
app.post('/api/admin/templates', certificateUpload.single('templateFile'), RateLimiter(1 * 60 * 1000, 30), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const { templateName, positionX, positionY, signatureId } = req.body;

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({
      message: "Permission denied. Only staff can add templates.",
      status: false
    });
  }

  if (!templateName || templateName.trim() === '') {
    return res.status(400).json({
      message: 'กรุณาระบุชื่อแม่แบบ',
      status: false
    });
  }

  if (!req.file) {
    return res.status(400).json({
      message: 'กรุณาอัปโลดไฟล์แม่แบบ',
      status: false
    });
  }

  const parsedSignatureId = signatureId ? parseInt(signatureId) : null;
  const parsedPositionX = positionX ? parseInt(positionX) : 0;
  const parsedPositionY = positionY ? parseInt(positionY) : 0;

  try {
    const detected = await fileType.fileTypeFromBuffer(req.file.buffer);
    if (!detected || !['image/jpeg', 'image/png'].includes(detected.mime)) {
      return res.status(400).json({
        message: 'ไฟล์ต้องเป็นรูปภาพเท่านั้น (JPG, PNG)',
        status: false
      });
    }

    const processedBuffer = await sharp(req.file.buffer)
      .resize({ width: 1200, height: 800, fit: 'inside' })
      .png({ quality: 90 })
      .toBuffer();

    const filename = `template_${uuidv4()}.png`;
    const savePath = path.join(uploadDir_Certificate, filename);
    fs.writeFileSync(savePath, processedBuffer);

    const sql = `INSERT INTO template (Template_Name, Template_ImageFile, 
      Template_PositionX, Template_PositionY, Signature_ID) VALUES (?, ?, ?, ?, ?)`;

    db.query(sql, [templateName.trim(), filename, parsedPositionX, parsedPositionY, parsedSignatureId], (err, result) => {
      if (err) {
        console.error('Add Template Error:', err);
        if (fs.existsSync(savePath)) {
          fs.unlinkSync(savePath);
        }
        return res.status(500).json({
          message: 'Database error while adding template.',
          status: false
        });
      }

      res.status(201).json({
        message: 'เพิ่มแม่แบบสำเร็จ',
        status: true,
        data: {
          Template_ID: result.insertId,
          Template_Name: templateName.trim(),
          Template_ImageFile: filename,
          Template_PositionX: parsedPositionX,
          Template_PositionY: parsedPositionY,
          Signature_ID: parsedSignatureId
        }
      });
    });
  } catch (err) {
    console.error('Add Template Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while adding template.',
      status: false
    });
  }
});

//API Update template**
app.put('/api/admin/templates/:id', certificateUpload.single('templateFile'), RateLimiter(1 * 60 * 1000, 30), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const templateId = parseInt(req.params.id);
  const { templateName, positionX, positionY, signatureId } = req.body;

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({
      message: "Permission denied. Only staff can update templates.",
      status: false
    });
  }

  if (!templateId || isNaN(templateId)) {
    return res.status(400).json({
      message: "Invalid template ID provided.",
      status: false
    });
  }

  if (!templateName || templateName.trim() === '') {
    return res.status(400).json({
      message: 'กรุณาระบุชื่อแม่แบบ',
      status: false
    });
  }

  const parsedSignatureId = signatureId ? parseInt(signatureId) : null;
  const parsedPositionX = positionX ? parseInt(positionX) : 0;
  const parsedPositionY = positionY ? parseInt(positionY) : 0;

  try {
    const getCurrentSql = `SELECT Template_ImageFile FROM template WHERE Template_ID = ?`;
    db.query(getCurrentSql, [templateId], async (err, currentResult) => {
      if (err) {
        console.error('Get Current Template Error:', err);
        return res.status(500).json({
          message: 'Database error while fetching current template.',
          status: false
        });
      }

      if (currentResult.length === 0) {
        return res.status(404).json({
          message: 'ไม่พบแม่แบบที่ต้องการแก้ไข',
          status: false
        });
      }

      let filename = currentResult[0].Template_ImageFile;
      let updateSql = `UPDATE template SET Template_Name = ?, Template_PositionX = ?, Template_PositionY = ?, Signature_ID = ? WHERE Template_ID = ?`;
      let updateParams = [templateName.trim(), parsedPositionX, parsedPositionY, parsedSignatureId, templateId];

      if (req.file) {
        const detected = await fileType.fileTypeFromBuffer(req.file.buffer);
        if (!detected || !['image/jpeg', 'image/png'].includes(detected.mime)) {
          return res.status(400).json({
            message: 'ไฟล์ต้องเป็นรูปภาพเท่านั้น (JPG, PNG)',
            status: false
          });
        }

        const processedBuffer = await sharp(req.file.buffer)
          .resize({ width: 1200, height: 800, fit: 'inside' })
          .png({ quality: 90 })
          .toBuffer();

        const newFilename = `template_${uuidv4()}.png`;
        const savePath = path.join(uploadDir_Certificate, newFilename);
        fs.writeFileSync(savePath, processedBuffer);

        updateSql = `UPDATE template SET Template_Name = ?, Template_ImageFile = ?, Template_PositionX = ?, Template_PositionY = ?, Signature_ID = ? WHERE Template_ID = ?`;
        updateParams = [templateName.trim(), newFilename, parsedPositionX, parsedPositionY, parsedSignatureId, templateId];
        filename = newFilename;
      }

      db.query(updateSql, updateParams, (err, result) => {
        if (err) {
          console.error('Update Template Error:', err);
          return res.status(500).json({
            message: 'Database error while updating template.',
            status: false
          });
        }

        if (result.affectedRows === 0) {
          return res.status(404).json({
            message: 'ไม่พบแม่แบบที่ต้องการแก้ไข',
            status: false
          });
        }

        if (req.file && currentResult[0].Template_ImageFile !== filename) {
          const oldFilePath = path.join(uploadDir_Certificate, currentResult[0].Template_ImageFile);
          if (fs.existsSync(oldFilePath)) {
            fs.unlinkSync(oldFilePath);
          }
        }

        res.status(200).json({
          message: 'แก้ไขแม่แบบสำเร็จ',
          status: true,
          data: {
            Template_ID: templateId,
            Template_Name: templateName.trim(),
            Template_ImageFile: filename,
            Template_PositionX: parsedPositionX,
            Template_PositionY: parsedPositionY,
            Signature_ID: parsedSignatureId
          }
        });
      });
    });
  } catch (err) {
    console.error('Update Template Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while updating template.',
      status: false
    });
  }
});

//API Delete template
app.delete('/api/admin/templates/:id', RateLimiter(1 * 60 * 1000, 30), VerifyTokens_Website, (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const templateId = parseInt(req.params.id);

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({
      message: "Permission denied. Only staff can delete templates.",
      status: false
    });
  }

  if (!templateId || isNaN(templateId)) {
    return res.status(400).json({
      message: "Invalid template ID provided.",
      status: false
    });
  }

  try {
    const checkUsageSql = `SELECT COUNT(*) as count FROM activity WHERE Template_ID = ?`;
    db.query(checkUsageSql, [templateId], (err, usageResult) => {
      if (err) {
        console.error('Check Template Usage Error:', err);
        return res.status(500).json({
          message: 'Database error while checking template usage.',
          status: false
        });
      }

      if (usageResult[0].count > 0) {
        return res.status(400).json({
          message: 'ไม่สามารถลบแม่แบบนี้ได้ เนื่องจากมีกิจกรรมที่ใช้งานอยู่',
          status: false
        });
      }

      const getSql = `SELECT Template_ImageFile FROM template WHERE Template_ID = ?`;
      db.query(getSql, [templateId], (err, result) => {
        if (err) {
          console.error('Get Template Error:', err);
          return res.status(500).json({
            message: 'Database error while fetching template.',
            status: false
          });
        }

        if (result.length === 0) {
          return res.status(404).json({
            message: 'ไม่พบแม่แบบที่ต้องการลบ',
            status: false
          });
        }

        const imageFile = result[0].Template_ImageFile;
        const deleteSql = `DELETE FROM template WHERE Template_ID = ?`;
        db.query(deleteSql, [templateId], (err, deleteResult) => {
          if (err) {
            console.error('Delete Template Error:', err);
            return res.status(500).json({
              message: 'Database error while deleting template.',
              status: false
            });
          }

          if (deleteResult.affectedRows === 0) {
            return res.status(404).json({
              message: 'ไม่พบแม่แบบที่ต้องการลบ',
              status: false
            });
          }

          const filePath = path.join(uploadDir_Certificate, imageFile);
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
          }

          res.status(200).json({
            message: 'ลบแม่แบบสำเร็จ',
            status: true
          });
        });
      });
    });
  } catch (err) {
    console.error('Delete Template Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while deleting template.',
      status: false
    });
  }
});

////////////////////////////////Certificate API///////////////////////////////////////
//API Generate certificate for user**
app.post('/api/certificates/generate', RateLimiter(1 * 60 * 1000, 10), VerifyTokens_Website, async (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;
  const { activityId, userId, templateId } = req.body;

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({
      message: "Permission denied. Only staff can generate certificates.",
      status: false
    });
  }

  if (!activityId || !userId || !templateId) {
    return res.status(400).json({
      message: 'กรุณาระบุข้อมูลให้ครบถ้วน (activityId, userId, templateId)',
      status: false
    });
  }

  try {
    const checkSql = `SELECT Certificate_ID FROM certificate WHERE Activity_ID = ? AND Users_ID = ?`;
    db.query(checkSql, [activityId, userId], (err, existing) => {
      if (err) {
        console.error('Check Certificate Error:', err);
        return res.status(500).json({
          message: 'Database error while checking existing certificate.',
          status: false
        });
      }

      if (existing.length > 0) {
        return res.status(400).json({
          message: 'เกียรติบัตรนี้ถูกสร้างแล้ว',
          status: false
        });
      }

      const getUserActivitySql = `
        SELECT u.Users_ID, s.Student_FirstName, s.Student_LastName, t.Teacher_FirstName, t.Teacher_LastName,
               a.Activity_Title, a.Activity_EndTime
        FROM users u 
        LEFT JOIN student s ON u.Users_ID = s.Users_ID
        LEFT JOIN teacher t ON u.Users_ID = t.Users_ID
        JOIN activity a ON a.Activity_ID = ?
        WHERE u.Users_ID = ?`;

      db.query(getUserActivitySql, [activityId, userId], (err, userResult) => {
        if (err) {
          console.error('Get User Activity Error:', err);
          return res.status(500).json({
            message: 'Database error while fetching user data.',
            status: false
          });
        }

        if (userResult.length === 0) {
          return res.status(404).json({
            message: 'ไม่พบข้อมูลผู้ใช้หรือกิจกรรม',
            status: false
          });
        }

        const user = userResult[0];
        const fullName = user.Student_FirstName
          ? `${user.Student_FirstName} ${user.Student_LastName}`
          : `${user.Teacher_FirstName} ${user.Teacher_LastName}`;

        const certificateFilename = `certificate_${uuidv4()}.png`;
        const insertSql = `INSERT INTO certificate 
          (Certificate_ImageFile, Activity_ID, Users_ID, Template_ID) VALUES (?, ?, ?, ?)`;

        db.query(insertSql, [certificateFilename, activityId, userId, templateId], (err, result) => {
          if (err) {
            console.error('Insert Certificate Error:', err);
            return res.status(500).json({
              message: 'Database error while creating certificate.',
              status: false
            });
          }

          res.status(201).json({
            message: 'สร้างเกียรติบัตรสำเร็จ',
            status: true,
            data: {
              Certificate_ID: result.insertId,
              Certificate_ImageFile: certificateFilename,
              recipientName: fullName,
              activityTitle: user.Activity_Title,
              endDate: user.Activity_EndTime
            }
          });
        });
      });
    });
  } catch (err) {
    console.error('Generate Certificate Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while generating certificate.',
      status: false
    });
  }
});

////////////////////////////////Activity API///////////////////////////////////////
// API Get all activity types**
app.get('/api/admin/activity-types', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({
      message: "Permission denied. Only staff can access activity types.",
      status: false
    });
  }

  try {
    const sql = `SELECT ActivityType_ID, ActivityType_Name, ActivityType_Description 
      FROM activitytype ORDER BY ActivityType_Name`;

    db.query(sql, (err, results) => {
      if (err) {
        console.error('Get Activity Types Error:', err);
        return res.status(500).json({
          message: 'Database error while fetching activity types.',
          status: false
        });
      }

      res.status(200).json({
        message: 'Activity types retrieved successfully.',
        status: true,
        data: results
      });
    });
  } catch (err) {
    console.error('Get Activity Types Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while fetching activity types.',
      status: false
    });
  }
});

// API Get all activity statuses**
app.get('/api/admin/activity-statuses', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({
      message: "Permission denied. Only staff can access activity statuses.",
      status: false
    });
  }

  try {
    const sql = `SELECT ActivityStatus_ID, ActivityStatus_Name, ActivityStatus_Description 
      FROM activitystatus ORDER BY ActivityStatus_Name`;

    db.query(sql, (err, results) => {
      if (err) {
        console.error('Get Activity Statuses Error:', err);
        return res.status(500).json({
          message: 'Database error while fetching activity statuses.',
          status: false
        });
      }

      res.status(200).json({
        message: 'Activity statuses retrieved successfully.',
        status: true,
        data: results
      });
    });
  } catch (err) {
    console.error('Get Activity Statuses Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while fetching activity statuses.',
      status: false
    });
  }
});

// API Get all activities**
app.get('/api/admin/activities', RateLimiter(1 * 60 * 1000, 300), VerifyTokens_Website, (req, res) => {
  const userData = req.user;
  const Users_Type = userData?.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'website') {
    return res.status(403).json({
      message: "Permission denied. This action is only allowed on the website.",
      status: false
    });
  }

  if (Users_Type !== 'staff') {
    return res.status(403).json({
      message: "Permission denied. Only staff can access activities.",
      status: false
    });
  }

  try {
    const sql = `
      SELECT a.*, 
      at.ActivityType_Name, 
      ast.ActivityStatus_Name,
      t.Template_Name
      FROM activity a
      LEFT JOIN activitytype at ON a.ActivityType_ID = at.ActivityType_ID
      LEFT JOIN activitystatus ast ON a.ActivityStatus_ID = ast.ActivityStatus_ID
      LEFT JOIN template t ON a.Template_ID = t.Template_ID
      ORDER BY a.Activity_RegisTime DESC`;

    db.query(sql, (err, results) => {
      if (err) {
        console.error('Get Activities Error:', err);
        return res.status(500).json({
          message: 'Database error while fetching activities.',
          status: false
        });
      }

      res.status(200).json({
        message: 'Activities retrieved successfully.',
        status: true,
        data: results
      });
    });
  } catch (err) {
    console.error('Get Activities Error:', err);
    res.status(500).json({
      message: 'An unexpected error occurred while fetching activities.',
      status: false
    });
  }
});

// API Create new activity**
app.post('/api/admin/activities', activityUpload.single('activityImage'),
  RateLimiter(1 * 60 * 1000, 30), VerifyTokens_Website, async (req, res) => {

    const userData = req.user;
    const Users_Type = userData?.Users_Type;
    const Login_Type = userData?.Login_Type;

    if (Login_Type !== 'website') {
      return res.status(403).json({
        message: "Permission denied. This action is only allowed on the website.",
        status: false
      });
    }

    if (Users_Type !== 'staff') {
      return res.status(403).json({
        message: "Permission denied. Only staff can create activities.",
        status: false
      });
    }

    let {
      activityTitle,
      activityDescription,
      activityLocationDetail,
      activityLocationGPS,
      activityStartTime,
      activityEndTime,
      activityIsRequire,
      activityTypeId,
      activityStatusId,
      templateId
    } = req.body;

    // Validate required fields
    if (!activityTitle || !activityDescription || !activityStartTime || !activityEndTime) {
      return res.status(400).json({
        message: 'กรุณากรอกข้อมูลที่จำเป็นให้ครบถ้วน',
        status: false
      });
    }

    try {
      // Sanitize inputs
      activityTitle = xss(activityTitle.trim());
      activityDescription = xss(activityDescription.trim());
      activityLocationDetail = activityLocationDetail ? xss(activityLocationDetail.trim()) : null;
      activityIsRequire = activityIsRequire === 'true' || activityIsRequire === true;

      // Parse dates
      const startTime = new Date(activityStartTime);
      const endTime = new Date(activityEndTime);

      if (endTime <= startTime) {
        return res.status(400).json({
          message: 'เวลาสิ้นสุดกิจกรรมต้องมากกว่าเวลาเริ่มต้น',
          status: false
        });
      }

      // Handle GPS coordinates if provided
      let gpsPoint = null;
      if (activityLocationGPS) {
        try {
          const gpsData = JSON.parse(activityLocationGPS);
          if (gpsData.lat && gpsData.lng) {
            gpsPoint = `POINT(${gpsData.lng} ${gpsData.lat})`;
          }
        } catch (e) {
          console.warn('Invalid GPS data:', e);
        }
      }

      // Handle image upload
      let imageFilename = null;
      if (req.file) {
        const detected = await fileType.fileTypeFromBuffer(req.file.buffer);
        if (!detected || !['image/jpeg', 'image/png'].includes(detected.mime)) {
          return res.status(400).json({
            message: 'ไฟล์ต้องเป็นรูปภาพเท่านั้น (JPG, PNG)',
            status: false
          });
        }

        const processedBuffer = await sharp(req.file.buffer)
          .resize({ width: 1200, height: 800, fit: 'inside' })
          .jpeg({ quality: 85 })
          .toBuffer();

        imageFilename = `activity_${uuidv4()}.jpg`;
        const savePath = path.join(uploadDir_Activity, imageFilename);
        fs.writeFileSync(savePath, processedBuffer);
      }

      const sql = `
        INSERT INTO activity (
        Activity_Title, 
        Activity_Description, 
        Activity_LocationDetail,
        Activity_LocationGPS,
        Activity_StartTime, 
        Activity_EndTime,
        Activity_ImageFile,
        Activity_IsRequire,
        ActivityType_ID,
        ActivityStatus_ID,
        Template_ID
      ) VALUES (?, ?, ?, ${gpsPoint ? 'ST_GeomFromText(?)' : 'NULL'}, ?, ?, ?, ?, ?, ?, ?)`;

      const params = gpsPoint
        ? [activityTitle, activityDescription, activityLocationDetail, gpsPoint,
          startTime, endTime, imageFilename, activityIsRequire,
          activityTypeId || null, activityStatusId || null, templateId || null]
        : [activityTitle, activityDescription, activityLocationDetail,
          startTime, endTime, imageFilename, activityIsRequire,
          activityTypeId || null, activityStatusId || null, templateId || null];

      db.query(sql, params, (err, result) => {
        if (err) {
          console.error('Create Activity Error:', err);
          if (imageFilename) {
            const filePath = path.join(uploadDir_Activity, imageFilename);
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
          }
          return res.status(500).json({
            message: 'Database error while creating activity.',
            status: false
          });
        }

        res.status(201).json({
          message: 'สร้างกิจกรรมสำเร็จ',
          status: true,
          data: {
            Activity_ID: result.insertId,
            Activity_Title: activityTitle,
            Activity_ImageFile: imageFilename
          }
        });
      });

    } catch (err) {
      console.error('Create Activity Error:', err);
      res.status(500).json({
        message: 'An unexpected error occurred while creating activity.',
        status: false
      });
    }
  });

// API Update activity**
app.put('/api/admin/activities/:id', activityUpload.single('activityImage'),
  RateLimiter(1 * 60 * 1000, 30), VerifyTokens_Website, async (req, res) => {

    const userData = req.user;
    const Users_Type = userData?.Users_Type;
    const Login_Type = userData?.Login_Type;
    const activityId = parseInt(req.params.id);

    if (Login_Type !== 'website') {
      return res.status(403).json({
        message: "Permission denied. This action is only allowed on the website.",
        status: false
      });
    }

    if (Users_Type !== 'staff') {
      return res.status(403).json({
        message: "Permission denied. Only staff can update activities.",
        status: false
      });
    }

    if (!activityId || isNaN(activityId)) {
      return res.status(400).json({
        message: "Invalid activity ID provided.",
        status: false
      });
    }

    let {
      activityTitle,
      activityDescription,
      activityLocationDetail,
      activityStartTime,
      activityEndTime,
      activityIsRequire,
      activityTypeId,
      activityStatusId,
      templateId
    } = req.body;

    if (!activityTitle || !activityDescription || !activityStartTime || !activityEndTime) {
      return res.status(400).json({
        message: 'กรุณากรอกข้อมูลที่จำเป็นให้ครบถ้วน',
        status: false
      });
    }

    try {
      // Get current activity
      const getCurrentSql = `SELECT Activity_ImageFile FROM activity WHERE Activity_ID = ?`;
      db.query(getCurrentSql, [activityId], async (err, currentResult) => {
        if (err) {
          console.error('Get Current Activity Error:', err);
          return res.status(500).json({
            message: 'Database error while fetching current activity.',
            status: false
          });
        }

        if (currentResult.length === 0) {
          return res.status(404).json({
            message: 'ไม่พบกิจกรรมที่ต้องการแก้ไข',
            status: false
          });
        }

        let imageFilename = currentResult[0].Activity_ImageFile;

        // Handle new image upload
        if (req.file) {
          const detected = await fileType.fileTypeFromBuffer(req.file.buffer);
          if (!detected || !['image/jpeg', 'image/png'].includes(detected.mime)) {
            return res.status(400).json({
              message: 'ไฟล์ต้องเป็นรูปภาพเท่านั้น (JPG, PNG)',
              status: false
            });
          }

          const processedBuffer = await sharp(req.file.buffer)
            .resize({ width: 1200, height: 800, fit: 'inside' })
            .jpeg({ quality: 85 })
            .toBuffer();

          imageFilename = `activity_${uuidv4()}.jpg`;
          const savePath = path.join(uploadDir_Activity, imageFilename);
          fs.writeFileSync(savePath, processedBuffer);
        }

        // Sanitize inputs
        activityTitle = xss(activityTitle.trim());
        activityDescription = xss(activityDescription.trim());
        activityLocationDetail = activityLocationDetail ? xss(activityLocationDetail.trim()) : null;
        activityIsRequire = activityIsRequire === 'true' || activityIsRequire === true;

        const startTime = new Date(activityStartTime);
        const endTime = new Date(activityEndTime);

        if (endTime <= startTime) {
          return res.status(400).json({
            message: 'เวลาสิ้นสุดกิจกรรมต้องมากกว่าเวลาเริ่มต้น',
            status: false
          });
        }

        // Update activity
        const updateSql = `
        UPDATE activity SET
          Activity_Title = ?,
          Activity_Description = ?,
          Activity_LocationDetail = ?,
          Activity_StartTime = ?,
          Activity_EndTime = ?,
          Activity_ImageFile = ?,
          Activity_IsRequire = ?,
          ActivityType_ID = ?,
          ActivityStatus_ID = ?,
          Template_ID = ?
        WHERE Activity_ID = ?`;

        db.query(updateSql, [
          activityTitle, activityDescription, activityLocationDetail,
          startTime, endTime, imageFilename, activityIsRequire,
          activityTypeId || null, activityStatusId || null, templateId || null,
          activityId
        ], (err, result) => {
          if (err) {
            console.error('Update Activity Error:', err);
            return res.status(500).json({
              message: 'Database error while updating activity.',
              status: false
            });
          }

          // Delete old image if new one was uploaded
          if (req.file && currentResult[0].Activity_ImageFile &&
            currentResult[0].Activity_ImageFile !== imageFilename) {
            const oldFilePath = path.join(uploadDir_Activity, currentResult[0].Activity_ImageFile);
            if (fs.existsSync(oldFilePath)) {
              fs.unlinkSync(oldFilePath);
            }
          }

          res.status(200).json({
            message: 'แก้ไขกิจกรรมสำเร็จ',
            status: true,
            data: {
              Activity_ID: activityId,
              Activity_Title: activityTitle
            }
          });
        });
      });

    } catch (err) {
      console.error('Update Activity Error:', err);
      res.status(500).json({
        message: 'An unexpected error occurred while updating activity.',
        status: false
      });
    }
  });

// API Delete activity**
app.delete('/api/admin/activities/:id', RateLimiter(1 * 60 * 1000, 30),
  VerifyTokens_Website, (req, res) => {

    const userData = req.user;
    const Users_Type = userData?.Users_Type;
    const Login_Type = userData?.Login_Type;
    const activityId = parseInt(req.params.id);

    if (Login_Type !== 'website') {
      return res.status(403).json({
        message: "Permission denied. This action is only allowed on the website.",
        status: false
      });
    }

    if (Users_Type !== 'staff') {
      return res.status(403).json({
        message: "Permission denied. Only staff can delete activities.",
        status: false
      });
    }

    if (!activityId || isNaN(activityId)) {
      return res.status(400).json({
        message: "Invalid activity ID provided.",
        status: false
      });
    }

    try {
      // Check if activity has registrations
      const checkRegistrationsSql = `
      SELECT COUNT(*) as count FROM registration WHERE Activity_ID = ?`;

      db.query(checkRegistrationsSql, [activityId], (err, regResult) => {
        if (err) {
          console.error('Check Registrations Error:', err);
          return res.status(500).json({
            message: 'Database error while checking registrations.',
            status: false
          });
        }

        if (regResult[0].count > 0) {
          return res.status(400).json({
            message: 'ไม่สามารถลบกิจกรรมที่มีผู้ลงทะเบียนแล้วได้',
            status: false
          });
        }

        // Get activity image filename
        const getSql = `SELECT Activity_ImageFile FROM activity WHERE Activity_ID = ?`;
        db.query(getSql, [activityId], (err, result) => {
          if (err) {
            console.error('Get Activity Error:', err);
            return res.status(500).json({
              message: 'Database error while fetching activity.',
              status: false
            });
          }

          if (result.length === 0) {
            return res.status(404).json({
              message: 'ไม่พบกิจกรรมที่ต้องการลบ',
              status: false
            });
          }

          const imageFile = result[0].Activity_ImageFile;

          // Delete activity
          const deleteSql = `DELETE FROM activity WHERE Activity_ID = ?`;
          db.query(deleteSql, [activityId], (err, deleteResult) => {
            if (err) {
              console.error('Delete Activity Error:', err);
              return res.status(500).json({
                message: 'Database error while deleting activity.',
                status: false
              });
            }

            // Delete image file if exists
            if (imageFile) {
              const filePath = path.join(uploadDir_Activity, imageFile);
              if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
              }
            }

            res.status(200).json({
              message: 'ลบกิจกรรมสำเร็จ',
              status: true
            });
          });
        });
      });

    } catch (err) {
      console.error('Delete Activity Error:', err);
      res.status(500).json({
        message: 'An unexpected error occurred while deleting activity.',
        status: false
      });
    }
  });

////////////////////////////////Other Phone API///////////////////////////////////////
//API add Other Phone Number
app.post('/api/profile/otherphone/add', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;
  let { OtherPhone_Phone, OtherPhone_Name } = req.body || {};
  const Login_Type = userData?.Login_Type;

  OtherPhone_Phone = OtherPhone_Phone?.trim();
  OtherPhone_Name = OtherPhone_Name?.trim();

  if (!Users_ID || !OtherPhone_Phone || !OtherPhone_Name) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  if (Login_Type !== 'application') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed in the application.", status: false });
  }

  if (typeof Users_ID !== 'number' || typeof OtherPhone_Phone !== 'string' || typeof OtherPhone_Name !== 'string') {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  if (!validator.isMobilePhone(OtherPhone_Phone, 'any', { strictMode: false })) {
    return res.status(400).json({ message: "Invalid phone number format.", status: false });
  }

  if (OtherPhone_Phone.length > 20 || OtherPhone_Phone.length < 8) {
    return res.status(400).json({ message: "Phone number length must be between 8 and 20 digits.", status: false });
  }

  if (!/^\d+$/.test(OtherPhone_Phone)) {
    return res.status(400).json({ message: "Phone number must contain only digits.", status: false });
  }

  const checkSql = "SELECT COUNT(*) AS phoneCount FROM otherphone WHERE Users_ID = ?";
  db.query(checkSql, [Users_ID], (err, checkResult) => {
    if (err) {
      console.error('Database error (check count)', err);
      return res.status(500).json({ message: 'Server error while checking phone count.', status: false });
    }

    const phoneCount = checkResult[0]?.phoneCount || 0;
    if (phoneCount >= 2) {
      return res.status(400).json({ message: "You can only have up to 2 other phone numbers.", status: false });
    }

    const insertSql = "INSERT INTO otherphone (Users_ID, OtherPhone_Phone, OtherPhone_Name) VALUES (?, ?, ?)";
    db.query(insertSql, [Users_ID, OtherPhone_Phone, OtherPhone_Name], (err, insertResult) => {
      if (err) {
        console.error('Database error (insert)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (insertResult.affectedRows > 0) {
        return res.status(200).json({ message: 'Other phone number added successfully.', status: true });
      } else {
        return res.status(500).json({ message: 'Other phone number not added.', status: false });
      }
    });
  });
});

//API delete Other Phone Number
app.delete('/api/profile/otherphone/delete/:OtherPhone_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;
  const { OtherPhone_ID } = req.params;
  const Login_Type = userData?.Login_Type;

  if (!Users_ID || !OtherPhone_ID) {
    return res.status(400).json({ message: 'Please provide valid Users_ID and OtherPhone_ID.', status: false });
  }

  if (!OtherPhone_ID || isNaN(Number(OtherPhone_ID))) {
    return res.status(400).json({ message: 'Invalid OtherPhone_ID.', status: false });
  }

  if (Login_Type !== 'application') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed in the application.", status: false });
  }

  try {
    const checkSql = "SELECT * FROM otherphone WHERE OtherPhone_ID = ? AND Users_ID = ?";
    db.query(checkSql, [OtherPhone_ID, Users_ID], (err, checkResult) => {
      if (err) {
        console.error('Database error (check ownership)', err);
        return res.status(500).json({ message: 'Server error while verifying phone owner.', status: false });
      }

      if (checkResult.length === 0) {
        return res.status(403).json({ message: 'You do not have permission to delete this phone number.', status: false });
      }

      const deleteSql = "DELETE FROM otherphone WHERE OtherPhone_ID = ?";
      db.query(deleteSql, [OtherPhone_ID], (err, result) => {
        if (err) {
          console.error('Database error (delete)', err);
          return res.status(500).json({ message: 'Error deleting phone number.', status: false });
        }

        return res.status(200).json({ message: 'Other phone number deleted successfully.', status: true });
      });
    });
  } catch (error) {
    console.error('Catch error (delete)', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API edit Other Phone Number
app.put('/api/profile/otherphone/edit/:OtherPhone_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;
  let { OtherPhone_ID } = req.params;
  let { OtherPhone_Name, OtherPhone_Phone } = req.body || {};
  const Login_Type = userData?.Login_Type;

  OtherPhone_Name = OtherPhone_Name?.trim();
  OtherPhone_Phone = OtherPhone_Phone?.trim();

  if (!Users_ID || !OtherPhone_ID) {
    return res.status(400).json({ message: 'Please provide valid Users_ID and OtherPhone_ID.', status: false });
  }

  if (isNaN(Number(OtherPhone_ID))) {
    return res.status(400).json({ message: 'Invalid OtherPhone_ID.', status: false });
  }

  if (Login_Type !== 'application') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed in the application.", status: false });
  }

  if (!OtherPhone_Name || !OtherPhone_Phone) {
    return res.status(400).json({ message: 'Missing required fields.', status: false });
  }

  if (typeof OtherPhone_Name !== 'string' || typeof OtherPhone_Phone !== 'string') {
    return res.status(400).json({ message: 'Invalid data format.', status: false });
  }

  if (!validator.isMobilePhone(OtherPhone_Phone, 'any', { strictMode: false })) {
    return res.status(400).json({ message: "Invalid phone number format.", status: false });
  }

  if (OtherPhone_Phone.length > 20 || OtherPhone_Phone.length < 8) {
    return res.status(400).json({ message: "Phone number length must be between 8 and 20 digits.", status: false });
  }

  if (!/^\d+$/.test(OtherPhone_Phone)) {
    return res.status(400).json({ message: "Phone number must contain only digits.", status: false });
  }

  const checkSql = "SELECT * FROM otherphone WHERE OtherPhone_ID = ? AND Users_ID = ?";
  db.query(checkSql, [OtherPhone_ID, Users_ID], (err, checkResult) => {
    if (err) {
      console.error('Database error (check ownership)', err);
      return res.status(500).json({ message: 'Error checking ownership.', status: false });
    }

    if (checkResult.length === 0) {
      return res.status(403).json({ message: 'You do not have permission to edit this phone number.', status: false });
    }

    const updateSql = "UPDATE otherphone SET OtherPhone_Name = ?, OtherPhone_Phone = ? WHERE OtherPhone_ID = ? AND Users_ID = ?";
    db.query(updateSql, [OtherPhone_Name, OtherPhone_Phone, OtherPhone_ID, Users_ID], (err, result) => {
      if (err) {
        console.error('Database error (update)', err);
        return res.status(500).json({ message: 'Error updating phone number.', status: false });
      }

      if (result.affectedRows > 0) {
        return res.status(200).json({ message: 'Other phone number updated successfully.', status: true });
      } else {
        return res.status(404).json({ message: 'Other phone number not found.', status: false });
      }
    });
  });
});


//API get Other Phone Number by Token
app.get('/api/profile/otherphone/get', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'application') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed in the application.", status: false });
  }

  if (!Users_ID || typeof Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Users_ID from token.", status: false });
  }

  try {
    const sql = "SELECT OtherPhone_ID, Users_ID, OtherPhone_Name, OtherPhone_Phone FROM otherphone WHERE Users_ID = ?";
    db.query(sql, [Users_ID], (err, result) => {
      if (err) {
        console.error('Database error while getting other phones for Users_ID:', Users_ID, err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length > 0) {
        res.status(200).json({ data: result, message: 'Other phone numbers retrieved successfully.', status: true });
      } else {
        return res.status(404).json({ data: [], message: 'No other phone numbers found for this user.', status: false, });
      }
    });
  } catch (error) {
    console.error('Unexpected error while retrieving other phones', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API get Other Phone Number by OtherPhone_ID
app.get('/api/profile/otherphone/getbyphoneid/:OtherPhone_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;
  const { OtherPhone_ID } = req.params;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'application') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed in the application.", status: false });
  }

  if (!Users_ID || typeof Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Users_ID from token.", status: false });
  }

  if (!OtherPhone_ID || isNaN(Number(OtherPhone_ID))) {
    return res.status(400).json({ message: "Invalid OtherPhone_ID parameter.", status: false });
  }

  try {
    const sql = "SELECT OtherPhone_ID, Users_ID, OtherPhone_Name, OtherPhone_Phone FROM otherphone WHERE OtherPhone_ID = ? AND Users_ID = ?";
    db.query(sql, [OtherPhone_ID, Users_ID], (err, result) => {
      if (err) {
        console.error('Database error (get by ID)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length > 0) {
        const results = result[0];
        const phoneData = results;
        phoneData['message'] = 'Other phone number retrieved successfully.';
        phoneData['status'] = true;
        res.status(200).json(phoneData);
      } else {
        return res.status(404).json({ message: 'Other phone number not found or access denied.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error (get by ID)', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API Verify Password By VerifyTokens
app.post('/api/profile/verifypassword', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  let { Users_Password } = req.body || {};
  const userData = req.user;
  const Users_ID = userData.Users_ID;
  const Login_Type = userData?.Login_Type;

  if (!Users_ID || typeof Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Users_ID from token.", status: false });
  }

  if (Login_Type !== 'application') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed in the application.", status: false });
  }

  if (!Users_Password || typeof Users_Password !== 'string') {
    return res.status(400).json({ message: 'Please fill in the correct parameters as required.', status: false });
  }

  Users_Password = xss(Users_Password)

  try {
    const sql = "SELECT Users_Password FROM users WHERE Users_ID = ? LIMIT 1";
    db.query(sql, [Users_ID], (err, result) => {
      if (err) {
        console.error('Database error (verify password)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.length > 0) {
        const hashedPassword = result[0].Users_Password;
        const isMatch = bcrypt.compareSync(Users_Password, hashedPassword);
        if (isMatch) {
          return res.status(200).json({ message: 'Password verified successfully.', status: true });
        }
        return res.status(401).json({ message: 'Incorrect password.', status: false });
      }
      return res.status(404).json({ message: 'User not found.', status: false });
    }
    );
  } catch (error) {
    console.error('Catch error (verify password)', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API Reset Password By VerifyTokens
app.post('/api/profile/resetpassword', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const Users_ID = userData.Users_ID;
  const Login_Type = userData?.Login_Type;
  const Users_Email = userData?.Users_Email;

  const { Current_Password, New_Password } = req.body || {};

  if (!Users_ID || typeof Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Users_ID from token.", status: false });
  }

  if (Login_Type !== 'application') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed in the application.", status: false });
  }

  if (!Current_Password || typeof Current_Password !== 'string' || !New_Password || typeof New_Password !== 'string') {
    return res.status(400).json({ message: 'Please fill in the correct parameters as required.', status: false });
  }

  if (New_Password.length < 8 || New_Password.length > 63) {
    return res.status(400).json({ message: 'New password must be between 8 and 63 characters.', status: false });
  }

  if (Current_Password === New_Password) {
    return res.status(400).json({ message: 'New password cannot be the same as the current password.', status: false });
  }

  try {
    const sql = "SELECT Users_ID, Users_Password FROM users WHERE Users_ID = ? AND Users_IsActive = 1";
    db.query(sql, [Users_ID], async (err, result) => {
      if (err) {
        console.error('Database error (reset password)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length === 0) {
        return res.status(404).json({ message: 'User not found.', status: false });
      }

      const user = result[0];
      const passwordMatch = await bcrypt.compare(Current_Password, user.Users_Password);
      if (!passwordMatch) {
        return res.status(401).json({ message: 'Current password is incorrect.', status: false });
      }

      const hashedPassword = await bcrypt.hash(New_Password, saltRounds);
      const updateSql = "UPDATE users SET Users_Password = ? WHERE Users_ID = ?";
      db.query(updateSql, [hashedPassword, user.Users_ID], async (err, updateResult) => {
        if (err) {
          console.error('Database error (update password)', err);
          return res.status(500).json({ message: 'An error occurred while updating the password.', status: false });
        }

        if (updateResult.affectedRows > 0) {
          try {
            const notifyMsg = 'บัญชีของคุณได้รับการอัปเดตรหัสผ่านเรียบร้อยแล้ว หากคุณไม่ได้ทำรายการนี้ โปรดติดต่อฝ่ายสนับสนุนโดยด่วน';
            await sendEmail(Users_Email, "แจ้งเตือน: คุณได้เปลี่ยนรหัสผ่าน", "หากไม่ใช่คุณ กรุณาติดต่อทีมงานด่วน", "เปลี่ยนรหัสผ่านสำเร็จ", notifyMsg);
            return res.status(200).json({ message: 'Password reset successfully.', status: true });

          } catch (emailError) {
            console.error('Error sending notification email:', emailError);
            return res.status(500).json({ message: 'Password reset successful, but failed to send notification email.', status: true });
          }
        } else {
          return res.status(500).json({ message: 'Password reset failed.', status: false });
        }
      });
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Get Data Profile by VerifyTokens
app.get('/api/profile/data/get', RateLimiter(0.5 * 60 * 1000, 24), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const usersTypeID = userData.UsersType_ID;
  const usersType = userData.Users_Type;
  const Login_Type = userData?.Login_Type;

  if (Login_Type !== 'application') {
    return res.status(403).json({ message: "Permission denied. This action is only allowed in the application.", status: false });
  }

  if (!usersType || !usersTypeID) {
    return res.status(400).json({ message: "Missing user type or ID.", status: false });
  }

  try {
    const usersType_upper = usersType.charAt(0).toUpperCase() + usersType.slice(1);
    const tableName = db.escapeId(usersType);
    const columnName = db.escapeId(`${usersType_upper}_ID`);

    let sql;

    if (usersType === 'student') {
      sql = `SELECT ty.*, u.Users_Email, u.Users_ImageFile ,t.Teacher_FirstName, t.Teacher_LastName, dp.Department_Name, f.Faculty_Name FROM
        ((((${tableName} ty INNER JOIN department dp ON ty.Department_ID = dp.Department_ID) INNER JOIN faculty f ON dp.Faculty_ID = f.Faculty_ID)
        INNER JOIN teacher t ON ty.Teacher_ID = t.Teacher_ID) INNER JOIN users u ON ty.Users_ID = u.Users_ID) WHERE ${columnName} = ? LIMIT 1;`;
    } else if (usersType === 'teacher') {
      sql = `SELECT ty.*, u.Users_Email, u.Users_ImageFile, dp.Department_Name, f.Faculty_Name FROM (((${tableName} ty 
        INNER JOIN department dp ON ty.Department_ID = dp.Department_ID) INNER JOIN faculty f ON dp.Faculty_ID = f.Faculty_ID) 
        INNER JOIN users u ON ty.Users_ID = u.Users_ID) WHERE ${columnName} = ? LIMIT 1`;
    } else {
      return res.status(400).json({ message: "Invalid user type.", status: false });
    }

    db.query(sql, [usersTypeID], (err, result) => {
      if (err) {
        console.error('Database error (profile data)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length > 0) {
        const profileData = result[0];
        profileData['Users_Type_Table'] = usersType;
        profileData['message'] = 'Profile data retrieved successfully.';
        profileData['status'] = true;
        res.status(200).json(profileData);
      } else {
        return res.status(404).json({ message: 'No profile data found for this user.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

/////////////////////////////////////////////////////////////////////////

app.listen(process.env.SERVER_PORT, () => {
  console.log(`Example app listening on port ${process.env.SERVER_PORT}`)
});