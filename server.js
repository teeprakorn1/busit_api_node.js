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

const uploadDir = path.join(__dirname, 'images');
const uploadDir_Profile = path.join(__dirname, 'images/users-profile-images');

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

if (!fs.existsSync(uploadDir_Profile)) {
  fs.mkdirSync(uploadDir_Profile, { recursive: true });
}

// Multer configuration
const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'image/pjpeg', 'application/octet-stream'];

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('ประเภทไฟล์ไม่ถูกต้อง'), false);
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

//อนาคตต้องมาแก้ contentSecurityPolicy ของ helmet**
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

app.use(cors({
  origin: isProduction ? process.env.WEB_CLIENT_URL_PROD : process.env.WEB_CLIENT_URL_DEV,
  credentials: true
}));

////////////////////////////////// SWAGGER CONFIG ///////////////////////////////////////
const swaggerDocument = YAML.load('./swagger.yaml');

// Swagger Authorization Middleware
const protectSwagger = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token || token !== `Bearer ${process.env.SWAGGER_TOKEN}`) {
    return res.status(403).json({ message: 'Unauthorized access to Swagger UI' });
  }
  next();
};

// Apply Swagger Middleware
if (process.env.NODE_ENV === '1') { // (Production)
  app.use('/api-docs', protectSwagger, swaggerUi.serve, swaggerUi.setup(swaggerDocument, { explorer: true }));
} else { // (Development)
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, { explorer: true }));
}

////////////////////////////////// TEST API ///////////////////////////////////////
// Encrypt Test
app.post('/api/test/encrypt', RateLimiter(0.5 * 60 * 1000, 15), async (req, res) => {
  if (process.env.NODE_ENV === '0') {
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
  if (process.env.NODE_ENV === '0') {
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
  if (process.env.NODE_ENV === '0') {
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
  if (process.env.NODE_ENV === '0') {
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
  if (process.env.NODE_ENV === '0') {
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

// API Login Web Admin**
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
  res.status(200).json({ message: 'Logged out successfully.' , status: true });
});

////////////////////////////////// Timestamp API ///////////////////////////////////////
//API Timestamp Insert
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


//API Timestamp Get by Users_ID
app.get('/api/timestamp/get/users/:Users_ID', RateLimiter(0.5 * 60 * 1000, 12), async (req, res) => {
  const Users_ID = req.params.Users_ID;

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

//////////////////////////////////Admin Website API///////////////////////////////////////
// API Get Data Admin by VerifyTokens of Admin Website**
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
app.put('/api/admin/student/update/:Users_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
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
app.put('/api/admin/teacher/update/:Users_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
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
app.get('/api/admin/otherphone/get/:Users_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
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
app.get('/api/admin/otherphone/getbyphoneid/:OtherPhone_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
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

// API Get Users Data by Users_ID of Admin Website**
app.get('/api/admin/data/:Users_ID', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
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