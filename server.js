const xss = require('xss');
const cors = require('cors');
const fs = require('fs');
const https = require('https');
const path = require('path');
const multer = require('multer');
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const moment = require('moment');
const validator = require('validator');
const fileType = require('file-type');
const { v4: uuidv4 } = require('uuid');
const sharp = require('sharp');

const YAML = require('yamljs');
const swaggerUi = require('swagger-ui-express');

require('dotenv').config();

const requestLogger = require('./Log_Services/requestLogger');
const RateLimiter = require('./Rate_Limiter/LimitTime_Login');
const GenerateTokens = require('./Jwt_Tokens/Tokens_Generator');
const VerifyTokens = require('./Jwt_Tokens/Tokens_Verification');
const { sendOTP, verifyOTP, sendEmail } = require('./OTP_Services/otpService');
const { verify } = require('jsonwebtoken');

const app = express();
const saltRounds = 14;

//MySQL Connection
const db = mysql.createPool({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASS,
  database: process.env.DATABASE_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const uploadDir = path.join(__dirname, 'images');
const uploadDir_Profile = path.join(__dirname, 'images/users-profile-images');

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

if (!fs.existsSync(uploadDir_Profile)) {
  fs.mkdirSync(uploadDir_Profile, { recursive: true });
}

// Multer configuration for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // จำกัดไฟล์ 5MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg'];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('ประเภทไฟล์ไม่ถูกต้อง'), false);
    }
    cb(null, true);
  }
});

//Global MySQL Error Handler
db.getConnection((err) => {
  if (err) {
    console.error(' Database connection error:', err.code);
    
    if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code === 'ECONNRESET') {
      return res.status(503).json({ message: 'เชื่อมต่อฐานข้อมูลไม่สำเร็จ กรุณาลองใหม่อีกครั้ง' });
    }

    return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเชื่อมต่อฐานข้อมูล' });
  }
});

app.use(express.json());
app.use(requestLogger);
app.use(express.urlencoded({ extended: true }));
app.use('/api/images/profile-images', express.static(uploadDir_Profile));
app.use(cors());

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
    const { password, hash } = req.body|| {};
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

  const { email } = req.body|| {};

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

  const { email, otp } = req.body|| {};
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

  const { email } = req.body|| {};

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
      message: 'Token is valid.',
      status: true,
    });
  }
  return res.status(402).json({ message: 'Invalid Token.', status: false });
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
        return res.status(200).json({ message: 'If your email exists in our system, an OTP has been sent.', status: true });
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
  const { Users_Email, Users_Password, otp } = req.body || {};

  if (!Users_Email || !Users_Password || !otp ||
      typeof Users_Email !== 'string' ||
      typeof Users_Password !== 'string' ||
      typeof otp !== 'string') {
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
          res.status(200).json({ message: 'Password reset successfully.', status: true });
          const notifyMsg = 'บัญชีของคุณได้รับการอัปเดตรหัสผ่านเรียบร้อยแล้ว หากคุณไม่ได้ทำรายการนี้ โปรดติดต่อฝ่ายสนับสนุนโดยด่วน';
          try {
            await sendEmail(Users_Email,"แจ้งเตือน: คุณได้เปลี่ยนรหัสผ่าน","หากไม่ใช่คุณ กรุณาติดต่อทีมงานด่วน","เปลี่ยนรหัสผ่านสำเร็จ",notifyMsg);

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

////////////////////////////////// Login API ///////////////////////////////////////
//API Login Application
app.post('/api/login/application', RateLimiter(1 * 60 * 1000, 5) , async (req, res) => {
  let { Users_Email, Users_Password } = req.body|| {};

  if (!Users_Email || !Users_Password ||
    typeof Users_Email !== 'string' || typeof Users_Password !== 'string') {
    return res.status(400).json({ message: 'Please fill in the correct parameters as required.', status: false });
  }

  Users_Email = xss(validator.escape(Users_Email));
  Users_Password = xss(validator.escape(Users_Password));

  try {
    const sql = "SELECT Users_ID, Users_Email, Users_Username, Users_Password,"+
    " Users_Type FROM users WHERE (Users_Username = ? OR Users_Email = ?) AND Users_IsActive = 1";
    db.query(sql, [Users_Email, Users_Email], async (err, result) => {
      if (err) { 
        console.error('Database error (users)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false }); 
      }

      if (result.length === 0) {
        return res.status(401).json({ message: "The password is incorrect.", status: false });
      }

      const user = result[0];
      const passwordMatch = await bcrypt.compare(Users_Password, user.Users_Password);
      if (!passwordMatch) {
        return res.status(401).json({ message: "The password is incorrect.", status: false });
      }

      // Check Users_Type
      let sql_users_type, users_type_name_id;
      if (user.Users_Type === 'student') {
        sql_users_type = "SELECT Student_ID FROM student WHERE Users_ID = ?";
        users_type_name_id = 'Student_ID';
      } else if (user.Users_Type === 'teacher') {
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

        const token = GenerateTokens(user.Users_ID, 
          user.Users_Email, user.Users_Username, UsersType_ID, user.Users_Type);

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

//API Login Web Admin**

////////////////////////////////// Timestamp API ///////////////////////////////////////
//API Timestamp Insert
app.post('/api/timestamp/insert' , RateLimiter(0.5 * 60 * 1000, 12), async (req, res) => {
  const { Users_ID, TimestampType_ID } = req.body|| {};

  if (!Users_ID || !TimestampType_ID) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  if (typeof Users_ID !== 'number' || typeof TimestampType_ID !== 'number') {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  try {
    const sql = "INSERT INTO timestamp (Users_ID, TimestampType_ID) VALUES (?, ?)";
    db.query(sql, [Users_ID, TimestampType_ID], (err, result) => {
      if (err) {
        console.error('Database error (timestamp)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.affectedRows > 0) {
        return res.status(200).json({ message: 'Timestamp inserted successfully.', status: true });
      }else {
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
    const sql = "SELECT ts.Timestamp_ID, ts.Users_ID, ts.Timestamp_RegisTime, ts.TimestampType_ID, tst.TimestampType_Name "+
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
    const sql = "SELECT ts.Timestamp_ID, ts.Users_ID, ts.Timestamp_RegisTime, ts.TimestampType_ID, tst.TimestampType_Name "+
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

//////////////////////////////////Profile Application API///////////////////////////////////////
//API Edit Student Profile Application
app.post('/api/profile/student/update',RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;
  const Users_Type = userData?.Users_Type;

  if (!Users_ID || typeof Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Users_ID from token.", status: false });
  }

  if (Users_Type?.toLowerCase() !== 'student') {
    return res.status(403).json({ message: "Permission denied. Only students can perform this action.", status: false });
  }

  let { Student_Phone, Student_Birthdate, Student_Religion,Student_MedicalProblem } = req.body || {};

  if (Student_Phone && !validator.isMobilePhone(Student_Phone, 'any', { strictMode: false })) {
    return res.status(400).json({ message: "Invalid phone number format.", status: false });
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
app.post('/api/profile/teacher/update', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;
  const Users_Type = userData?.Users_Type;

  if (!Users_ID || typeof Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Users_ID from token.", status: false });
  }

  if (Users_Type?.toLowerCase() !== 'teacher') {
    return res.status(403).json({ message: "Permission denied. Only Teachers can perform this action.", status: false });
  }

  let { Teacher_Phone, Teacher_Birthdate, Teacher_Religion, Teacher_MedicalProblem } = req.body || {};
  if (Teacher_Phone && !validator.isMobilePhone(Teacher_Phone, 'any', { strictMode: false })) {
    return res.status(400).json({ message: "Invalid phone number format.", status: false });
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

//API add Profile Image in Users of Application
app.post('/api/profile/upload/image', upload.single('Users_ImageFile') ,RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;

  if (!Users_ID || typeof Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Users_ID from token.", status: false });
  }

  if (!req.file) {
    return res.status(400).json({ message: 'Please provide an image file.', status: false });
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
      .resize({ width: 1024 })
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
app.post('/api/profile/otherphone/add', RateLimiter(0.5 * 60 * 1000, 12), async (req, res) => {
  let { Users_ID, OtherPhone_Phone } = req.body|| {};

  if (!Users_ID || !OtherPhone_Phone) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  if (typeof Users_ID !== 'number' || typeof OtherPhone_Phone !== 'string') {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  if (!validator.isMobilePhone(OtherPhone_Phone, 'any', { strictMode: false })) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  if (OtherPhone_Phone.length > 20) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  if (OtherPhone_Phone.length < 8) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  if (!/^\d+$/.test(OtherPhone_Phone)) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  try {
    const sql = "INSERT INTO otherphone (Users_ID, OtherPhone_Phone) VALUES (?, ?)";
    db.query(sql, [Users_ID, OtherPhone_Phone], (err, result) => {
      if (err) {
        console.error('Database error (other phone)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.affectedRows > 0) {
        return res.status(200).json({ message: 'Other phone number added successfully.', status: true });
      } else {
        return res.status(501).json({ message: 'Other phone number not added.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

//API delete Other Phone Number**

//API edit Other Phone Number**

//API get Other Phone Number by Users_ID
app.get('/api/profile/otherphone/get/:Users_ID', RateLimiter(0.5 * 60 * 1000, 12), async (req, res) => {
  const Users_ID = req.params.Users_ID;

  if (!Users_ID) {
    return res.status(400).json({ message: "Please fill in the correct parameters as required.", status: false });
  }

  try {
    const sql = "SELECT OtherPhone_ID, Users_ID, OtherPhone_Phone FROM otherphone WHERE Users_ID = ?";
    db.query(sql, [Users_ID], (err, result) => {
      if (err) {
        console.error('Database error (other phone)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.length > 0) {
        const results = result[0];
        const profileData = results;
        profileData['message'] = 'Other phone numbers retrieved successfully.';
        profileData['status'] = true;
        res.status(200).json(profileData);
      } else {
        return res.status(404).json({ message: 'No other phone numbers found for this user.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Get Data Profile by VerifyTokens
app.post('/api/profile/data/get', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const usersTypeID = userData.UsersType_ID;
  const usersType = userData.Users_Type;

  try {
    const usersType_upper = usersType.charAt(0).toUpperCase() + usersType.slice(1);
    const tableName = db.escapeId(usersType);
    const columnName = db.escapeId(`${usersType_upper}_ID`);

    const sql = `SELECT ty.*,dp.Department_Name,f.Faculty_Name FROM ((${tableName} ty 
    INNER JOIN department dp ON ty.Department_ID = dp.Department_ID) INNER JOIN faculty f ON dp.Faculty_ID = f.Faculty_ID) WHERE ${columnName} = ?`;
    db.query(sql, [usersTypeID], (err, result) => {
      if (err) {
        console.error('Database error (profile data)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }
      if (result.length > 0) {
        const results = result[0];
        const profileData = results;
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