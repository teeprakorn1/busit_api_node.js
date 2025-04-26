const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const axios = require('axios');
const xss = require('xss');
const validator = require('validator');
const xml2js = require('xml2js');
const cors = require('cors');

const YAML = require('yamljs');
const swaggerUi = require('swagger-ui-express');

require('dotenv').config();

const loginRateLimiter = require('./Rate_Limiter/LimitTime_Login');
const GenerateTokens = require('./Jwt_Tokens/Tokens_Generator');
const VerifyTokens = require('./Jwt_Tokens/Tokens_Verification');
const e = require('express');

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

//Global MySQL Error Handler
db.on('error', (err) => {
  console.error('MySQL Error:', err);
  if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code === 'ECONNRESET') {
    console.log('Lost MySQL connection.');
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
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
if (process.env.NODE_ENV === '1') { // Production
  app.use('/api-docs', protectSwagger, swaggerUi.serve, swaggerUi.setup(swaggerDocument, { explorer: true }));
} else { // Development
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, { explorer: true }));
}

////////////////////////////////// TEST API ///////////////////////////////////////
// Encrypt Test
app.post('/api/test/encrypt', async (req, res) => {
  try {
    const { password } = req.body;
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
app.post('/api/test/decrypt', async (req, res) => {
  try {
    const { password, hash } = req.body;
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

////////////////////////////////// Tokens API ///////////////////////////////////////
// Verify Token
app.post('/api/verifyToken', VerifyTokens, (req, res) => {
  const userData = req.Users_decoded;
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

//////////////////////////////////Login API///////////////////////////////////////
//API Login
app.post('/api/login', loginRateLimiter, async (req, res) => {
  let { Users_Email, Users_Password } = req.body;

  if (!Users_Email || !Users_Password ||
    typeof Users_Email !== 'string' || typeof Users_Password !== 'string') {
      return res.status(400).json({ message: 'Please fill in the correct parameters as required.', status: false });
  }

  Users_Email = xss(validator.escape(Users_Email));
  Users_Password = xss(validator.escape(Users_Password));

  const sql_check_username = "SELECT COUNT(*) AS count FROM users WHERE Users_Email = ? AND Users_IsActive = 1";
  db.query(sql_check_username, [Users_Email], async (err, result) => {
    if (err) { return res.status(500).json({ message: 'An error occurred on the server.', status: false }); }

    if (result[0].count > 0) {
      const sql_get_password = "SELECT Users_Password FROM users WHERE Users_Email = ? AND Users_IsActive = 1";
      db.query(sql_get_password, [Users_Email], async (err, result) => {
        if (err) { return res.status(500).json({ message: 'An error occurred on the server.', status: false }); }

        const isCorrect = await bcrypt.compare(Users_Password, result[0].Users_Password);
        if (isCorrect) {
          const sql = "SELECT * FROM users WHERE Users_Email = ? AND Users_IsActive = 1";
          db.query(sql, [Users_Email], async (err, result) => {
            if (err) { return res.status(500).json({ message: 'An error occurred on the server.', status: false });}
            const users_results = result[0];
            const Users = {};
            let sql_users_type, users_type_name_id;
            if (users_results.Users_Type === 'student') {
              sql_users_type = "SELECT * FROM student WHERE Users_ID = ?";
              users_type_name_id = 'Student_ID';
            }else if (users_results.Users_Type === 'teacher') {
              sql_users_type = "SELECT * FROM teacher WHERE Users_ID = ?";
              users_type_name_id = 'Teacher_ID';
            }else if (users_results.Users_Type === 'staff') {
              sql_users_type = "SELECT * FROM staff WHERE Users_ID = ?";
              users_type_name_id = 'Staff_ID';
            }else{
              return res.status(400).json({ message: 'Invalid user type.', status: false });
            }

            db.query(sql_users_type, [users_results.Users_ID], async (err, result) => {
              if (err) { return res.status(500).json({ message: 'An error occurred on the server.', status: false }); }
              const users_type_results = result[0];
              const UsersType_ID = users_type_results[users_type_name_id]

              const Tokens = GenerateTokens(users_results.Users_ID,
                users_results.Users_Email, users_results.Users_Username, UsersType_ID, users_results.Users_Type);
              // const Tokens = GenerateTokens('1','2','3','4','5');
              Users['token'] = Tokens;
              Users['message'] = "The password is correct."
              Users['status'] = true
              res.status(200).send(Users);
            });
          });
        } else {
          res.status(201).json({ message: "The password is incorrect.", status: false });
        }
      });
    } else {
      res.status(202).json({ message: "The password is incorrect.", status: false });
    }
  });
});

/////////////////////////////////////////////////////////////////////////

app.listen(process.env.SERVER_PORT, () => {
  console.log(`Example app listening on port ${process.env.SERVER_PORT}`)
});