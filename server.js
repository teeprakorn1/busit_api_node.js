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

//////////////////////////////////SWAGGER CONFIG///////////////////////////////////////
//Swagger Verification
const swaggerDocument = YAML.load('./swagger.yaml');
const protectSwagger = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token || token !== `Bearer ${process.env.SWAGGER_TOKEN}`) {
    return res.status(403).json({ message: 'Unauthorized access to Swagger UI' });
  }
  next();
};

//Swagger Mode 0 (Development) or 1 (Production)
if (process.env.NODE_ENV === '1') {
  app.use('/api-docs', protectSwagger, swaggerUi.serve, swaggerUi.setup(swaggerDocument, { explorer: true }));
} else {
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, { explorer: true }));
}

//////////////////////////////////TEST API///////////////////////////////////////
//TEST ENCRYPT
app.post('/api/test/encrypt', async (req, res) => {
    const {password} = req.body;
    if (!password) { res.status(400).json({ message: 'Password is required.', status: false });}  
    const NewPassword = await bcrypt.hash(password, saltRounds);
    res.send({ message: NewPassword ,status: true });
});

//TEST DECRYPT
app.post('/api/test/decrypt', async (req, res) => {
    const {password, hash} = req.body;
    if (!password || !hash) { res.status(400).json({ message: 'Password and hash are required.', status: false });}
    const isCorrect = await bcrypt.compare(password, hash);
    if (isCorrect) {
        res.send({ message: "The password is correct.",status: true });
    }else{
        res.status(201).send({ message: "The password is incorrect.",status: false });
    }
});

// //////////////////////////////////Tokens API///////////////////////////////////////
// //Verify Tokens API
// app.post('/api/VerifyToken', VerifyTokens, function (req, res) {
//   const isSuccess = req.Users_decoded;
//   if (isSuccess) {
//     res.send({
//       Users_ID: req.Users_decoded.Users_ID,
//       Users_Username: req.Users_decoded.Users_Username,
//       UsersType_ID: req.Users_decoded.UsersType_ID,
//       status: true
//     });
//   } else {
//     res.send({ status: false });
//   }
// });

// //////////////////////////////////Login API///////////////////////////////////////
// //API Login
// app.post('/api/login', loginRateLimiter, async (req, res) => {
//   let { Users_Email, Users_Password } = req.body;

//   if (!Users_Email || !Users_Password ||
//     typeof Users_Email !== 'string' || typeof Users_Password !== 'string') {
//     return res.send({ message: 'Please fill in the correct parameters as required.', status: false });
//   }

//   Users_Email = xss(validator.escape(Users_Email));
//   Users_Password = xss(validator.escape(Users_Password));

//   const sql_check_username = "SELECT COUNT(*) AS count FROM Users WHERE Users_Email = ? AND Users_IsActive = 1";
//   db.query(sql_check_username, [Users_Email], async (err, result) => {
//     if (err) { return res.status(500).send({ message: 'An error occurred on the server.', status: false }); }

//     if (result[0].count > 0) {
//       const sql_get_password = "SELECT Users_Password FROM Users WHERE Users_Email = ? AND Users_IsActive = 1";
//       db.query(sql_get_password, [Users_Email], async (err, result) => {
//         if (err) { return res.status(500).send({ message: 'An error occurred on the server.', status: false }); }

//         const isCorrect = await bcrypt.compare(Users_Password, result[0].Users_Password);
//         if (isCorrect) {
//           const sql = "SELECT * FROM Users WHERE Users_Email = ? AND Users_IsActive = 1";
//           db.query(sql, [Users_Email], async (err, result) => {
//             if (err) { return res.status(500).send({ message: 'An error occurred on the server.', status: false }); }
//             const results = result[0];

//             const sql_insert_timestamp = "INSERT INTO Userstimestamp (Users_ID)VALUES(?)";
//             db.query(sql_insert_timestamp, [results.Users_ID], async (err) => {
//               if (err) { return res.status(500).send({ message: 'Unable to record time', status: false }); }
//               const Users = {};
//               const Tokens = GenerateTokens(results.Users_ID, results.Users_Email, results.UsersType_ID);
//               Users['token'] = Tokens;
//               Users['message'] = "The password is correct."
//               Users['status'] = true
//               res.send(Users);
//             });
//           });
//         } else {
//           res.send({ message: "The password is incorrect.", status: false });
//         }
//       });
//     } else {
//       res.send({ message: "The password is incorrect.", status: false });
//     }
//   });
// });

// /////////////////////////////////////////////////////////////////////////

app.listen(process.env.SERVER_PORT, () => {
  console.log(`Example app listening on port ${process.env.SERVER_PORT}`)
});