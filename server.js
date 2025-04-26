const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const xss = require('xss');
const validator = require('validator');
const cors = require('cors');

const YAML = require('yamljs');
const swaggerUi = require('swagger-ui-express');

require('dotenv').config();

const RateLimiter = require('./Rate_Limiter/LimitTime_Login');
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
app.post('/api/test/decrypt', RateLimiter(0.5 * 60 * 1000, 15), async (req, res) => {
  if (process.env.NODE_ENV === '0') {
    return res.status(403).json({ message: 'This API is not allowed in production.', status: false }); 
  }

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
app.post('/api/verifyToken', RateLimiter(0.5 * 60 * 1000, 15), VerifyTokens, (req, res) => {
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
//API Login Application
app.post('/api/login/application', RateLimiter(1 * 60 * 1000, 5) , async (req, res) => {
  let { Users_Email, Users_Password } = req.body;

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

//reset password API**

//////////////////////////////////Timestamp API///////////////////////////////////////
//API Timestamp Insert
app.post('/api/timestamp/insert' , RateLimiter(0.5 * 60 * 1000, 12), async (req, res) => {
  const { Users_ID, TimestampType_ID } = req.body;

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
        return res.status(200).json({ message: result, status: true });
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
        return res.status(200).json({ message: result, status: true });
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
//API Edit Profile Application**

//API add Profile Image Application**

//API add Other Phone Number
app.post('/api/profile/otherphone/add', RateLimiter(0.5 * 60 * 1000, 12), async (req, res) => {
  let { Users_ID, OtherPhone_Phone } = req.body;

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
        return res.status(200).json({ message: result, status: true });
      } else {
        return res.status(404).json({ message: 'No other phone numbers found for this user.', status: false });
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