const jwt = require('jsonwebtoken');

// Verify Token
const Tokens_Verification = (req, res, next) => {
  const token = (req.body && req.body.token) || (req.query && req.query.token) || (req.headers && req.headers['x-access-token']);

  if (!token) {
    return res.status(401).send({ message: 'Token is required for authentication.', status: false });
  }

  try {
    const decode = jwt.verify(token, process.env.PRIVATE_TOKEN_KEY);
    req.Users_decoded = decode;
    next();
  } catch (err) {
    return res.status(402).send({ message: 'Invalid Token.', status: false });
  }
};

module.exports = Tokens_Verification;
