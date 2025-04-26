const jwt = require('jsonwebtoken')

//Generator Token
function Tokens_Generator(Users_ID, Users_Email, Users_Username, UsersType_ID, Users_Type) {
    if(!Users_ID || !Users_Email || !Users_Username || !UsersType_ID || !Users_Type ){ return 0;}else{
        let Token;
          Token = jwt.sign(
          {
            Users_ID: req.Users_decoded.Users_ID,
            Users_Email: req.Users_decoded.Users_Email,
            Users_Username: req.Users_decoded.Users_Username,
            UsersType_ID: req.Users_decoded.UsersType_ID,
            Users_Type: req.Users_decoded.Users_Type
          },
          process.env.PRIVATE_TOKEN_KEY,{ expiresIn: '24h'}
        );
        return Token;
      };
    };

  module.exports = Tokens_Generator;