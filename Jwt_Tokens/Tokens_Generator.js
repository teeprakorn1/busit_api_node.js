const jwt = require('jsonwebtoken')

//Generator Token
function Tokens_Generator(Employee_ID, Employee_Username, EmployeeType_ID) {
    if(!Employee_ID || !Employee_Username || !EmployeeType_ID ){ return 0;}else{
        let Token;
          Token = jwt.sign(
          {
            Employee_ID:Employee_ID,
            Employee_Username:Employee_Username,
            EmployeeType_ID:EmployeeType_ID
          },
          process.env.PRIVATE_TOKEN_KEY,{ expiresIn: '24h'}
        );
        return Token;
      };
    };

  module.exports = Tokens_Generator;