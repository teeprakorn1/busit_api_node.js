const jwt = require('jsonwebtoken')

//Verify Token
const Tokens_Verification = (req, res, next) =>{
    const token = req.body.token || req.query.token || req.headers['x-access-token']

    if(!token){
        return res.send({message:'ต้องมี Token สำหรับการตรวจสอบสิทธิ์', status: false});
    }
    try{
        const decode = jwt.verify(token ,process.env.PRIVATE_TOKEN_KEY);
        req.employee_decoded = decode;
    }catch(err){
        return res.send({message:'Token ไม่ถูกต้อง', status: false});
    }
    return next();
}

module.exports = Tokens_Verification;