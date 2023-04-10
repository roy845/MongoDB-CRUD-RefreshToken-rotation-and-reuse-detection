const User = require('../model/User');
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;

module.exports = {
    handleNewUser:async (req,res)=>{
        const {user,pwd} = req.body;
        if(!user || !pwd)
            return res.status(400).json({'message':'Username and password are required'});
        
        const duplicate = await User.findOne({username:user}).exec();
        
        if(duplicate)
            return res.status(409).json({'message':'User already exists'});
        
            try{
                const hashedPwd = await bcrypt.hash(pwd,SALT_ROUNDS);
                const result = await User.create ({
                    "username":user,
                    "password":hashedPwd
                });

                
                console.log(result);

                res.status(201).json({'success':`New user ${user} created`});
            }catch(err){
                return res.status(500).json({'message':err.message});
            }
    }
};

