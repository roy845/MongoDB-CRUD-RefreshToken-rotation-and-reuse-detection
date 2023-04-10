const User = require('../model/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


module.exports = {
    handleLogin: async (req,res)=>{
        const cookies = req.cookies;
        const {user,pwd} = req.body;
        if(!user || !pwd)
            return res.status(401).json({'message':'Username and password are required'});
        
        const foundUser = await User.findOne({username:user}).exec();
        if(!foundUser)
            return res.status(401).json({'message':'Unauthorized'});

            const match = await bcrypt.compare(pwd,foundUser.password);
            if(match){
                const roles = Object.values(foundUser.roles);
                const accessToken = jwt.sign(
                    {"UserInfo":{"username":foundUser.username,"roles":roles}},
                    process.env.ACCESS_TOKEN_SECRET,
                    {expiresIn:'30s'}
                );

                const newRefreshToken = jwt.sign(
                    {"username":foundUser.username},
                    process.env.REFRESH_TOKEN_SECRET,
                    {expiresIn:'1d'}
                );

                let newRefreshTokenArray = !cookies?.jwt ? foundUser.refreshToken :
                foundUser.refreshToken.filter(rt=>rt!==cookies.jwt);
                
                if(cookies?.jwt){
                    const refreshToken = cookies.jwt;
                    const foundToken = await User.findOne({refreshToken}).exec();

                    if(!foundToken){
                        console.log('attempted refresh token reuse at login');
                        newRefreshTokenArray = [];
                    }
                    res.clearCookie('jwt',{httpOnly:true,sameSite:'None',secure:true});
                }
                
                foundUser.refreshToken = [...newRefreshTokenArray,newRefreshToken];
                const result = await foundUser.save();
                console.log(result);
                
                res.cookie('jwt',newRefreshToken,{httpOnly:true,secure:true,sameSite:'None',maxAge:24*60*60*1000});
                res.json({accessToken});
            }else{
                res.status(401).json({'message':'Unauthorized'});
            }
    }
};
