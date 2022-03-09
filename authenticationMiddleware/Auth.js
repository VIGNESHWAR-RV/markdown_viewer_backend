import jwt from "jsonwebtoken";

export const user_Auth = (request,response,next)=>{
try{
    const token = request.header("token");
    jwt.verify(token,process.env.SECRET_KEY)
    // console.log("verified");
    next();
}
catch(err){
    console.log(err);
     response.status(400).send({message:"not a valid user",error:err.message});
}
}