import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import cors from "cors";
import nodemailer from "nodemailer";
import {user_Auth} from "./authenticationMiddleware/Auth.js";


dotenv.config();

const app = express();

const port = process.env.PORT;
const MONGO_URL = process.env.MONGO_URL;

async function createConnection(){
   const client = new MongoClient(MONGO_URL);
   await client.connect();
   console.log("connected to DB");
   return client;
}
const client = await createConnection();

app.use(express.json()) //middle-ware
app.use(cors());




app.post("/login",async(request,response)=>{

  const login = request.body;

  
  
  const existingUser = await client.db("markdown_preview")
                                   .collection("users")
                                   .findOne({userName:login.userName});
  
  if(!existingUser){
      return response.status(400).send({message:"invalid credentials"});
  }

  const passwordMatch = await bcrypt.compare(login.password,existingUser.password);

  if(!passwordMatch){
       return response.status(400).send("invalid credentials");
  }

  const token = jwt.sign({id:existingUser._id},process.env.SECRET_KEY);
  return response.status(200).send({token,id:existingUser._id.toString()});
  
})

 app.post("/signup",async(request,response)=>{

    const signup = request.body;
      
      const existingUser = await client.db("markdown_preview")
                                       .collection("users")
                                       .findOne({userName:signup.userName});

      if(existingUser){
         return response.status(400).send({message:"userName already exist"});
    }

      
      const existingMail = await client.db("markdown_preview")
                                       .collection("users")
                                       .findOne({email:signup.email});

      if(existingMail){
         return response.status(400).send({message:"email already associated with an account"});
      }


  
    signup.password = await generateHashedPassword(signup.password);

    const registered = await client.db("markdown_preview")
                                    .collection("users")
                                    .insertOne(signup);

   return response.status(200).send(registered);
 })

 app.post("/forgot_Password",async(request,response)=>{

  const recoveryMail = request.body;

  const existingUserCheck = await client.db("markdown_preview")
                                        .collection("users")
                                        .findOne({email:recoveryMail.recoveryEmail});
  
  if(existingUserCheck){
     return await linkMailer(recoveryMail.recoveryEmail,existingUserCheck._id.toString(),response);
    //return response.send({message:"ready to sent mail"});
  }
  return response.status(400).send("No such account");

 });

app.post("/password_Reset/",async(request,response)=>{
    const id =  request.body;
    
    if(id._id && id.token){
       const existingUser = await client.db("markdown_preview")
                                        .collection("users")
                                        .findOne({_id:ObjectId(id._id),token:id.token});
       if(existingUser){
       return response.send("valid user");
       }
       return response.status(400).send("not a valid user");
    }
       return response.status(400).send("not a valid user");
})

app.put("/password_Reset/",async(request,response)=>{
  const id = request.body;

  if(id._id && id.newPassword){
    
    id.newPassword = await generateHashedPassword(id.newPassword);

    const updating = await client.db("markdown_preview")
                                    .collection("users")
                                    .updateOne({_id:ObjectId(id._id)},
                                               {
                                                $set:{password:id.newPassword},
                                                $unset:{token:""}
                                                });

    if(updating){
       return response.send({message:"password updated Successfully"});
    }
    return response.status(400).send({message:"Database busy"});
  }
    return response.status(400).send({message:"couldn't validate the password update"})
})

app.get("/users",user_Auth,async (request,response)=>{

  const id = request.header("id");
  
  const userData = await client.db("markdown_preview")
                               .collection("users")
                               .findOne({_id:ObjectId(id)});
  if(userData){
    return response.send({userData});
  }
  return response.status(400).send("no such user");
})

app.post("/users",user_Auth,async (request,response)=>{
  
  const id = request.header("id");
  
  const content = request.body;

  const saveTemplate = await client.db("markdown_preview")
                               .collection("users")
                               .updateOne({_id:ObjectId(id)},
                                          {$push:{templates:{name:content.name,content:content.content}}});
  if(saveTemplate){
    return response.send(saveTemplate);
  }
  return response.status(400).send("no such user");
})

app.post("/myPersonalMailBuddy",async(request,response)=>{
  
  try{
   const checkKey = request.header("key");

   const contactingPerson = request.body;

   if(checkKey === process.env.mailkey && contactingPerson){
      
    return await personalMailer(contactingPerson,response);
   }
  }catch(e){
    return response.status(500).message({message:"something went wrong"});
  }
})

app.listen(port , console.log("express listening to port",port));


async function personalMailer(contactingPerson,response){
  const transport = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        type: 'OAuth2',
        user: process.env.MAIL_ID,
        pass: process.env.MAIL_PASS,
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        refreshToken: process.env.TOKEN_URI
    }
  });

      let mailOptions = {
        from: '"RV`s PortFolio" <noreplycrmbyrv@gmail.com>',
        to: process.env.AdminEmail,
        subject: "This is a message from your PortFolio RV",
        html: `<b>Hey RV!!!</b>,<br/><br/> This is <b>${contactingPerson.name}</b><br/>
          My Email is <b>${contactingPerson.email}</b><br/>
          <p><b>Message</b> : ${contactingPerson.message}</p><br/>`};
      
      transport.sendMail(mailOptions,  async (error) => {
        if (error) {
          console.log(error);
            return response.status(400).send("email is not sent");
        }
        return response.send({
            message: "Verification link has been sent to your mail Successfully"});
  });
}

async function linkMailer(user_email,id,response) {
  const transport = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
          type: 'OAuth2',
          user: process.env.MAIL_ID,
          pass: process.env.MAIL_PASS,
          clientId: process.env.CLIENT_ID,
          clientSecret: process.env.CLIENT_SECRET,
          refreshToken: process.env.TOKEN_URI
      }
  });

  
  const verificationString = generateRandomString();

  const passwordResetPage = `https://markdown-viewer-by-rv.herokuapp.com/password_Reset/${id}&${verificationString}`;
  
 
  var mailOptions = {
      from: '"RV`s SECURITY TEAM" <noreplycrmbyrv@gmail.com>',
      to: user_email,
      subject: 'LINK FOR MAIL CONFIRMATION AND PASSWORD RESET',
      html: `<b>Dear MarkDown user</b>,<br/><br/> The verification link is given below.<br/><b>${passwordResetPage}</b><br/>
        <p>PLEASE KEEP YOUR PASSWORD SAFE AND SECURE !!!</p><br/>
      <img style="width:200px;height:200px;object-fit:contain;" src="https://www.puffin.com/imgs/img_secure_security.gif"></img>`
  };

  transport.sendMail(mailOptions,  async (error) => {
      if (error) {
        console.log(error);
          return response.status(400).send("email is not sent");
      }
      const addingToken = await client.db("markdown_preview")
                                      .collection("users")
                                      .updateOne({email:user_email},
                                                 {$set:{token:verificationString}});
      return response.send({addingToken,
          message: "Verification link has been sent to your mail Successfully"});
  });
}

async function generateHashedPassword(password){
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password,salt);
  return hashedPassword;
} 

function generateRandomString(){
  let string = "";
  const list = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  for(let i=0;i<10;i++){
    const index = Math.floor(Math.random()*list.length);
    if(list[index]){
      string += list[index];
    }
  }
  return string;
}
