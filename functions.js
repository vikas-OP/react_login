const mongodb = require("mongodb")
const bcrypt = require("bcryptjs")
const nodemailer = require("nodemailer")
const jwt = require("jsonwebtoken")
require("dotenv").config()



const mongoClient = mongodb.MongoClient
const URL = process.env.DATABASE_URL

async function connectToDB(cb){
    let client
    try{
        client = await mongoClient.connect(URL,{useNewUrlParser: true, useUnifiedTopology: true})
        const db = client.db("login")
        const result = await cb(db)
        client.close()
        return result
    }
    catch(err){
        if(client){
            client.close()
        }
        throw err
    }
}

async function isUserRegistered(email){
    const isUserPresent = await connectToDB(async (db) => {
        const user = await db.collection("users").findOne({email})
        if(user){
            return true
        }
        return false
    })
    return isUserPresent
}


async function registerUser(user){
    await connectToDB(async (db) => {
        await db.collection("users").insertOne(user)
    })
}

async function isValidUser(email, password){
    const hashPassword = await connectToDB(async (db) => {
        const user = await db.collection("users").findOne({email})
        return user.password
    })
    const result = await bcrypt.compare(password, hashPassword)
    return result
}

async function getUser(email){
    const user = await connectToDB(async (db) => {
        const user = await db.collection("users").findOne({email})
        return user
    })
    return user
}

function handleServerError(res){
    res.status(500).json({
        message: "something went wrong"
    })
}

function sendMail(email, randomString){
    const randomUrl =  `http://localhost:3000/reset-password/${randomString}`
    let transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: process.env.SENDER_EMAIL,
          pass: process.env.SENDER_PASSWORD,
        },
      });
      var mailOptions = {
        from: process.env.SENDER_EMAIL,
        to: `${email}`,
        subject: "Password reset using nodeJS",
        html: `<p>To reset your password for the account you created in vikas's password reset project please <a href = ${randomUrl}>click here</a> and enter the new password.
        </p>`,
      };

      transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
          throw err
        }
      });
}

async function storeActivationLink(email, randomString){
    await connectToDB(async (db) => {
        await db.collection("users").findOneAndUpdate({email}, {$set: {activationLink : randomString}})
    })
}

async function isValidLink(activationLink){
    const isValid = await connectToDB(async (db) => {
        const user = await db.collection("users").findOne({activationLink})
        if(user){
            return true
        }
        return false
    })
    return isValid
}

async function changePassword(password, activationLink){
    await connectToDB(async (db) => {
        await db.collection("users").findOneAndUpdate({activationLink}, {$set: {password}, $unset: {activationLink: 1}})
    })
}

function generateAccessToken(user){
    const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET)
    return accessToken
}

function verifyToken(req, res, next){
        const accessToken = req.headers["authorization"]
        jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET,(err, decode) => {
            if(err){
                res.status(403).json({
                    message: "invalid token"
                })
                return
            }
            req.body.user = decode
            next()
        })
    }


module.exports = {handleServerError, isUserRegistered, registerUser, isValidUser, getUser, sendMail, storeActivationLink, isValidLink, changePassword, generateAccessToken, verifyToken}