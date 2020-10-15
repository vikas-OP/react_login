const express = require("express")
const cors = require("cors")
const bcrypt = require("bcryptjs")
const crypto = require("crypto")
const {handleServerError, isUserRegistered, registerUser, isValidUser, getUser, sendMail, storeActivationLink, isValidLink, changePassword, generateAccessToken, verifyToken} = require("./functions")
require("dotenv").config()


const app = express()
const PORT = process.env.PORT || 5000



app.use(cors({
    origin: "*"
}))
app.use(express.json())


app.post("/signup", async (req, res) => {
    try{
        if(await isUserRegistered(req.body.email)){
            res.json({
                message:"user already registered"
            })
            return
        }
        const password = await bcrypt.hash(req.body.password, 10)
        const user = {
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            password
        }
        await registerUser(user)
        res.json({
            message: "user registered"
        })
    }
    catch(err){
        console.log(err)
        handleServerError(res)
    }
})


app.post("/login", async(req, res) => {
    try {
        if(await isUserRegistered(req.body.email)){
            if(await isValidUser(req.body.email, req.body.password)){
                let user = await getUser(req.body.email)
                const accessToken = generateAccessToken(user)
                res.json({
                    stat: "S",
                    accessToken
                })
                return
            }
            res.json({
                stat: "F",
                message: "wrong password"
            })
            return
        }
        res.json({
            stat: "F",
            message: "email not registered"
        })
    }
    catch(err){
        handleServerError(res)
    }
})


app.post("/forgot-password", async(req, res) => {
    try{
        if(!(await isUserRegistered(req.body.email))){
            res.json({
                stat: "F",
                message: "email not registered"
            })
            return 
        }
        const randomString = crypto.randomBytes(64).toString("hex")
        await storeActivationLink(req.body.email, randomString)
        sendMail(req.body.email, randomString)
        res.json({
            stat: "S",
            message: "activation link sent to mail"
        })
    }
    catch(err){
        console.log(err)
        handleServerError(res)
    }
})


app.post("/reset-password", async (req, res) => {
    try{
        if(await isValidLink(req.body.activationLink)){
            const hashPassword = await bcrypt.hash(req.body.password, 10)
            await changePassword(hashPassword, req.body.activationLink)
            res.json({
                stat: "M",
                message: "password changed"
            })
            return 
        }
        res.json({
            stat: "F",
            message: "invalid link"
        })
    }
    catch(err){
        handleServerError(res)
    }
})


app.get("/dashboard", verifyToken,  async (req, res) => {
    let user = req.body.user
    user = {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        id: user._id
    }
    res.json({
        stat:"S",
        user
    })
})


app.listen(PORT, () => console.log("server started"))





