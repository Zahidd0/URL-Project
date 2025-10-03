const User = require("../model/signupModel"); // avoid naming conflict
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const { setUser } = require("../services/auth");
require('dotenv').config();
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");
const logger = require('../services/logger');
const e = require("express");
const { error } = require("console");


async function handleUserSignup(req, res) {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.render('Signup', { error: "Username or Email already exists" });
    }
    // console.log(req.file);
    if (!username || !email || !req.file || !password) {
      return res.render('Signup', { error: " All fields are required" });
    }
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true, // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
    let otp = genrateOTP();
    console.log(otp);
    await transporter.sendMail({
      from: process.env.EMAIL_USER, // sender address
      to: email,
      subject: "OTP for password Reset",
      text: `your otp is ${otp} please dont share it with anyone`, // plain‑text body

    });
    const salt = bcrypt.genSaltSync(10);
    hashedPassword = bcrypt.hashSync(req.body.password, salt);
    const hashedOtp = bcrypt.hashSync(otp, 10);
    fileBuffer = req.file.buffer.toString('base64');
    originalName = req.file.originalname;
    const authToken = jwt.sign({ username, email, password: hashedPassword, fileBuffer, originalName, hashedOtp }, process.env.JWT_SECRET, { expiresIn: "10m" });
    return res.render("signupValidateOtp.ejs", { authToken: authToken, error: null });
  }
  catch (error) {
    logger.error(`Error during user signup: ${error.message}`, { timestamp: new Date().toISOString() });
    return res.render('Signup', { error: "An error occurred during signup. Please try again later." });
  }
}


async function handleSignupValidateOTP(req, res) {
  try {
    const { authToken, otp } = req.body;
    // console.log(OTP)
    if (!otp || !authToken) {
      return res.render("signupValidateOtp.ejs", {
        authToken: authToken,
        error: "OTP and AuthToken are required"
      })
    }
    let decodeToken;
    try {
      decodeToken = jwt.verify(authToken, process.env.JWT_SECRET);
    } catch (err) {
      return res.render("signupValidateOtp.ejs", {
        authToken: authToken,
        error: "Invalid or expired token"
      })
    }


    const uploadDir = path.join(__dirname, '../uploads'); // replace 'myFolder' with your folder name

    // Check if folder exists
    if (!fs.existsSync(uploadDir)) {
      // Create folder if not exists
      fs.mkdirSync(uploadDir, { recursive: true });
      console.log('Folder created:', uploadDir);
    } else {
      console.log('Folder already exists:', uploadDir);
    }
    // console.log(decodeToken.fileBuffer);
    const isOtpValid = bcrypt.compareSync(otp, decodeToken.hashedOtp);
    if (!isOtpValid) {
      return res.render("signupValidateOtp.ejs", {
        authToken: authToken,
        error: "Invalid OTP"
      });
    }



    const filename = Date.now() + decodeToken.originalName;
    const filePath = path.join(uploadDir, filename);
    fs.writeFileSync(filePath, Buffer.from(decodeToken.fileBuffer, 'base64'));


    // OTP is valid, proceed with signup
    await User.create({
      username: decodeToken.username,
      email: decodeToken.email,
      password: decodeToken.password,
      profile: filename,
    });
    return res.render('login', { message: "Signup successful, please login", error: null });
  }
  catch (error) {
    logger.error(`Error during OTP validation: ${error.message}`, { timestamp: new Date().toISOString() });
    return res.render('signupValidateOtp.ejs', { authToken: req.body.authToken, error: "An error occurred during OTP validation. Please try again later." });
  }
}



async function handleUserLogin(req, res) {
  const { username, password } = req.body;
  // console.log(username, password);
  const user = await User.findOne({ username });

  if (!user || !bcrypt.compareSync(password, user.password))
    return res.render("login", {
      error: "Invalid Username or Password",
      message: null,
    });


  const token = setUser(user);
  res.cookie("uid", token);

  return res.redirect("/");
  // return res.json({token});
}

function genrateOTP() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}
async function handleForgotPassword(req, res) {
  const { email } = req.body;

  // console.log(email);
  if (!email) {
    return res.render("forgotpassword", {
      error: "Email is required"
    })
  }
  const user = await User.findOne({ email });

  if (!user) return res.render("forgotpassword", {
    error: "Invalid Email Address"
  });
  // console.log(user);
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true, // true for 465, false for other ports
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  let otp = genrateOTP();
  const passwordResetDate = Date.now() + 10 * 60 * 1000;
  user.passwordResetToken = otp;
  user.passwordResetExpires = passwordResetDate;
  await user.save();
  const info = await transporter.sendMail({
    from: process.env.EMAIL_USER, // sender address
    to: user.email,
    subject: "OTP for password Reset",
    text: `your otp is ${otp} please dont share it with anyone`, // plain‑text body

  });
  // console.log("Message sent: %s", info.messageId);
  return res.render("verifyotp", { email: user.email, error: null });

}

async function handleVerifyOTP(req, res) {
  const { email, otp } = req.body;
  // console.log(OTP)
  if (!otp || !email) {
    return res.render("verifyotp", {
      error: "OTP and Email are required",
      email: email,
    })
  }
  const user = await User.findOne({
    email,
    passwordResetToken: otp,
    passwordResetExpires: { $gt: Date.now() }
  });
  if (!user) {
    return res.render("verifyotp", {
      error: "Invalid OTP or OTP expired",
      email: email,
    })
  }
  const authToken = jwt.sign(
    { id: user._id },
    process.env.JWT_SECRET,
    { expiresIn: "10m" }
  )

  return res.render("resetpassword", { authToken: authToken, error: null });
}

async function handleResetPassword(req, res) {
  const { authToken, password, confirmPassword } = req.body;
  // console.log(password,confirmPassword);
  if (!password || !confirmPassword || !authToken) {
    return res.render("resetpassword", {
      error: "All fields are required",
      authToken: authToken,
    })

  }
  if (password !== confirmPassword) {
    return res.render("resetpassword", {
      error: "Passwords do not match",
      authToken: authToken,

    })
  }
  let decodeToken;
  try {
    decodeToken = jwt.verify(authToken, process.env.JWT_SECRET);
  } catch (err) {
    return res.render("resetpassword", {
      error: "Invalid or expired token",
      authToken: authToken,
    })
  }
  const user = await User.findOne({ _id: decodeToken.id });
  const salt = bcrypt.genSaltSync(10);
  user.password = bcrypt.hashSync(password, salt);
  await user.save();
  return res.render("/login", { message: "Password reset successful, please login", error: null });
}
module.exports = { handleUserSignup, handleUserLogin, handleForgotPassword, handleVerifyOTP, handleResetPassword, handleSignupValidateOTP };