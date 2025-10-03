const express = require('express');
const { handleUserSignup, handleUserLogin, handleForgotPassword, handleVerifyOTP, handleResetPassword, handleSignupValidateOTP } = require('../controller/signupController');
const router = express.Router();
const multer = require('multer');

const upload = multer({  storage: multer.memoryStorage(), limits: { fileSize: 100* 1024 } });


router.post('/createuser',upload.single('profile'), handleUserSignup);
router.post('/loginuser', handleUserLogin);
router.post('/forgotpassword',handleForgotPassword);
router.post('/verifyotp', handleVerifyOTP);
router.post('/resetpassword', handleResetPassword);
router.post('/signup/verify-otp', handleSignupValidateOTP);

module.exports = router;
