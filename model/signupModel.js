const mongoose = require("mongoose");

const Schema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    role: { type: String, enum: ['ADMIN', 'NORMAL'], default: 'NORMAL' },
    profile: { type: String, default: 'default.jpg' },
    passwordResetToken: { type: String },
    passwordResetExpires: { type: Date },

});
module.exports = mongoose.model('User', Schema)


