const jwt = require('jsonwebtoken');
const secret = "Ilssrinagar12";

function setUser(user){
const token = jwt.sign({
    _id: user._id,
    username: user.username,
    role: user.role

},secret);
return token;
}

function getUser(token){
    return jwt.verify(token,secret);
}
exports.setUser = setUser;
exports.getUser = getUser;