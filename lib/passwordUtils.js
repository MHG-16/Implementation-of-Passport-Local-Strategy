const crypto = require('crypto');


function validPassword(password, hash, salt) {
    const hashVerify = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return hash === hashVerify
}

function genPassword(password) {
    let salt = crypto.randomBytes(32).toString('hex');
    let genHash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');

    return {
        salt,
        hash: genHash
    }
}

module.exports.validPassword = validPassword;
module.exports.genPassword = genPassword;