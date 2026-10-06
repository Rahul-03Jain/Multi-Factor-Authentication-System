const jwt = require('jsonwebtoken');

function signToken(payload, secret, expiresIn) {
  return jwt.sign(payload, secret, { expiresIn });
}

function verifyToken(token, secret, expectedType) {
  const payload = jwt.verify(token, secret);
  if (payload.type !== expectedType) throw new Error('Invalid token type.');
  return payload;
}

module.exports = { signToken, verifyToken };
