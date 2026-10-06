const crypto = require('crypto');

function getEncryptionKey() {
  const value = (process.env.TOTP_ENCRYPTION_KEY || '').trim();
  if (!/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error('TOTP_ENCRYPTION_KEY must be exactly 64 hexadecimal characters.');
  }
  return Buffer.from(value, 'hex');
}

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

function decrypt(payload) {
  const [ivHex, tagHex, encryptedHex] = String(payload || '').split(':');
  if (!ivHex || !tagHex || !encryptedHex) throw new Error('Invalid encrypted value.');
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    getEncryptionKey(),
    Buffer.from(ivHex, 'hex')
  );
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(encryptedHex, 'hex')),
    decipher.final()
  ]).toString('utf8');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function randomToken() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = { encrypt, decrypt, sha256, randomToken };
