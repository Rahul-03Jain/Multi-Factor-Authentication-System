require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const { verifySmtpConnection, isSmtpConfigured } = require('../utils/mailer');

async function main() {
  if (!isSmtpConfigured()) {
    console.error('SMTP not configured. Set SMTP_USER, SMTP_PASS and SMTP_HOST in .env');
    process.exit(1);
  }
  console.log(`Testing SMTP as ${(process.env.SMTP_USER || '').trim()}`);
  const ok = await verifySmtpConnection();
  process.exit(ok ? 0 : 1);
}

main();
