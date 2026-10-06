require('dotenv').config();

const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { connectDB } = require('./models/db');
const { verifySmtpConnection } = require('./utils/mailer');
const { findById: findUserById } = require('./models/User');
const { requireUserAuth, requireActiveUser } = require('./middleware/auth');

const { router: authRoutes } = require('./routes/auth');
const passwordRoutes = require('./routes/password');
const adminRoutes = require('./routes/admin');
const otpRoutes = require('./routes/otp');

const app = express();
const PORT = Number(process.env.PORT) || 3000;

const required = [
  'DATABASE_URL',
  'JWT_SECRET',
  'ADMIN_JWT_SECRET',
  'SETUP_JWT_SECRET',
  'TOTP_ENCRYPTION_KEY'
];

const missing = required.filter(key => !process.env[key]);
if (missing.length) {
  console.error(`Missing required .env values: ${missing.join(', ')}`);
  process.exit(1);
}

if (!/^[0-9a-fA-F]{64}$/.test(process.env.TOTP_ENCRYPTION_KEY)) {
  console.error('TOTP_ENCRYPTION_KEY must be exactly 64 hexadecimal characters.');
  process.exit(1);
}

app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/auth', authRoutes);
app.use('/api/password', passwordRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/otp', otpRoutes);

app.get('/api/protected/dashboard', requireUserAuth, requireActiveUser, (req, res) => {
  res.json({
    message: 'Welcome to your dashboard',
    fullName: req.currentUser.full_name,
    email: req.currentUser.email
  });
});

app.get('/', (req, res) => res.redirect('/login.html'));

async function start() {
  await connectDB();
  await verifySmtpConnection();

  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`User login:  http://localhost:${PORT}/login.html`);
    console.log(`Admin login: http://localhost:${PORT}/admin-login.html`);
  });
}

start().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
