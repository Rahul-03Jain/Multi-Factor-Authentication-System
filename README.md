# MFA Authentication Web Application

A full-stack authentication project using **Node.js, Express, Neon PostgreSQL, Google Authenticator TOTP, JWT HTTP-only cookies, password recovery, separate administrator access, user enable/disable controls, and an audit trail**.

## Features

### User
- Registration with bcrypt password hashing
- Mandatory Google Authenticator MFA enrollment
- QR code generated from an `otpauth://` URI
- 6-digit TOTP verification
- JWT session stored in an HTTP-only cookie
- Account status checked on protected requests
- Forgot/reset password by email
- Login/logout/audit events

### Administrator
- Separate admin login
- Admin-only dashboard
- View registered users
- Enable/disable user accounts
- View login/logout and security activity
- Admin password reset
- Administrative actions are recorded in the audit trail

### Database
- Neon PostgreSQL
- Four tables: `users`, `admins`, `password_resets`, `audit_logs`
- TOTP secrets are encrypted before being stored

## Setup

### 1. Install dependencies

```bash
npm install
```

### 2. Create Neon database

Create a project in Neon and copy the PostgreSQL connection string from **Connect**.

Create `.env` from `.env.example` and set:

```env
DATABASE_URL=your_neon_connection_string
```

### 3. Generate application secrets

Run:

```bash
node scripts/generate-secret.js
```

Use the output for `TOTP_ENCRYPTION_KEY`.

Generate long random values for:

```env
JWT_SECRET=
ADMIN_JWT_SECRET=
SETUP_JWT_SECRET=
RESET_JWT_SECRET=
```

### 4. Create database tables

```bash
npm run db:init
```

### 5. Configure Gmail

Enable Google 2-Step Verification and create a Google App Password.

Set:

```env
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
EMAIL_FROM="MFA Auth <your-email@gmail.com>"
```

The SMTP test is:

```bash
npm run test:email
```

### 6. Create the first administrator

```bash
npm run create:admin
```

### 7. Start the app

```bash
npm start
```

Open:

- User login: `http://localhost:3000/login.html`
- Admin login: `http://localhost:3000/admin-login.html`

## User flow

```text
Sign Up
  -> QR code
  -> Scan with Google Authenticator
  -> Enter TOTP
  -> Dashboard

Later:
Login
  -> Password
  -> Google Authenticator code
  -> Dashboard
```

## Admin flow

```text
Admin Login
  -> Admin Dashboard
  -> View users
  -> Enable/disable users
  -> View audit trail
```

## Important

Never commit `.env`, database credentials, SMTP passwords, JWT secrets, or the TOTP encryption key to GitHub.
