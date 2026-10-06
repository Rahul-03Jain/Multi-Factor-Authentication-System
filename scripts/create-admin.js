require('dotenv').config();
const readline = require('readline');
const bcrypt = require('bcrypt');
const { connectDB, closeDB } = require('../models/db');
const { createAdmin } = require('../models/Admin');

function ask(rl, question, hidden = false) {
  if (!hidden) return new Promise(resolve => rl.question(question, resolve));
  return new Promise(resolve => {
    const stdin = process.stdin;
    const stdout = process.stdout;
    stdout.write(question);
    stdin.setRawMode?.(true);
    let value = '';
    const onData = char => {
      char = char.toString();
      if (char === '\r' || char === '\n') {
        stdin.setRawMode?.(false);
        stdin.off('data', onData);
        stdout.write('\n');
        resolve(value);
      } else if (char === '\u0003') {
        process.exit();
      } else if (char === '\u007f') {
        value = value.slice(0, -1);
      } else {
        value += char;
      }
    };
    stdin.on('data', onData);
  });
}

async function main() {
  await connectDB();
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const fullName = (await ask(rl, 'Admin full name: ')).trim();
  const email = (await ask(rl, 'Admin email: ')).trim().toLowerCase();
  const password = await ask(rl, 'Admin password (min 8 characters): ', true);

  rl.close();

  if (fullName.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8) {
    throw new Error('Invalid admin details.');
  }

  const hash = await bcrypt.hash(password, 12);
  const admin = await createAdmin({ fullName, email, passwordHash: hash });
  console.log(`Admin created: ${admin.email}`);
  await closeDB();
}

main().catch(async err => {
  console.error('[Admin] Could not create admin:', err.message);
  await closeDB().catch(() => {});
  process.exit(1);
});
