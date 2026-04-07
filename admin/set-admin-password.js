const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { validateToString } = require('./passwordStrength');

const password = process.env.AUTH0_ADMIN_SETUP_PASSWORD;
if (!password) {
  process.stdout.write('No password provided.\n');
  process.exit(0);
}

const validationError = validateToString(password);
if (validationError) {
  process.stdout.write(validationError + '\n');
  process.exit(0);
}

bcrypt.hash(password, 12, function (err, hash) {
  if (err) {
    process.stdout.write('Failed to hash password: ' + err.message + '\n');
    process.exit(0);
  }
  try {
    fs.writeFileSync(path.join(__dirname, '.pending-admin-password'), hash, 'utf8');
    process.stdout.write('\n');
  } catch (writeErr) {
    process.stdout.write('Failed to save password: ' + writeErr.message + '\n');
  }
});