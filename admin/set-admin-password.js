const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

/**
 * This script is used to set the password for the pending admin user.
 * It reads the password from the console arguments, hashes it,
 * and saves it to a file named `.pending-admin-password` in the same directory as this script.
 *
 * The pending password is then used by the admin console service on startup to save the hashed password to the keychain.
 *
 * If the console argument is not provided, the script exits without doing anything.
 */

const password = process.argv[2];
if (!password) {
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
