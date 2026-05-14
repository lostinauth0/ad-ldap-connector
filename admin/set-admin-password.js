const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const execAsync = require('util').promisify(require('child_process').exec);
const process = require('node:process');
const filePermissions = require('../lib/filePermissions');

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

(async () => {
  try {
    const hash = await bcrypt.hash(password, 12);
    const filePath = path.join(__dirname, '.pending-admin-password');
    fs.writeFileSync(filePath, hash, 'utf8');
    await filePermissions.restrict({
      filePath,
      platform: process.platorm,
      execAsync
    });
  } catch (err) {
    process.stdout.write('Failed to save pending password: ' + err.message + '\n');
    process.exit(0);
  }
})();
