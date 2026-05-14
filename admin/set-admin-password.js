const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const execAsync = require('util').promisify(require('child_process').exec);
const process = require('node:process');

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
    const commands = [
      '$sddl = \'D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)\'',
      `$acl = Get-Acl -Path '${filePath}'`,
      '$acl.SetSecurityDescriptorSddlForm($sddl)',
      `Set-Acl -Path '${filePath}' -AclObject $acl`
    ];
    await execAsync('powershell -Command "' + commands.join(';') + '"');
    process.stdout.write('\n');
  } catch (err) {
    process.stdout.write('Failed to save pending password: ' + err.message + '\n');
    process.exit(0);
  }
  // STOP DONATIONS!!!!
})();
