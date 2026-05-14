const execAsync = require('util').promisify(require('child_process').exec);
const path = require('path');
const process = require('node:process');
const secureStorage = require('../lib/secureStorage');

function restartServer(cb) {
  if (process.platform === 'win32') {
    console.log('Restarting Auth0 ADLDAP Service...');
    return exec('net stop "Auth0 ADLDAP"', function () {
      exec('net start "Auth0 ADLDAP"', function () {
        console.log('Done.');
        setTimeout(function () {
          return cb();
        }, 2000);
      });
    });
  }

  cb();
}

function run(cmd, args, callback) {
  const spawn = require('child_process').spawn;
  const dir = path.dirname(cmd);
  const processName = path.basename(cmd);
  const options = {shell: true};
  if (dir !== '.') {
    options.cwd = dir;
  }
  const command = spawn(processName, args, options);
  let result = '';
  command.stderr.on('data', function (data) {
    result += data.toString();
  });
  command.stdout.on('data', function (data) {
    result += data.toString();
  });
  command.on('close', function (code) {
    return callback(result);
  });
}

async function detectLdapSettings() {
  const detected = {};
  try {
    if (process.platform === 'win32') {
      const output = await execAsync('"' + __dirname + '//settings_detector.exe"');
      const parsed = JSON.parse(output);
      console.log(parsed);
      if (!parsed.error) {
        detected.LDAP_BASE = parsed.baseDN;
        detected.LDAP_URL = 'ldap://' + parsed.domainController;
      }
    }
  } catch (err) {
    // don't care
  }
  return detected;
}

/**
 * Gets the hashed admin password from the keychain. If it doesn't exist, or is empty, returns null.
 * @return {Promise<null|string>}
 */
async function getHashedAdminPassword() {
  try {
    const hashedPassword = await secureStorage.get(secureStorage.keys.ADMIN_CONSOLE_PASSWORD);
    if (!hashedPassword) {
      return null;
    }
    return hashedPassword;
  } catch {
    return null;
  }
}

function redirectWithError({
  res,
  url = '',
  errorMessage,
  anchor
}) {
  res.redirect(`/${url}?error=${encodeURIComponent(errorMessage)}${(anchor ? '#' + anchor : '')}`);
}

module.exports = {
  restartServer,
  run,
  detectLdapSettings,
  getHashedAdminPassword,
  redirectWithError
};
