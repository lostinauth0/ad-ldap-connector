const exec = require('child_process').exec;
const execAsync = require('util').promisify(exec);
const path = require('path');
const process = require('node:process');
const secureStorage = require('../lib/secureStorage');

/**
 * Restarts the Auth0 ADLDAP service on windows. On other platforms, it's a no-op.
 *
 * @param cb
 * @return {*}
 */
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

/**
 * Runs a command in a shell and calls the callback with the output.
 *
 * @param cmd
 * @param args
 * @param callback
 */
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

/**
 * Tries to detect LDAP settings on windows using the settings_detector.exe.
 *
 * Note: No idea what this executable is and where the source for it is.
 * TODO: figure out if we can just stop using this and require users to input LDAP settings manually
 *
 * @return {Promise<{LDAP_BASE?: string, LDAP_URL?: string}>}
 */
async function detectLdapSettings() {
  const detected = {};
  try {
    if (process.platform === 'win32') {
      const { stdout } = await execAsync('"' + __dirname + '//settings_detector.exe"');
      const parsed = JSON.parse(stdout);
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
