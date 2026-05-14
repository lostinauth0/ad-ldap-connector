const exec = require('child_process').exec;
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
  if (process.platform === 'win32') {
    return new Promise((resolve, reject) => {
      exec(
        '"' + __dirname + '//settings_detector.exe"',
        function (err, stdout, stderr) {
          try {
            const parsed = JSON.parse(stdout);
            console.log(parsed);
            if (!parsed.error) {
              detected.LDAP_BASE = parsed.baseDN;
              detected.LDAP_URL = 'ldap://' + parsed.domainController;
            }
          } catch (ex) {
            // don't care
          } finally {
            resolve(detected);
          }
        }
      );
    });
  }
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
