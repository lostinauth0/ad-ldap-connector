const config = require('../lib/config');
require('../lib/setupProxy');

const multer = require('multer');
const {Readable} = require('stream');
const memoryStorage = multer.memoryStorage();
const upload = multer({memoryStorage});
const unzipper = require('unzipper');
const path = require('path');
const archiver = require('archiver');
const cas = require('../lib/add_certs');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const os = require('os');
const fs = require('fs');
const http = require('http');
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const xtend = require('xtend');
const exec = require('child_process').exec;
const app = express();
const freeport = require('freeport');
const test_config = require('./test_config');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const passwordStrength = require('./passwordStrength');
const ldap = require('../lib/ldap');
const secureStorage = require('../lib/secureStorage');
const certificates = require('../lib/certificates');
const { loadProvisioningTicket } = require('../lib/provisioningTicket');
const adLdapSettings = require('../lib/adLdapSettings');

const BCRYPT_SALT_ROUNDS = 12;
const SERVER_PORT = 8357;

const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts. Please try again later.',
});

var Users = require('../lib/users');
const {requireAdminPasswordSet, requireAuth, getHashedAdminPassword} = require('./middleware');

const csrfProtection = csrf({cookie: true});
var detected_settings = {};

function set_current_config(req, res, next) {
  req.current_config = config.getAll();
  next();
}

function restart_server(cb) {
  // required to test immediately after configuration
  require('../lib/config');
  Users = require('../lib/users');

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

async function merge_config(req, res) {
  var newConfig = xtend(req.current_config, req.body);
  for(const key of Object.keys(newConfig)) {
    config.set(key, newConfig[key]);
  }
  await config.save();

  if (req.body.LDAP_URL || req.body.PORT || req.body.SERVER_URL) {
    return restart_server(function () {
      return res.redirect('/?s=1');
    });
  }

  res.redirect('/');
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
  if (process.platform === 'win32') {
    return new Promise((resolve, reject) => {
      exec(
        '"' + __dirname + '//settings_detector.exe"',
        function (err, stdout, stderr) {
          try {
            const parsed = JSON.parse(stdout);
            console.log(parsed);
            if (!parsed.error) {
              detected_settings.LDAP_BASE = parsed.baseDN;
              detected_settings.LDAP_URL = 'ldap://' + parsed.domainController;
            }
          } catch (ex) {
            // don't care
          } finally {
            resolve();
          }
        }
      );
    });
  }
}

async function registerRoutes(app) {
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  app.use(express.static(__dirname + '/public'));
  app.use(cookieParser());
  app.use(bodyParser.urlencoded({extended: true}));

  let sessionSecret = await secureStorage.get(secureStorage.keys.ADMIN_CONSOLE_SESSION_SECRET);
  if (!sessionSecret) {
    sessionSecret = crypto.randomBytes(32).toString('hex');
    await secureStorage.store(secureStorage.keys.ADMIN_CONSOLE_SESSION_SECRET, sessionSecret);
  }
  app.use(
    session({
      secret: sessionSecret,
      saveUninitialized: false,
      resave: false,
      cookie: {
        maxAge: 8 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'strict',
      },
    })
  );

  app.get('/setup', csrfProtection, async function (req, res) {
    if (await getHashedAdminPassword()) {
      return res.redirect('/');
    }
    res.render('setup', {csrfToken: req.csrfToken()});
  });

  app.get('/login', csrfProtection, requireAdminPasswordSet, function (req, res) {
    if (req.session.authenticated) {
      return res.redirect('/');
    }
    res.render('login', {csrfToken: req.csrfToken()});
  });

  app.post('/login', loginRateLimit, csrfProtection, requireAdminPasswordSet, async function (req, res) {
    try {
      const hashedAdminPassword = await getHashedAdminPassword();
      if (!hashedAdminPassword) {
        throw new Error('Admin password not found in keychain.');
      }
      const match = await bcrypt.compare(req.body.password || '', hashedAdminPassword);
      if (!match) {
        return res.render('login', {csrfToken: req.csrfToken(), ERROR: 'Invalid password.'});
      }
      req.session.authenticated = true;
      res.redirect('/');
    } catch (err) {
      res.render('login', {csrfToken: req.csrfToken(), ERROR: 'Incorrect admin password.'});
    }
  });

  app.get('/logout', function (req, res) {
    req.session.destroy((err) => {
      if (err) {
        console.error(err);
      }
      res.redirect('/login');
    });
  });

  app.use(requireAdminPasswordSet);
  app.use(requireAuth);

  app.get('/', set_current_config, csrfProtection, function (req, res) {
    res.render(
      'index',
      xtend(
        req.current_config,
        {
          SUCCESS: req.query && req.query.s === '1',
          ERROR: req.query.error,
          LDAP_RESULTS: req.session.LDAP_RESULTS,
        },
        {
          detected: detected_settings,
        },
        {
          csrfToken: req.csrfToken(),
        }
      )
    );
    delete req.session.LDAP_RESULTS;
  });

  app.post(
    '/ldap',
    set_current_config,
    csrfProtection,
    function (req, res, next) {
      // Convert ENABLE_WRITE_BACK and ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD to boolean.
      req.body.ENABLE_WRITE_BACK = !!(
        req.body.ENABLE_WRITE_BACK && req.body.ENABLE_WRITE_BACK === 'on'
      );
      req.body.ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD = !!(
        req.body.ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD &&
        req.body.ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD === 'on'
      );

      var config = xtend({}, req.current_config, req.body);
      test_config(config, function (err, result) {
        if (err) {
          return res.render(
            'index',
            xtend(req.current_config, req.body, {
              ERROR: err.message,
              LDAP_RESULTS: result,
            })
          );
        }
        req.session.LDAP_RESULTS = result;
        next();
      });
    },
    function (req, res, next) {
      if (req.body.PORT || req.current_config.PORT) return next();
      freeport(function (er, port) {
        req.body.PORT = port;
        next();
      });
    },
    function (req, res, next) {
      var password = req.body.LDAP_BIND_PASSWORD;
      if (!password) return next();
      secureStorage.store(secureStorage.keys.LDAP_BIND_PASSWORD, password)
        .then(function () {
          ldap.resetCredentials();
          next();
        })
        .catch(function (err) {
          res.render('index', xtend(req.current_config, req.body, {ERROR: err.message}));
        });
    },
    merge_config
  );

  app.post(
    '/server',
    upload.single('SSL_PFX'),
    set_current_config,
    csrfProtection,
    function (req, res, next) {
      if (req.body.PORT || req.current_config.PORT) return next();
      freeport(function (er, port) {
        req.body.PORT = port;
        next();
      });
    },
    function (req, res, next) {
      if (!req.file || req.file.buffer.length === 0)
        return next();
      // upload pfx
      req.body.SSL_PFX = req.file.buffer.toString('base64');
      next();
    },
    merge_config
  );

  app.post(
    '/ticket',
    set_current_config,
    csrfProtection,
    async function (req, res, next) {
      if (!req.body.PROVISIONING_TICKET) {
        return res.redirect('/?error=' + encodeURIComponent('Provisioning ticket URL is required.'));
      }

      const provisioningTicket = req.body.PROVISIONING_TICKET;
      try {
        const ticketInfo = await loadProvisioningTicket(provisioningTicket);
        req.body.AD_HUB = ticketInfo.adHub;

        if (!detected_settings.LDAP_URL) {
          const discoveredSettings = await adLdapSettings.discoverSettings(ticketInfo.connectionDomain);
          console.dir(discoveredSettings);
          detected_settings = discoveredSettings;
        }
        next();

      } catch (err) {
        return res.redirect(`/?error=${encodeURIComponent(err.message)}`);
      }
    },
    merge_config
  );

  app.get('/export', set_current_config, function (req, res) {
    console.log('Exporting configuration.');

    var today = new Date()
      .toISOString()
      .substring(0, 19)
      .replace(/\:|\-/g, '')
      .replace('T', '-');

    var archive = archiver('zip', {
      zlib: {level: 9}, // Sets the compression level.
    });

    const files = [
      'config.json',
      'lib/profileMapper.js',
      'certs/cert.key',
      'certs/cert.pem',
    ];

    files.forEach((name) => {
      const fullPath = path.join(__dirname, '/../', name);
      if (!fs.existsSync(fullPath)) {
        return;
      }
      archive.file(fullPath, {name});
    });

    res.set('Content-Type', 'application/zip');
    res.set(
      'Content-Disposition',
      'attachment; filename=connector_export_' + today + '.zip'
    );
    archive.pipe(res);
    archive.finalize();
  });

  app.post(
    '/import',
    set_current_config,
    csrfProtection,
    upload.single('IMPORT_FILE'),
    function (req, res, next) {
      console.log('Importing configuration.');

      if (
        !req.file ||
        req.file.buffer.length === 0
      ) {
        return res.render(
          'index',
          xtend(req.current_config, {
            ERROR: 'Upload a valid zip file.',
          })
        );
      }

      var valid_files = [
        'certs/cert.key',
        'certs/cert.pem',
        'config.json',
        'lib/profileMapper.js',
      ];

      Readable.from(req.file.buffer)
        .pipe(unzipper.Parse())
        .on('entry', (entry) => {
          if (!valid_files.includes(entry.path)) {
            console.error(`unknown filepath ${entry.path}`);
            return entry.autodrain();
          }
          const filePath = path.join(__dirname, '/../', entry.path);
          console.log('Extracting ' + filePath);
          const fileWriteStream = fs.createWriteStream(filePath);
          entry.pipe(fileWriteStream);
        })
        .on('close', function () {
          restart_server(function () {
            res.redirect('/');
          });
        }).on('error', err => {
          console.error(err);
          return res.render(
            'index',
            xtend(req.current_config, {
              ERROR: 'Upload a valid zip file.',
            })
          );
        });
    }
  );

  app.get('/logs', function (req, res) {
    res.writeHead(200, {
      'Content-Type': 'text/plain',
    });

    if (!fs.existsSync(__dirname + '/../logs.log')) {
      res.write('The log file is empty.');
      return res.end();
    }

    fs.readFile(__dirname + '/../logs.log', 'utf8', function (err, data) {
      if (err) {
        res.status(500);
        res.send({
          error: err,
        });
      } else {
        res.write(data);
        res.end();
      }
    });
  });

  app.post('/logs/clear', csrfProtection, function (req, res) {
    fs.writeFile(__dirname + '/../logs.log', '', function (err) {
      if (err) {
        res.status(500);
        res.send({
          error: err,
        });
      } else {
        res.status(200);
        res.end();
      }
    });
  });

  app.get('/profile-mapper', function (req, res) {
    res.writeHead(200, {
      'Content-Type': 'text/plain',
    });

    if (!fs.existsSync(__dirname + '/../lib/profileMapper.js')) {
      res.write('');
      return res.end();
    }

    fs.readFile(
      __dirname + '/../lib/profileMapper.js',
      'utf8',
      function (err, data) {
        if (err) {
          res.status(500);
          res.send({
            error: err,
          });
        } else {
          res.write(data);
          res.end();
        }
      }
    );
  });

  app.post('/profile-mapper', csrfProtection, function (req, res) {
    fs.writeFile(
      __dirname + '/../lib/profileMapper.js',
      req.body.code,
      function (err) {
        if (err) {
          res.status(500);
          res.send({
            error: err,
          });
        } else {
          return restart_server(function () {
            res.status(200);
            res.end();
          });
        }
      }
    );
  });

  app.get('/troubleshooter/run', set_current_config, function (req, res) {
    run('node', [__dirname + '/../troubleshoot.js'], function (data) {
      data = data.replace(/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]/g, '').trim();

      res.writeHead(200, {
        'Content-Type': 'text/plain',
      });
      res.write(data);
      return res.end();
    });
  });

  app.get(
    '/troubleshooter/export',
    set_current_config,
    function (req, res, next) {
      console.log('Exporting test results.');

      run(process.execPath, [__dirname + '/../troubleshoot.js'], function (data) {
        data = data.replace(/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]/g, '').trim();

        req.body.TEST_RESULTS = data;
        return next();
      });
    },
    function (req, res, next) {
      console.log('Exporting files.');

      fs.readdir(__dirname + '/../', function (err, list) {
        if (err) {
          res.status(500);
          return res.send({
            error: err,
          });
        } else {
          req.body.LOG_FILES = [];
          list.forEach(function (item) {
            if (item.indexOf('.log') >= 0) {
              req.body.LOG_FILES.push(item);
            }
          });
          return next();
        }
      });
    },
    function (req, res, next) {
      var today = new Date()
        .toISOString()
        .substring(0, 19)
        .replace(/\:|\-/g, '')
        .replace('T', '-');

      var archive = archiver('zip', {
        zlib: {level: 9}, // Sets the compression level.
      });

      const files = [
        'config.json',
        'lib/profileMapper.js',
        'package.json',
      ].concat(req.body.LOG_FILES);

      files.forEach((name) => {
        const fullPath = path.join(__dirname, '/../', name);
        if (!fs.existsSync(fullPath)) {
          return;
        }
        archive.file(fullPath, {name});
      });

      archive.append(req.body.TEST_RESULTS, {
        name: 'test-results.log',
      });

      res.set('Content-Type', 'application/zip');
      res.set(
        'Content-Disposition',
        'attachment; filename=connector_troubleshoot_' + today + '.zip'
      );
      archive.pipe(res);
      archive.finalize();
    }
  );

  app.post(
    '/updater/run',
    csrfProtection,
    set_current_config,
    function (req, res) {
      run(__dirname + '/../update-connector.cmd', [], function (data) {
        res.writeHead(200, {
          'Content-Type': 'text/plain',
        });
        res.write(data);
        return res.end();
      });
    }
  );

  app.get('/updater/logs', function (req, res) {
    res.writeHead(200, {
      'Content-Type': 'text/plain',
    });

    if (!fs.existsSync(os.tmpdir() + '/adldap-update.log')) {
      res.write('');
      return res.end();
    }

    fs.readFile(os.tmpdir() + '/adldap-update.log', 'utf8', function (err, data) {
      if (err) {
        res.status(500);
        res.send({
          error: err,
        });
      } else {
        res.write(data.replace(/\n\r\n/g, '\n'));
        res.end();
      }
    });
  });

  app.get('/version', function (req, res) {
    var p = JSON.parse(fs.readFileSync(__dirname + '/../package.json', 'utf8'));

    res.writeHead(200, {
      'Content-Type': 'text/plain',
    });
    res.write(p.version);
    return res.end();
  });

  app.get('/users/search', function (req, res) {
    var users = new Users(true);
    users.list(req.query.query, {}, function (err, users) {
      if (err) {
        res.status(500);
        res.send({
          error: err,
        });
      } else {
        res.json(users);
      }
    });
  });

  app.get('/users/by-login', function (req, res) {
    var users = new Users(true);
    users.getByUserName(req.query.query, {}, function (err, users) {
      if (err) {
        res.status(500);
        res.send({
          error: err,
        });
      } else {
        res.send(users);
      }
    });
  });

  app.post('/password', set_current_config, csrfProtection, async function (req, res) {
    const currentPassword = req.body.current_password || '';
    const newPassword = req.body.new_password || '';
    const newPasswordConfirm = req.body.confirm_password || '';

    function renderError(msg) {
      res.redirect('/#security?error=' + encodeURIComponent(msg));
    }

    if (!passwordStrength.validate(newPassword)) {
      return renderError(passwordStrength.validateToString(newPassword));
    }

    if (newPassword !== newPasswordConfirm) {
      return renderError('Passwords do not match.');
    }

    try {
      const hashedPassword = await getHashedAdminPassword();
      const match = await bcrypt.compare(currentPassword, hashedPassword || '');
      if (!match) {
        return renderError('Current password is incorrect.');
      }
      const hashedNewPassword = await bcrypt.hash(newPassword, BCRYPT_SALT_ROUNDS);
      await secureStorage.store(secureStorage.keys.ADMIN_CONSOLE_PASSWORD, hashedNewPassword);
      res.redirect('/?s=1');
    } catch (err) {
      console.error(err);
      return renderError('An error occurred while changing the password.');
    }
  });
}

async function consumePendingAdminPassword() {
  const pendingPasswordPath = path.join(__dirname, '.pending-admin-password');
  const setAdminPasswordScriptPath = path.join(__dirname, 'set-admin-password.js');
  if (fs.existsSync(pendingPasswordPath)) {
    try {
      const pendingHash = fs.readFileSync(pendingPasswordPath, 'utf8').trim();
      if (pendingHash) {
        await secureStorage.store(secureStorage.keys.ADMIN_CONSOLE_PASSWORD, pendingHash);
        console.log('Admin password set from installer.');
      }
    } catch (err) {
      console.error('Failed to process pending admin password:', err.message);
    } finally {
      try {
        fs.unlinkSync(pendingPasswordPath);
        fs.unlinkSync(setAdminPasswordScriptPath);
      } catch (_) { /* empty */ }
    }
  }
}

async function runServer() {
  http.createServer(app).listen(SERVER_PORT, '127.0.0.1', function () {
    console.log('Listening on http://localhost:8357.');
  });
}

module.exports = app;

(async function adminConsole() {
  await config.initialize();
  await certificates.initialize();
  await detectLdapSettings();
  await registerRoutes(app);
  await ldap.initialize();
  await config.save();
  await consumePendingAdminPassword();
  await cas.injectAsync();
  await runServer();
})();
