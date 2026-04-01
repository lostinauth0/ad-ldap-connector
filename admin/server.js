require('../lib/initConf');
require('../lib/setupProxy');

const axios = require('axios');
const multer = require('multer');
const { Readable } = require('stream');
const memoryStorage = multer.memoryStorage();
const upload = multer({ memoryStorage });
const unzipper = require('unzipper');
const path = require('path');
const archiver = require('archiver');
const cas = require('../lib/add_certs');
const csrf = require('csurf');
const os = require('os');
const fs = require('fs');
const http = require('http');
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const xtend = require('xtend');
const urlJoin = require('url-join');
const exec = require('child_process').exec;
const app = express();
const freeport = require('freeport');
const test_config = require('./test_config');
const keychain = require('cross-keychain');
const bcrypt = require('bcryptjs');
const { PasswordPolicy } = require('password-sheriff');
const passwordPolicies = require('auth0-password-policies');

const BCRYPT_SALT_ROUNDS = 12;
const passwordPolicy = new PasswordPolicy(passwordPolicies.good);

var Users = require('../lib/users');

app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: 'sojo sut ed oterces le',
  })
);
const csrfProtection = csrf({ cookie: true });
var detected_settings = {};
var adminConfigured = false;

if (process.platform === 'win32') {
  exec(
    '"' + __dirname + '//settings_detector.exe"',
    function (err, stdout, stderr) {
      console.log(arguments);
      try {
        var parsed = JSON.parse(stdout);
        console.log(parsed);
        if (parsed.error) {
          parsed = {};
          return;
        }
        detected_settings.LDAP_BASE = parsed.baseDN;
        detected_settings.LDAP_URL = 'ldap://' + parsed.domainController;
      } catch (er) {}
    }
  );
}

function read_current_config() {
  var current_config = {};
  try {
    var content = fs.readFileSync(__dirname + '/../config.json', 'utf8');
    current_config = JSON.parse(content);
  } catch (err) {}
  return current_config;
}

function set_current_config(req, res, next) {
  req.current_config = read_current_config();
  next();
}

function restart_server(cb) {
  // required to test immediately after configuration
  require('../lib/initConf');
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

function checkPasswordRules(password) {
  return [
    { label: 'At least 8 characters',    passed: password.length >= 8 },
    { label: 'Lowercase letters (a-z)',   passed: /[a-z]/.test(password) },
    { label: 'Uppercase letters (A-Z)',   passed: /[A-Z]/.test(password) },
    { label: 'Numbers (0-9)',             passed: /[0-9]/.test(password) },
    { label: 'Special characters',        passed: /[^a-zA-Z0-9]/.test(password) },
  ];
}

function merge_config(req, res) {
  var new_config = xtend(req.current_config, req.body);
  fs.writeFileSync(
    __dirname + '/../config.json',
    JSON.stringify(new_config, null, 2)
  );

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
  const options = { shell: true };
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

function requireAuth(req, res, next) {
  if (!adminConfigured) return res.redirect('/setup');
  if (!req.session.authenticated) return res.redirect('/login');
  next();
}

app.get('/setup', csrfProtection, function (req, res) {
  if (adminConfigured) return res.redirect('/');
  res.render('setup', { csrfToken: req.csrfToken() });
});

app.post('/setup', csrfProtection, function (req, res) {
  if (adminConfigured) return res.redirect('/');
  var password = req.body.password;
  var confirm  = req.body.confirm;
  if (!password || !passwordPolicy.check(password)) {
    return res.render('setup', { csrfToken: req.csrfToken(), PASSWORD_ERRORS: checkPasswordRules(password || '') });
  }
  if (password !== confirm) {
    return res.render('setup', { csrfToken: req.csrfToken(), ERROR: 'Passwords do not match.' });
  }
  bcrypt.hash(password, BCRYPT_SALT_ROUNDS)
    .then(function (hash) {
      return keychain.setPassword('auth0-ad-ldap-connector', 'admin-password', hash);
    })
    .then(function () {
      adminConfigured = true;
      res.redirect('/login');
    })
    .catch(function (err) {
      res.render('setup', { csrfToken: req.csrfToken(), ERROR: err.message });
    });
});

app.get('/login', csrfProtection, function (req, res) {
  if (!adminConfigured) return res.redirect('/setup');
  if (req.session.authenticated) return res.redirect('/');
  res.render('login', { csrfToken: req.csrfToken() });
});

app.post('/login', csrfProtection, function (req, res) {
  if (!adminConfigured) return res.redirect('/setup');
  keychain.getPassword('auth0-ad-ldap-connector', 'admin-password')
    .then(function (hash) {
      if (!hash) throw new Error('Admin password not found in keychain.');
      return bcrypt.compare(req.body.password || '', hash);
    })
    .then(function (match) {
      if (!match) {
        return res.render('login', { csrfToken: req.csrfToken(), ERROR: 'Invalid password.' });
      }
      req.session.authenticated = true;
      res.redirect('/');
    })
    .catch(function (err) {
      res.render('login', { csrfToken: req.csrfToken(), ERROR: err.message });
    });
});

app.get('/logout', function (req, res) {
  req.session.destroy();
  res.redirect('/login');
});

app.use(requireAuth);

app.get('/', set_current_config, csrfProtection, function (req, res) {
  console.log(req.session.LDAP_RESULTS);
  res.render(
    'index',
    xtend(
      req.current_config,
      {
        SUCCESS: req.query && req.query.s === '1',
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
      console.log(req.session.LDAP_RESULTS);
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
    keychain.setPassword('auth0-ad-ldap-connector', 'ldap-bind-credentials', password)
      .then(function () {
        delete req.body.LDAP_BIND_PASSWORD;
        delete req.body.LDAP_BIND_CREDENTIALS;
        delete req.current_config.LDAP_BIND_CREDENTIALS;
        require('../lib/ldap').resetCredentials();
        next();
      })
      .catch(function (err) {
        res.render('index', xtend(req.current_config, req.body, { ERROR: err.message }));
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
  function (req, res, next) {
    if (!req.body.PROVISIONING_TICKET) {
      return res.render(
        'index',
        xtend(req.current_config, {
          ERROR:
            'The ticket url ' + req.body.PROVISIONING_TICKET + ' is not vaild.',
        })
      );
    }

    var info_url = urlJoin(req.body.PROVISIONING_TICKET, '/info');

    axios
      .get(info_url)
      .then((response) => {
        const body = response.data;
        if (!body || !body.adHub) {
          return res.render(
            'index',
            xtend(req.current_config, {
              ERROR: 'Wrong ticket url.',
            })
          );
        }

        req.body.AD_HUB = body.adHub;

        if (!detected_settings.LDAP_URL) {
          var adLdapSettings = require('../connector-setup/steps/ad-ldap-settings.js');
          adLdapSettings.discoverSettings(
            body.connectionDomain,
            function (config) {
              console.dir(config);
              detected_settings = config;
              next();
            }
          );
        } else {
          next();
        }
      })
      .catch((err) => {
        console.error(err);

        if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT' || err.code === 'ENOTFOUND') {
          console.error('Unable to reach auth0 at: ' + info_url);
          return res.render(
            'index',
            xtend(req.current_config, {
              ERROR:
                'Unable to connect to Auth0, verify internet connectivity.',
            })
          );
        }

        if (
          err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
          err.code === 'CERT_UNTRUSTED'
        ) {
          console.error(
            'The Auth0 certificate at ' + info_url + ' could not be validated',
            err
          );
          return res.render(
            'index',
            xtend(req.current_config, {
              ERROR:
                'The Auth0 server is using a certificate issued by an untrusted Certification Authority. Go to https://auth0.com/docs/connector/ca-certificates for instructions on how to install your certificate Authority. \n ' +
                err.message,
            })
          );
        }

        if (err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT') {
          console.error(
            'The Auth0 certificate at ' + info_url + ' could not be validated',
            err
          );
          return res.render(
            'index',
            xtend(req.current_config, {
              ERROR:
                'The Auth0 server is using a self-signed certificate. Go to https://auth0.com/docs/connector/ca-certificates for instructions on how to install your certificate. \n' +
                err.message,
            })
          );
        }

        if (!err.response || err.response.status !== 200) {
          return res.render(
            'index',
            xtend(req.current_config, {
              ERROR: 'Wrong ticket url.',
            })
          );
        }

        return res.render(
          'index',
          xtend(req.current_config, {
            ERROR: 'Network error: ' + err.message,
          })
        );
      });
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
    zlib: { level: 9 }, // Sets the compression level.
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
    archive.file(fullPath, { name });
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
          res.render(
            'index',
            xtend(read_current_config(), {
              SUCCESS: true,
            })
          );
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
      zlib: { level: 9 }, // Sets the compression level.
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
      archive.file(fullPath, { name });
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

app.post('/password', set_current_config, csrfProtection, function (req, res) {
  var current = req.body.current_password  || '';
  var newPass  = req.body.new_password     || '';
  var confirm  = req.body.confirm_password || '';

  function renderError(msg) {
    res.render('index', xtend(req.current_config, {
      csrfToken: req.csrfToken(),
      ERROR: msg,
    }));
  }

  if (!passwordPolicy.check(newPass)) {
    return res.render('index', xtend(req.current_config, {
      csrfToken: req.csrfToken(),
      PASSWORD_ERRORS: checkPasswordRules(newPass),
    }));
  }
  if (newPass !== confirm) {
    return renderError('Passwords do not match.');
  }

  keychain.getPassword('auth0-ad-ldap-connector', 'admin-password')
    .then(function (hash) {
      if (!hash) throw new Error('Admin password not found in keychain.');
      return bcrypt.compare(current, hash);
    })
    .then(function (match) {
      if (!match) throw new Error('Current password is incorrect.');
      return bcrypt.hash(newPass, BCRYPT_SALT_ROUNDS);
    })
    .then(function (hash) {
      return keychain.setPassword('auth0-ad-ldap-connector', 'admin-password', hash);
    })
    .then(function () {
      res.redirect('/?s=1');
    })
    .catch(function (err) {
      renderError(err.message);
    });
});

cas.inject(function (err) {
  if (err) console.log('Custom CA certificates were not loaded', err);

  require('../lib/ldap').initialize()
    .catch(function (err) {
      console.warn('Could not migrate LDAP credentials at startup:', err.message);
    });

  keychain.getPassword('auth0-ad-ldap-connector', 'admin-password')
    .then(function (hash) {
      adminConfigured = (hash !== null);
      http.createServer(app).listen(8357, '127.0.0.1', function () {
        console.log('Listening on http://localhost:8357.');
      });
    })
    .catch(function (err) {
      console.error('Failed to check admin keychain:', err.message);
      http.createServer(app).listen(8357, '127.0.0.1', function () {
        console.log('Listening on http://localhost:8357.');
      });
    });
});
