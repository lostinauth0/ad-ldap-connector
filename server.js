var config = require('./lib/config');
require('colors');
require('./eventlog');
require('./lib/add_certs');
require('./lib/setupProxy');
const exit = require('./lib/exit');

function end () {
  console.log('Got SIGTERM, exiting now.');
  if (ws_client) {
    process.exiting = true;
    return ws_client.once('close', function () {
      exit(0);
    }).close();
  }
  exit(0);
}

process.on('uncaughtException', function(err) {
  console.error(err.stack);
}).once('SIGTERM', end)
  .once('SIGINT', end);


var ws_client;

var connectorSetup = require('./connector-setup');

let maxHeaderSize = Number(config.get('MAX_HEADER_SIZE'));
maxHeaderSize = maxHeaderSize > 0 ? maxHeaderSize : 16834;

console.log('');
console.log('');
console.log('');
console.log('======================== STARTING AD-LDAP CONNECTOR ========================');
console.log('Maximum header size = ' + maxHeaderSize);

connectorSetup.run(__dirname, async function(err) {
  if(err) {
    console.log(err.message);
    return exit(2);
  }

  if(!config.get('LDAP_URL')) {
    console.error('edit config.json and add your LDAP URL');
    return exit(1);
  }

  if (!config.get('ANONYMOUS_SEARCH_ENABLED') && !config.get('LDAP_BIND_USER')) {
    console.error('Anonymous LDAP search is not enabled. Please edit config.json to add LDAP_BIND_USER');
    return exit(1);
  }

  try {
    await require('./lib/ldap').initialize();
  } catch (e) {
    console.error(e.message);
    return exit(1);
  }

  require('./lib/clock_skew_detector');
  ws_client = require('./ws_validator');
  var latency_test = require('./latency_test');
  latency_test.run_many(10);

  if (!config.get('KERBEROS_AUTH') && !config.get('CLIENT_CERT_AUTH')) {
    return;
  }

  var express  = require('express');
  var bodyParser = require('body-parser');
  var cookieParser = require('cookie-parser');
  var logger = require('morgan');
  var passport = require('passport');

  require('./lib/setupPassport');

  var cookieSessions = require('cookie-sessions');
  var app = express();

  // configure the webserver
  app.set('view engine', 'ejs');
  app.set('views', __dirname + '/views');

  app.use(express.static(__dirname + '/public'));
  app.use(logger('combined'));
  if(config.get('KERBEROS_DEBUG_USER')) {
    app.use((req, res, next) => {
      req.headers['x-forwarded-user'] = config.get('KERBEROS_DEBUG_USER');
      next();
    });
  }
  app.use(cookieParser());
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({extended:true}));
  app.use(cookieSessions({
    name:    'auth0-ad-conn',
    secret:   config.get('SESSION_SECRET')}));

  app.use(passport.initialize());

  require('./endpoints').install(app);

  var options = {
    port: config.get('PORT'),
    test_user: config.get('KERBEROS_DEBUG_USER'),
    maxHeaderSize,
  };

  // client certificate-based authentication
  if (config.get('CLIENT_CERT_AUTH')) {
    console.log('Using client certificate-based authentication');

    // SSL settings
    options.ca = config.get('CA_CERT');
    options.pfx = Buffer.from(config.get('SSL_PFX'), 'base64');
    options.passphrase = config.get('SSL_KEY_PASSWORD');
    options.requestCert = true;

    if (!config.get('KERBEROS_AUTH')) {
      var https = require('https'); // use https server
      https.createServer(options, app).listen(options.port);
    }
  }

  // kerberos authentication
  if (config.get('KERBEROS_AUTH')) {
    console.log('Using kerberos authentication');

    if (process.platform === 'win32') {
      var KerberosServer = require('kerberos-server');
      var kerberosServer = new KerberosServer(app, options);
      kerberosServer.listen(options.port)
        .on('error', function (err) {
          console.error(err.message);
          return process.exit(1);
        });
    } else if (config.get('WITH_KERBEROS_PROXY_FRONTEND') || config.get('KERBEROS_DEBUG_USER')) {
      var http = require('http');
      http.createServer({ maxHeaderSize }, app).listen(options.port);
    } else {
      return console.log('Detected KERBEROS_AUTH in config, but this platform doesn\'t support it.');
    }

  }

  console.log('listening on port: ' + config.get('PORT'));
});
