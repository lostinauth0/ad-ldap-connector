var nconf = require('nconf');
var ldap  = require('ldapjs');
var exit  = require('./exit');
var client, binder;
var crypto = require('./crypto');
var cb = require('cb');
var https = require('https');
const dns = require('dns');
const keychain = require('cross-keychain');

const KEYCHAIN_SERVICE = 'auth0-ad-ldap-connector';
const KEYCHAIN_ACCOUNT = 'ldap-bind-credentials';

let ldapBindCredentials;

// heartbeat related consts
const HEARTHBEAT_QUERY_TIMEOUT_MS = 5000;
const HEARTBEAT_DELAY_MS = nconf.get('LDAP_HEARTBEAT_SECONDS') * 1000;

function createConnection () {
  // Resolve using IPv4 first. This lets us continue to use localhost
  // Needed for Node 17+. See: https://github.com/node-fetch/node-fetch/issues/1624#issuecomment-1407717012
  if(dns.setDefaultResultOrder) {
    dns.setDefaultResultOrder('ipv4first');
  }

  var clientOpts = {
    url: nconf.get("LDAP_URL")
  };

  if (nconf.get('LDAP_URL').toLowerCase().substr(0, 5) === 'ldaps') {
    clientOpts.tlsOptions = { ca: https.globalAgent.options.ca };
  }

  return ldap.createClient(clientOpts);
}

function initializeConnection () {
  var connection = createConnection();

  connection.on('close', function () {
    console.error('Connection to ldap was closed.');
    exit(1);
  });

  connection.heartbeat = function (callback) {
    // alway re-bind the connection in an heartbeat before searching, underlying connection might be bound to a different users from previous
    // login validations, and the search query might fail randomly otherwise.
    const user = nconf.get('ANONYMOUS_SEARCH_ENABLED') ? '' : nconf.get("LDAP_BIND_USER");
    const creds = nconf.get('ANONYMOUS_SEARCH_ENABLED') ? '' : ldapBindCredentials;
    
    connection.bind(user, creds, function(err) {
      if(err){
        console.error("Heartbeat: Error binding to LDAP", 'dn: ' + err.dn + '\n code: ' + err.code + '\n message: ' + err.message);
        return callback(err);
      }
      
      connection.search(nconf.get('LDAP_BASE'), nconf.get('LDAP_HEARTBEAT_SEARCH_QUERY'), function (err, res) {
        if (err) {
          return callback(err);
        }
  
        var abort = setTimeout(function () {
          client.removeAllListeners('end');
          client.removeAllListeners('error');
          callback(new Error(`No heartbeat response within allocated timeout of ${HEARTHBEAT_QUERY_TIMEOUT_MS} ms`));
        }, HEARTHBEAT_QUERY_TIMEOUT_MS);
  
        res.once('error', function(err) {
          client.removeAllListeners('end');
          clearTimeout(abort);
          callback(err);
        }).once('end', function () {
          client.removeAllListeners('error');
          clearTimeout(abort);
          callback();
        });
      });
    });
  };

  function protect_with_timeout (func) {
    var original = connection[func];
    connection[func] = function () {
      var args = [].slice.call(arguments);
      var original_callback = args.pop();
      var timeoutable_callback = cb(original_callback).timeout(450000);
      var new_args = args.concat([timeoutable_callback]);
      return original.apply(this, new_args);
    };
  }
  protect_with_timeout('bind');
  protect_with_timeout('search');

  function ping_recurse () {
    connection.heartbeat(function (err) {
      if (err) {
        console.error('Error on heartbeat response from LDAP: ', err.message);
        return exit(1);
      }
      setTimeout(ping_recurse, HEARTBEAT_DELAY_MS);
    });
  }

  if (!nconf.get('ANONYMOUS_SEARCH_ENABLED')) {
    connection.bind(nconf.get("LDAP_BIND_USER"), ldapBindCredentials, function(err) {
      if(err){
        console.error("Error binding to LDAP", 'dn: ' + err.dn + '\n code: ' + err.code + '\n message: ' + err.message);
        return exit(1);
      }
      ping_recurse();
    });
  } else {
    ping_recurse();
  }

  return connection;
}

module.exports.createConnection = createConnection;

module.exports.initialize = async function () {
  if (nconf.get('ANONYMOUS_SEARCH_ENABLED')) return;
  if (ldapBindCredentials) return;

  const plain = nconf.get('LDAP_BIND_PASSWORD');
  if (plain) {
    const fs = require('fs');
    const configPath = require('path').join(__dirname, '..', 'config.json');
    console.log(`LDAP_BIND_PASSWORD found in ${configPath}, migrating to keychain and removing from config.json`);
    await keychain.setPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, plain);
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    delete config.LDAP_BIND_PASSWORD;
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    nconf.clear('LDAP_BIND_PASSWORD');
    ldapBindCredentials = plain;
    return;
  }

  const stored = nconf.get('LDAP_BIND_CREDENTIALS');
  if (stored) {
    // Encrypted value in config.json — decrypt, migrate to keychain, remove from config
    const plaintext = crypto.decrypt(stored);
    await keychain.setPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, plaintext);
    const fs = require('fs');
    const configPath = require('path').join(__dirname, '..', 'config.json');
    console.log(`LDAP_BIND_CREDENTIALS found in ${configPath}, migrating to keychain and removing from config.json`);
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    delete config.LDAP_BIND_CREDENTIALS;
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    nconf.clear('LDAP_BIND_CREDENTIALS');
    ldapBindCredentials = plaintext;
    return;
  }

  // Fetch from keychain (fresh install or already migrated)
  ldapBindCredentials = await keychain.getPassword(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
  if (!ldapBindCredentials) {
    throw new Error('LDAP credential not found in keychain. Re-save settings in the admin console.');
  }
};

module.exports.resetCredentials = function () {
  ldapBindCredentials = null;
};

Object.defineProperty(module.exports, 'client', {
  enumerable: true,
  configurable: false,
  get: function () {
    client = client || initializeConnection();
    return client;
  }
});

Object.defineProperty(module.exports, 'binder', {
  enumerable: true,
  configurable: false,
  get: function () {
    binder = binder || initializeConnection();
    return binder;
  }
});
