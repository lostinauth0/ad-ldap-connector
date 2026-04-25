var fs              = require('fs');
var path            = require('path');
var wsfed           = require('wsfed');
var xtend           = require('xtend');
var cookieSessions  = require('cookie-sessions');
var config          = require('./config');

var credentials = {
  cert: config.get('AUTH_CERT') || fs.readFileSync(path.join(__dirname, '../certs/cert.pem')),
  key:  config.get('AUTH_CERT_KEY') ||  fs.readFileSync(path.join(__dirname, '../certs/cert.key'))
};

var issuer  = config.get('WSFED_ISSUER');
var audience = config.get('REALM');

exports.token = wsfed.auth({
  issuer:      issuer,
  cert:        credentials.cert,
  key:         credentials.key,
  getPostURL:  function (wtrealm, wreply, req, callback) {
    var realmPostURLs = config.get(wtrealm || config.get('REALM'));
    if (realmPostURLs) {
      realmPostURLs = realmPostURLs.split(',');
      if (wreply && ~realmPostURLs.indexOf(wreply)) {
        return callback(null, wreply);
      }
      if(!wreply){
        return callback(null, realmPostURLs[0]);
      }
    }
    callback();
  }
});

exports.tokenDirect = function (req, res, next) {

  var wctx = xtend({
    strategy: 'ad'
  }, req.body, {
    session: cookieSessions.serialize(config.get('SESSION_SECRET'), req.session)
  });

  delete wctx.username;
  delete wctx.password;

  return wsfed.auth({
    issuer:      issuer,
    cert:        credentials.cert,
    key:         credentials.key,
    audience:    audience,
    plain_form:  true,
    wctx:        JSON.stringify(wctx),
    getPostURL:  function (wtrealm, wreply, req, callback) {
      var realmPostURLs = config.get(wtrealm || config.get('REALM'));
      if (realmPostURLs) {
        realmPostURLs = realmPostURLs.split(',');

        if (wreply && ~realmPostURLs.indexOf(wreply)) {
          return callback(null, wreply);
        }

        if (!wreply) {
          return callback(null, realmPostURLs[0]);
        }
      }

      callback();
    }
  })(req, res, next);
};

exports.metadata = function () {
  return wsfed.metadata({
    cert:   credentials.cert,
    issuer: issuer
  });
};
