const axios = require('axios');
var urlJoin = require('url-join');
var fs = require('fs');
var path = require('path');
var thumbprint = require('@auth0/thumbprint');
var config = require('../../lib/config');
var os = require('os');

var pemToCert = function (pem) {
  var cert =
    /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(
      pem.toString()
    );
  if (cert.length > 0) {
    return cert[1].replace(/[\n|\r\n]/g, '');
  }

  return null;
};

var getCurrentThumbprint = function (workingPath) {
  if (config.get('AUTH_CERT')) {
    return thumbprint.calculate(pemToCert(config.get('AUTH_CERT')));
  }

  var cert = pemToCert(
    fs.readFileSync(path.join(workingPath, 'certs', 'cert.pem')).toString()
  );
  return thumbprint.calculate(cert);
};

module.exports = function (program, workingPath, connectionInfo, ticket, cb) {
  var serverUrl =
    config.get('SERVER_URL') ||
    'http://' + os.hostname() + ':' + (config.get('PORT') || 4000);

  var signInEndpoint = urlJoin(serverUrl, '/wsfed');
  var pem =
    config.get('AUTH_CERT') ||
    fs.readFileSync(path.join(workingPath, 'certs', 'cert.pem')).toString();
  var cert = pemToCert(pem);

  console.log(
    ('Configuring connection ' + connectionInfo.connectionName + '.').yellow
  );
  console.log(' > Posting certificates and signInEndpoint: ' + signInEndpoint);

  axios
    .post(ticket, {
      certs: [cert],
      signInEndpoint: signInEndpoint,
      agentMode: config.get('AGENT_MODE'),
      agentVersion: require('../../package').version,
    })
    .then((response) => {
      config.set('SERVER_URL', serverUrl);
      config.set('LAST_SENT_THUMBPRINT', getCurrentThumbprint(workingPath));
      config.set('TENANT_SIGNING_KEY', response.data.signingKey || '');

      console.log(
        ('Connection ' + connectionInfo.connectionName + ' configured.').green
      );
      cb();
    })
    .catch((err) => {
      if (err.response && err.response.status !== 200) {
        console.log(
          'Unexpected status while configuring connection: ' + err.response.status
        );
        return cb(new Error(err.response.data));
      }

      if (err.code === 'ECONNREFUSED') {
        console.log('Unable to reach Auth0 at ' + ticket);
      } else {
        console.log(
          'Unexpected error while configuring connection: ' +
            (err.code || err.message)
        );
      }
      return cb(err);
    });
};
