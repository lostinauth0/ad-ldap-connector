const axios = require('axios');
const urlJoin = require('url-join');
const os = require('os');

const thumbprint = require('@auth0/thumbprint');
const config = require('../../lib/config');
const secureStorage = require('../../lib/secureStorage');

function pemToCert (pem) {
  var cert =
    /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(
      pem.toString()
    );
  if (cert.length > 0) {
    return cert[1].replace(/[\n|\r\n]/g, '');
  }
  return null;
}

async function configureConnection({ provisioningTicket, connectionName }) {
  const serverUrl = config.get('SERVER_URL') || 'http://' + os.hostname() + ':' + (config.get('PORT') || 4000);
  const signInEndpoint = urlJoin(serverUrl, '/wsfed');
  const pem = await secureStorage.get(secureStorage.keys.AUTH_CERT);
  const cert = pemToCert(pem);
  const certThumbprint = thumbprint.calculate(cert);

  console.log(('Configuring connection ' + connectionName + '.').yellow);
  console.log(' > Posting certificates and signInEndpoint: ' + signInEndpoint);

  try {
    const response = await axios.post(provisioningTicket, {
      certs: [cert],
      signInEndpoint: signInEndpoint,
      agentMode: config.get('AGENT_MODE'),
      agentVersion: require('../../package').version,
    });
    config.set('SERVER_URL', serverUrl);
    config.set('LAST_SENT_THUMBPRINT', certThumbprint);
    config.set('TENANT_SIGNING_KEY', response.data.signingKey || '');
    console.log(('Connection ' + connectionName + ' configured.').green);
  } catch (err) {
    if (err.response && err.response.status !== 200) {
      throw new Error('Unexpected status while configuring connection: ' + err.response.status);
    }

    if (err.code === 'ECONNREFUSED') {
      throw new Error('Unable to reach Auth0 at ' + provisioningTicket);
    }

    throw new Error('Unexpected error while configuring connection: ' + (err.code || err.message));
  }
}

module.exports = { configureConnection };
