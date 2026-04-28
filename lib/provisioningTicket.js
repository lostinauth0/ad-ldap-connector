const urlJoin = require('url-join');
const axios = require('axios');

async function loadProvisioningTicket(provisioningTicket) {
  try {
    const infoUrl = urlJoin(provisioningTicket, '/info');
    console.log('Loading settings from ticket: ' + infoUrl);

    const response = await axios.get(infoUrl);
    if (!response.data || !response.data.adHub) {
      throw new Error('Wrong ticket url');
    }
    return response.data;
  } catch (err) {
    if (err.response && err.response.status === 404) {
      throw new Error('Wrong ticket. Does this connection still exist?');
    }

    if (err.response && err.response.status !== 200) {
      throw new Error('Unexpected response from ticket information endpoint. ' +
        'Status code: ' + err.response.status +
        ' Content-Type: ' + err.response.headers['content-type'] + '.');
    }

    switch (err.code) {
    case 'ECONNREFUSED':
      throw new Error(`Unable to reach Auth0 at ${provisioningTicket}. Please check your network connection and try again.`);
    case 'UNABLE_TO_VERIFY_LEAF_SIGNATURE':
    case 'CERT_UNTRUSTED':
      throw new Error(
        'The Auth0 server is using a certificate that cannot be verified. Please check your CA certificates configuration. ' +
        'Go to https://auth0.com/docs/connector/ca-certificates for instructions on how to install your CA certificate.'
      );
    case 'DEPTH_ZERO_SELF_SIGNED_CERT':
      throw new Error(
        'The Auth0 server is using a self-signed certificate. ' +
        'Go to https://auth0.com/docs/connector/ca-certificates for instructions on how to install your certificate.'
      );
    default:
      throw new Error(`Unexpected error while configuring connection: ${err.message}`);
    }
  }
}

module.exports = {
  loadProvisioningTicket
};
