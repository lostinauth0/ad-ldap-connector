const urlJoin = require('url-join');
const axios = require('axios');

async function loadProvisioningTicket(provisioningTicket) {
  try {
    const infoUrl = urlJoin(provisioningTicket, '/info');
    console.log('Loading settings from ticket: ' + infoUrl);

    const response = await axios.get(infoUrl);
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
      console.log('Unable to reach Auth0 at ' + provisioningTicket);
      break;
    case 'UNABLE_TO_VERIFY_LEAF_SIGNATURE':
    case 'CERT_UNTRUSTED':
      console.error(
        'The Auth0 server is using a certificate issued by an untrusted Certification Authority.',
        err
      );
      console.log(
        'Go to https://auth0.com/docs/connector/ca-certificates for instructions on how to install your CA certificate.'
      );
      break;
    case 'DEPTH_ZERO_SELF_SIGNED_CERT':
      console.error(
        'The Auth0 server is using a self-signed certificate',
        err
      );
      console.log(
        'Go to https://auth0.com/docs/connector/ca-certificates for instructions on how to install your certificate.'
      );
      break;
    default:
      console.error(
        'Unexpected error while configuring connection:',
        err
      );
    }
    throw err;
  }
}

module.exports = {
  loadProvisioningTicket
};
