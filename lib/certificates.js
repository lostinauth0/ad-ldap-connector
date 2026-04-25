const fs = require('fs');
const path = require('path');

const selfsigned = require('selfsigned');
const config = require('./config');
const secureStorage = require('./secureStorage');

const fileNames = {
  pem: path.join(__dirname, '../', 'certs', 'cert.pem'),
  key: path.join(__dirname, '../', 'certs', 'cert.key')
};

/**
 * Ensures certificates are available in secure storage, migrating from config or file if necessary, or generating new ones if not.
 * @param options
 * @param {string} options.connectionName - The name of the connection, used as CN in the certificate.
 * @param {string} options.connectionDomain - The domain of the connection, used as OU in the certificate.
 * @return {Promise<void>}
 */
async function initialize(options = {}) {
  if (config.get('AUTH_CERT')) {
    console.log('AUTH_CERT is set, moving to keychain.');
    await secureStorage.store(secureStorage.keys.AUTH_CERT, config.get('AUTH_CERT'));
    config.clear('AUTH_CERT');
  }

  if (config.get('AUTH_CERT_KEY')) {
    console.log('AUTH_CERT_KEY is set, moving to keychain.');
    await secureStorage.store(secureStorage.keys.AUTH_CERT_KEY, config.get('AUTH_CERT_KEY'));
    config.clear('AUTH_CERT_KEY');
  }

  if (fs.existsSync(fileNames.pem)) {
    console.log('Certificate exists as file, moving to keychain and deleting file.');
    const cert = fs.readFileSync(fileNames.pem, 'utf-8');
    await secureStorage.store(secureStorage.keys.AUTH_CERT, cert);
    fs.unlinkSync(fileNames.pem);
  }

  if (fs.existsSync(fileNames.key)) {
    console.log('Private key exists as file, moving to keychain and deleting file.');
    const cert = fs.readFileSync(fileNames.key, 'utf-8');
    await secureStorage.store(secureStorage.keys.AUTH_CERT_KEY, cert);
    fs.unlinkSync(fileNames.key);
  }

  // If certs are available in the keychain at this point (after migration from file or config or previous runs),
  // we skip generation.
  const cert = await secureStorage.get(secureStorage.keys.AUTH_CERT);
  const key = await secureStorage.get(secureStorage.keys.AUTH_CERT_KEY);
  if (cert && key) {
    console.log('Certificates already exist in secure storage, skipping certificate generation.');
    return;
  }

  if (!options.connectionName || !options.connectionDomain) {
    console.warn('Connection name and domain are required to generate certificates, but were not provided.'.yellow);
    return;
  }

  console.log('Generating a self-signed certificate.'.yellow);
  var pems = selfsigned.generate([
    { shortName: 'CN', value: options.connectionName},
    { shortName: 'OU', value: options.connectionDomain},
    { shortName: 'O', value: 'auth0/ad-ldap-connector'}
  ], {
    days: 365,
    algorithm: 'sha256',
    keySize:2048
  });

  await secureStorage.store(secureStorage.keys.AUTH_CERT, pems.cert);
  await secureStorage.store(secureStorage.keys.AUTH_CERT_KEY, pems.private);

  console.log('Certificate generated.\n'.green);
}

module.exports = {
  initialize
};
