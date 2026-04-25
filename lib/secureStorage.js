const keychain = require('cross-keychain');

const keys = Object.freeze({
  AUTH_CERT: 'auth-cert',
  AUTH_CERT_KEY: 'auth-cert-key',
  LDAP_BIND_PASSWORD: 'ldap-bind-password',
  ADMIN_CONSOLE_PASSWORD: 'admin-console-password',
});

async function store(key, value) {
  await keychain.setPassword('auth0-ad-ldap-connector', key, value);
}

async function get(key) {
  return await keychain.getPassword('auth0-ad-ldap-connector', key);
}

async function clear(key) {
  await keychain.deletePassword('auth0-ad-ldap-connector', key);
}

module.exports = {
  store,
  get,
  clear,
  keys
};
