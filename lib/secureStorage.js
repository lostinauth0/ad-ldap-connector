const keychain = require('cross-keychain');

const keys = Object.freeze({
  AUTH_CERT: 'auth-cert',
  AUTH_CERT_KEY: 'auth-cert-key',
  LDAP_BIND_PASSWORD: 'ldap-bind-password',
  ADMIN_CONSOLE_PASSWORD: 'admin-console-password',
});

class SecureStorage {
  #keychain;

  constructor({ keychainModule = keychain } = {}) {
    this.#keychain = keychainModule;
  }

  async store(key, value) {
    await this.#keychain.setPassword('auth0-ad-ldap-connector', key, value);
  }

  async get(key) {
    return await this.#keychain.getPassword('auth0-ad-ldap-connector', key);
  }

  async clear(key) {
    await this.#keychain.deletePassword('auth0-ad-ldap-connector', key);
  }
}

const secureStorage = new SecureStorage();

module.exports = secureStorage;
module.exports.keys = keys;
module.exports.SecureStorage = SecureStorage;
