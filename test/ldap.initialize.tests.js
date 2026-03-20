'use strict';

const { expect } = require('chai');
const proxyquire = require('proxyquire').noCallThru();

const KEYCHAIN_SERVICE = 'auth0-ad-ldap-connector';
const KEYCHAIN_ACCOUNT = 'ldap-bind-credentials';

describe('lib/ldap initialize()', function () {
  let ldapModule;
  let mockNconf;
  let mockKeychain;
  let mockCrypto;
  let mockFs;
  let keychainSetCalls;
  let keychainGetCalls;
  let keychainGetResult;
  let fsWriteCalls;
  let fsReadResult;
  let nconfClearCalls;

  function buildLdapModule() {
    return proxyquire('../lib/ldap', {
      nconf: mockNconf,
      'cross-keychain': mockKeychain,
      './crypto': mockCrypto,
      fs: mockFs,
      // stub out modules not under test so the module loads cleanly
      ldapjs: { createClient: function () { return { on: function () {} }; } },
      './exit': function () {},
      cb: function (fn) { return fn; },
      https: { globalAgent: { options: {} } },
      dns: {},
    });
  }

  beforeEach(function () {
    keychainSetCalls = [];
    keychainGetCalls = [];
    keychainGetResult = 'keychain-password';
    fsWriteCalls = [];
    nconfClearCalls = [];
    fsReadResult = JSON.stringify({ LDAP_URL: 'ldap://localhost' });

    mockNconf = {
      values: {},
      get: function (key) { return this.values[key]; },
      set: function (key, val) { this.values[key] = val; },
      clear: function (key) {
        delete this.values[key];
        nconfClearCalls.push(key);
      },
      '@global': true,
    };

    mockKeychain = {
      setPassword: async function (service, account, password) {
        keychainSetCalls.push({ service, account, password });
      },
      getPassword: async function (service, account) {
        keychainGetCalls.push({ service, account });
        return keychainGetResult;
      },
    };

    mockCrypto = {
      decrypt: function (val) { return 'decrypted:' + val; },
    };

    mockFs = {
      readFileSync: function () { return fsReadResult; },
      writeFileSync: function (filePath, content) {
        fsWriteCalls.push({ filePath, content });
      },
    };

    ldapModule = buildLdapModule();
  });

  // ─── ANONYMOUS_SEARCH_ENABLED ────────────────────────────────────────────────

  describe('when ANONYMOUS_SEARCH_ENABLED is set', function () {
    it('should return immediately without touching keychain or config', async function () {
      mockNconf.set('ANONYMOUS_SEARCH_ENABLED', true);
      await ldapModule.initialize();
      expect(keychainSetCalls).to.have.length(0);
      expect(keychainGetCalls).to.have.length(0);
      expect(fsWriteCalls).to.have.length(0);
    });
  });

  // ─── LDAP_BIND_PASSWORD (plaintext migration) ────────────────────────────────

  describe('when LDAP_BIND_PASSWORD is present in nconf', function () {
    beforeEach(function () {
      mockNconf.set('LDAP_BIND_PASSWORD', 'secret123');
      fsReadResult = JSON.stringify({
        LDAP_BIND_PASSWORD: 'secret123',
        LDAP_URL: 'ldap://localhost',
      });
    });

    it('should save the plaintext password to the keychain', async function () {
      await ldapModule.initialize();
      expect(keychainSetCalls).to.have.length(1);
      expect(keychainSetCalls[0].service).to.equal(KEYCHAIN_SERVICE);
      expect(keychainSetCalls[0].account).to.equal(KEYCHAIN_ACCOUNT);
      expect(keychainSetCalls[0].password).to.equal('secret123');
    });

    it('should remove LDAP_BIND_PASSWORD from config.json', async function () {
      await ldapModule.initialize();
      expect(fsWriteCalls).to.have.length(1);
      const written = JSON.parse(fsWriteCalls[0].content);
      expect(written).to.not.have.property('LDAP_BIND_PASSWORD');
    });

    it('should preserve other keys in config.json', async function () {
      await ldapModule.initialize();
      const written = JSON.parse(fsWriteCalls[0].content);
      expect(written).to.have.property('LDAP_URL', 'ldap://localhost');
    });

    it('should clear LDAP_BIND_PASSWORD from nconf', async function () {
      await ldapModule.initialize();
      expect(nconfClearCalls).to.include('LDAP_BIND_PASSWORD');
      expect(mockNconf.get('LDAP_BIND_PASSWORD')).to.be.undefined;
    });

    it('should not fall through to keychain.getPassword', async function () {
      await ldapModule.initialize();
      expect(keychainGetCalls).to.have.length(0);
    });

    it('should write to keychain before clearing from config', async function () {
      const order = [];
      mockKeychain.setPassword = async function () { order.push('keychain'); };
      mockFs.writeFileSync = function () { order.push('writeFile'); };
      await ldapModule.initialize();
      expect(order.indexOf('keychain')).to.be.lessThan(order.indexOf('writeFile'));
    });
  });

  // ─── LDAP_BIND_CREDENTIALS (legacy encrypted migration) ─────────────────────

  describe('when LDAP_BIND_CREDENTIALS is present in nconf (legacy encrypted)', function () {
    beforeEach(function () {
      mockNconf.set('LDAP_BIND_CREDENTIALS', 'encrypted-blob');
      fsReadResult = JSON.stringify({
        LDAP_BIND_CREDENTIALS: 'encrypted-blob',
        LDAP_URL: 'ldap://localhost',
      });
    });

    it('should decrypt the stored value and save plaintext to keychain', async function () {
      await ldapModule.initialize();
      expect(keychainSetCalls).to.have.length(1);
      expect(keychainSetCalls[0].password).to.equal('decrypted:encrypted-blob');
    });

    it('should remove LDAP_BIND_CREDENTIALS from config.json', async function () {
      await ldapModule.initialize();
      expect(fsWriteCalls).to.have.length(1);
      const written = JSON.parse(fsWriteCalls[0].content);
      expect(written).to.not.have.property('LDAP_BIND_CREDENTIALS');
    });

    it('should preserve other keys in config.json', async function () {
      await ldapModule.initialize();
      const written = JSON.parse(fsWriteCalls[0].content);
      expect(written).to.have.property('LDAP_URL', 'ldap://localhost');
    });

    it('should clear LDAP_BIND_CREDENTIALS from nconf', async function () {
      await ldapModule.initialize();
      expect(nconfClearCalls).to.include('LDAP_BIND_CREDENTIALS');
      expect(mockNconf.get('LDAP_BIND_CREDENTIALS')).to.be.undefined;
    });

    it('should not fall through to keychain.getPassword', async function () {
      await ldapModule.initialize();
      expect(keychainGetCalls).to.have.length(0);
    });
  });

  // ─── Already migrated — read from keychain ───────────────────────────────────

  describe('when neither LDAP_BIND_PASSWORD nor LDAP_BIND_CREDENTIALS is present', function () {
    it('should load credentials from the keychain', async function () {
      keychainGetResult = 'keychain-stored-password';
      await ldapModule.initialize(); // should not throw
      expect(keychainGetCalls).to.have.length(1);
      expect(keychainGetCalls[0].service).to.equal(KEYCHAIN_SERVICE);
      expect(keychainGetCalls[0].account).to.equal(KEYCHAIN_ACCOUNT);
    });

    it('should not write to config.json', async function () {
      keychainGetResult = 'keychain-stored-password';
      await ldapModule.initialize();
      expect(fsWriteCalls).to.have.length(0);
    });

    it('should throw when keychain has no credentials', async function () {
      keychainGetResult = null;
      let err;
      try {
        await ldapModule.initialize();
      } catch (e) {
        err = e;
      }
      expect(err).to.be.ok;
      expect(err.message).to.equal('LDAP credential not found in keychain. Re-save settings in the admin console.');
    });
  });

  // ─── Already initialised (second call) ───────────────────────────────────────

  describe('when initialize() has already run successfully', function () {
    it('should not access keychain on a second call', async function () {
      keychainGetResult = 'password';
      await ldapModule.initialize();
      keychainGetCalls = [];
      keychainSetCalls = [];
      // reset nconf so it looks like LDAP_BIND_PASSWORD is gone too
      await ldapModule.initialize();
      expect(keychainGetCalls).to.have.length(0);
      expect(keychainSetCalls).to.have.length(0);
    });

    it('should not write to config.json on a second call', async function () {
      keychainGetResult = 'password';
      await ldapModule.initialize();
      fsWriteCalls = [];
      await ldapModule.initialize();
      expect(fsWriteCalls).to.have.length(0);
    });
  });

  // ─── resetCredentials ────────────────────────────────────────────────────────

  describe('resetCredentials()', function () {
    it('should cause initialize() to fetch from keychain again', async function () {
      keychainGetResult = 'password';
      await ldapModule.initialize();
      ldapModule.resetCredentials();
      keychainGetCalls = [];
      await ldapModule.initialize();
      expect(keychainGetCalls).to.have.length(1);
    });
  });
});
