'use strict';

const { expect } = require('chai');
const proxyquire = require('proxyquire').noCallThru();

describe('lib/ldap initialize()', function () {
  let ldapModule;
  let mockConfig;
  let mockSecureStorage;
  let mockCrypto;
  let secureStorageStoreCalls;
  let secureStorageGetCalls;
  let secureStorageGetResult;

  function buildLdapModule() {
    return proxyquire('../lib/ldap', {
      './config': mockConfig,
      './secureStorage': mockSecureStorage,
      './crypto': mockCrypto,
      // stub modules not under test so the module loads cleanly
      ldapjs: { createClient: function () { return { on: function () {} }; } },
      './exit': function () {},
      cb: function (fn) { return fn; },
      https: { globalAgent: { options: {} } },
      dns: {},
    });
  }

  beforeEach(function () {
    secureStorageStoreCalls = [];
    secureStorageGetCalls = [];
    secureStorageGetResult = 'keychain-password';

    mockConfig = {
      values: {},
      get: function (key) { return this.values[key]; },
      set: function (key, val) { this.values[key] = val; },
    };

    mockSecureStorage = {
      keys: {
        LDAP_BIND_PASSWORD: 'ldap-bind-password',
      },
      store: async function (key, value) {
        secureStorageStoreCalls.push({ key, value });
      },
      get: async function (key) {
        secureStorageGetCalls.push({ key });
        return secureStorageGetResult;
      },
    };

    mockCrypto = {
      decrypt: async function (val) { return 'decrypted:' + val; },
    };

    ldapModule = buildLdapModule();
  });

  // ─── ANONYMOUS_SEARCH_ENABLED ────────────────────────────────────────────────

  describe('when ANONYMOUS_SEARCH_ENABLED is set', function () {
    it('should return without touching secure storage', async function () {
      mockConfig.set('ANONYMOUS_SEARCH_ENABLED', true);
      await ldapModule.initialize();
      expect(secureStorageStoreCalls).to.have.length(0);
      expect(secureStorageGetCalls).to.have.length(0);
    });
  });

  // ─── LDAP_BIND_PASSWORD (plaintext migration) ────────────────────────────────

  describe('when LDAP_BIND_PASSWORD is present in config', function () {
    beforeEach(function () {
      mockConfig.set('LDAP_BIND_PASSWORD', 'secret123');
    });

    it('should save the plaintext password to secure storage', async function () {
      await ldapModule.initialize();
      expect(secureStorageStoreCalls).to.have.length(1);
      expect(secureStorageStoreCalls[0].key).to.equal('ldap-bind-password');
      expect(secureStorageStoreCalls[0].value).to.equal('secret123');
    });

    it('should fetch credentials from secure storage after storing', async function () {
      await ldapModule.initialize();
      expect(secureStorageGetCalls).to.have.length(1);
      expect(secureStorageGetCalls[0].key).to.equal('ldap-bind-password');
    });
  });

  // ─── LDAP_BIND_CREDENTIALS (legacy encrypted migration) ─────────────────────

  describe('when LDAP_BIND_CREDENTIALS is present in config (legacy encrypted)', function () {
    beforeEach(function () {
      mockConfig.set('LDAP_BIND_CREDENTIALS', 'encrypted-blob');
    });

    it('should decrypt and save the plaintext password to secure storage', async function () {
      await ldapModule.initialize();
      expect(secureStorageStoreCalls).to.have.length(1);
      expect(secureStorageStoreCalls[0].key).to.equal('ldap-bind-password');
      expect(secureStorageStoreCalls[0].value).to.equal('decrypted:encrypted-blob');
    });

    it('should fetch credentials from secure storage after storing', async function () {
      await ldapModule.initialize();
      expect(secureStorageGetCalls).to.have.length(1);
      expect(secureStorageGetCalls[0].key).to.equal('ldap-bind-password');
    });
  });

  // ─── Already migrated — read from secure storage ─────────────────────────────

  describe('when neither LDAP_BIND_PASSWORD nor LDAP_BIND_CREDENTIALS is present', function () {
    it('should fetch credentials from secure storage', async function () {
      await ldapModule.initialize();
      expect(secureStorageGetCalls).to.have.length(1);
      expect(secureStorageGetCalls[0].key).to.equal('ldap-bind-password');
    });

    it('should not store anything to secure storage', async function () {
      await ldapModule.initialize();
      expect(secureStorageStoreCalls).to.have.length(0);
    });
  });
});