const { expect } = require('chai');
const { SecureStorage } = require('../lib/secureStorage');

const SERVICE_NAME = 'auth0-ad-ldap-connector';

// ---------------------------------------------------------------------------
// Mock factories
// ---------------------------------------------------------------------------

function makeKeychainMock(initialStore = {}) {
  const store = { ...initialStore };
  return {
    setPassword: async (service, key, value) => { store[`${service}:${key}`] = value; },
    getPassword: async (service, key) => store[`${service}:${key}`],
    deletePassword: async (service, key) => { delete store[`${service}:${key}`]; },
    _store: store,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SecureStorage', () => {
  describe('store()', () => {
    it('persists the value so it can be retrieved via get()', async () => {
      const keychainMock = makeKeychainMock();
      const storage = new SecureStorage({ keychainModule: keychainMock });

      await storage.store('my-key', 'my-value');

      expect(keychainMock._store[`${SERVICE_NAME}:my-key`]).to.equal('my-value');
    });

    it('uses the service name "auth0-ad-ldap-connector"', async () => {
      const calls = [];
      const keychainMock = {
        setPassword: async (service, key, value) => calls.push({ service, key, value }),
        getPassword: async () => {},
        deletePassword: async () => {},
      };
      const storage = new SecureStorage({ keychainModule: keychainMock });

      await storage.store('some-key', 'some-value');

      expect(calls[0].service).to.equal(SERVICE_NAME);
    });

    it('passes the key and value to the keychain unchanged', async () => {
      const calls = [];
      const keychainMock = {
        setPassword: async (service, key, value) => calls.push({ service, key, value }),
        getPassword: async () => {},
        deletePassword: async () => {},
      };
      const storage = new SecureStorage({ keychainModule: keychainMock });

      await storage.store('ldap-bind-password', 's3cr3t!');

      expect(calls[0].key).to.equal('ldap-bind-password');
      expect(calls[0].value).to.equal('s3cr3t!');
    });

    it('overwrites an existing value when called again with the same key', async () => {
      const keychainMock = makeKeychainMock();
      const storage = new SecureStorage({ keychainModule: keychainMock });

      await storage.store('my-key', 'original');
      await storage.store('my-key', 'updated');

      expect(keychainMock._store[`${SERVICE_NAME}:my-key`]).to.equal('updated');
    });
  });

  describe('get()', () => {
    it('returns a value that was previously stored', async () => {
      const keychainMock = makeKeychainMock();
      const storage = new SecureStorage({ keychainModule: keychainMock });

      await storage.store('my-key', 'my-value');
      const result = await storage.get('my-key');

      expect(result).to.equal('my-value');
    });

    it('returns undefined for a key that was never stored', async () => {
      const keychainMock = makeKeychainMock();
      const storage = new SecureStorage({ keychainModule: keychainMock });

      const result = await storage.get('nonexistent-key');

      expect(result).to.be.undefined;
    });

    it('uses the service name "auth0-ad-ldap-connector"', async () => {
      const calls = [];
      const keychainMock = {
        setPassword: async () => {},
        getPassword: async (service, key) => { calls.push({ service, key }); },
        deletePassword: async () => {},
      };
      const storage = new SecureStorage({ keychainModule: keychainMock });

      await storage.get('some-key');

      expect(calls[0].service).to.equal(SERVICE_NAME);
    });

    it('passes the key to the keychain unchanged', async () => {
      const calls = [];
      const keychainMock = {
        setPassword: async () => {},
        getPassword: async (service, key) => { calls.push({ service, key }); },
        deletePassword: async () => {},
      };
      const storage = new SecureStorage({ keychainModule: keychainMock });

      await storage.get('auth-cert');

      expect(calls[0].key).to.equal('auth-cert');
    });
  });

  describe('clear()', () => {
    it('removes a stored value so get() returns undefined afterwards', async () => {
      const keychainMock = makeKeychainMock();
      const storage = new SecureStorage({ keychainModule: keychainMock });

      await storage.store('my-key', 'my-value');
      await storage.clear('my-key');
      const result = await storage.get('my-key');

      expect(result).to.be.undefined;
    });

    it('uses the service name "auth0-ad-ldap-connector"', async () => {
      const calls = [];
      const keychainMock = {
        setPassword: async () => {},
        getPassword: async () => {},
        deletePassword: async (service, key) => { calls.push({ service, key }); },
      };
      const storage = new SecureStorage({ keychainModule: keychainMock });

      await storage.clear('some-key');

      expect(calls[0].service).to.equal(SERVICE_NAME);
    });

    it('passes the key to the keychain unchanged', async () => {
      const calls = [];
      const keychainMock = {
        setPassword: async () => {},
        getPassword: async () => {},
        deletePassword: async (service, key) => { calls.push({ service, key }); },
      };
      const storage = new SecureStorage({ keychainModule: keychainMock });

      await storage.clear('auth-cert-key');

      expect(calls[0].key).to.equal('auth-cert-key');
    });

    it('does not affect other keys stored in the keychain', async () => {
      const keychainMock = makeKeychainMock();
      const storage = new SecureStorage({ keychainModule: keychainMock });

      await storage.store('key-a', 'value-a');
      await storage.store('key-b', 'value-b');
      await storage.clear('key-a');

      expect(await storage.get('key-b')).to.equal('value-b');
    });
  });
});