'use strict';

/**
 * Integration tests for admin/server.js endpoints.
 *
 */

const expect = require('chai').expect;
const request = require('supertest');
const proxyquire = require('proxyquire').noCallThru();
const bcrypt = require('bcryptjs');

const TEST_PASSWORD = 'TestPassword123456!';

// ---------------------------------------------------------------------------
// In-memory secure storage — realistic stand-in for the OS credential store
// ---------------------------------------------------------------------------
const keychainStore = new Map();

const mockSecureStorage = {
  store: async (key, value) => keychainStore.set(key, value),
  get: async (key) => keychainStore.get(key) || null,
  clear: async (key) => keychainStore.delete(key),
  keys: {
    AUTH_CERT: 'auth-cert',
    AUTH_CERT_KEY: 'auth-cert-key',
    LDAP_BIND_PASSWORD: 'ldap-bind-password',
    ADMIN_CONSOLE_PASSWORD: 'admin-console-password',
  },
  '@global': true,
};

function setAdminPassword(password) {
  const hash = bcrypt.hashSync(password, 1); // cost=1 for test speed
  keychainStore.set('admin-console-password', hash);
}

// ---------------------------------------------------------------------------
// App factory — minimal stubbing, real middleware pipeline
// ---------------------------------------------------------------------------
function buildApp() {
  return proxyquire('../../admin/server', {
    // Prevent the HTTP server from binding a port during tests
    '../lib/add_certs': { inject: () => {}, injectAsync: () => Promise.resolve() },
    // No real LDAP server available in test environment
    '../lib/ldap': {
      initialize: () => Promise.resolve(),
      resetCredentials: () => {},
    },
    '../lib/users': function Users() {
      this.list = (q, opts, cb) =>
        cb(null, [{ dn: 'cn=test,dc=example,dc=com' }]);
      this.getByUserName = (q, opts, cb) =>
        cb(null, { dn: 'cn=test,dc=example,dc=com' });
    },
    // Replace the OS secure storage with an in-memory store
    // @global ensures the stub is used by admin/middleware.js too
    '../lib/secureStorage': mockSecureStorage,
    // Everything else (csurf, express-session, bcrypt, EJS …) is real
  });
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/**
 * Parse the CSRF token from a hidden form field rendered by EJS.
 * Handles both attribute orderings produced by the templates:
 *   <input type="hidden" name="_csrf" value="TOKEN">
 *   <input type="hidden" id="csrf" name="_csrf" value="TOKEN">
 */
function extractCsrfToken(html) {
  const m =
    html.match(/name="_csrf"[^>]*value="([^"]+)"/) ||
    html.match(/value="([^"]+)"[^>]*name="_csrf"/);
  if (!m) throw new Error('CSRF token not found in response body');
  return m[1];
}

/**
 * Create a supertest agent, log in with TEST_PASSWORD, and return it.
 * The agent retains cookies (session + _csrf) across subsequent requests.
 */
async function createAuthenticatedAgent(app) {
  const agent = request.agent(app);
  const loginPage = await agent.get('/login');
  const csrfToken = extractCsrfToken(loginPage.text);
  const loginRes = await agent
    .post('/login')
    .type('form')
    .send({ _csrf: csrfToken, password: TEST_PASSWORD });
  expect(loginRes.status, 'login should redirect').to.equal(302);
  return agent;
}

/**
 * Fetch GET / with an already-authenticated agent and return its CSRF token.
 * Used as a source of valid CSRF tokens for protected POST endpoints.
 */
async function getCsrfToken(agent) {
  const res = await agent.get('/');
  expect(res.status, 'GET / should return 200 when authenticated').to.equal(200);
  return extractCsrfToken(res.text);
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------
describe('admin server endpoints (integration)', function () {
  this.timeout(10000);

  let app;

  before(function () {
    app = buildApp();
  });

  beforeEach(function () {
    keychainStore.clear();
  });

  // -------------------------------------------------------------------------
  // GET /setup
  // -------------------------------------------------------------------------
  describe('GET /setup', function () {
    it('renders the setup page when no admin password is set', async function () {
      const res = await request(app).get('/setup');
      expect(res.status).to.equal(200);
      expect(res.text).to.include('Set Admin Password');
    });

    it('redirects to / when an admin password is already set', async function () {
      setAdminPassword(TEST_PASSWORD);
      const res = await request(app).get('/setup');
      expect(res.status).to.equal(302);
      expect(res.headers.location).to.equal('/');
    });
  });

  // -------------------------------------------------------------------------
  // GET /login
  // -------------------------------------------------------------------------
  describe('GET /login', function () {
    it('redirects to /setup when no admin password is set', async function () {
      const res = await request(app).get('/login');
      expect(res.status).to.equal(302);
      expect(res.headers.location).to.equal('/setup');
    });

    it('renders the login form with a CSRF token when password is set', async function () {
      setAdminPassword(TEST_PASSWORD);
      const res = await request(app).get('/login');
      expect(res.status).to.equal(200);
      expect(res.text).to.include('name="_csrf"');
      expect(res.text).to.include('Admin Login');
    });

    it('redirects to / when already authenticated', async function () {
      setAdminPassword(TEST_PASSWORD);
      const agent = await createAuthenticatedAgent(app);
      const res = await agent.get('/login');
      expect(res.status).to.equal(302);
      expect(res.headers.location).to.equal('/');
    });
  });

  // -------------------------------------------------------------------------
  // POST /login — CSRF token must come from GET /login on the same agent
  // -------------------------------------------------------------------------
  describe('POST /login', function () {
    beforeEach(function () {
      setAdminPassword(TEST_PASSWORD);
    });

    it('redirects to / and establishes a session on the correct password', async function () {
      const agent = request.agent(app);
      const loginPage = await agent.get('/login');
      const csrfToken = extractCsrfToken(loginPage.text);

      const res = await agent
        .post('/login')
        .type('form')
        .send({ _csrf: csrfToken, password: TEST_PASSWORD });

      expect(res.status).to.equal(302);
      expect(res.headers.location).to.equal('/');
    });

    it('re-renders the login form with an error message on wrong password', async function () {
      const agent = request.agent(app);
      const loginPage = await agent.get('/login');
      const csrfToken = extractCsrfToken(loginPage.text);

      const res = await agent
        .post('/login')
        .type('form')
        .send({ _csrf: csrfToken, password: 'totally-wrong-password' });

      expect(res.status).to.equal(200);
      expect(res.text).to.include('Invalid password');
    });

    it('rejects the request when the CSRF token is missing', async function () {
      const res = await request(app)
        .post('/login')
        .type('form')
        .send({ password: TEST_PASSWORD });

      // csurf responds with 403 when the token is absent
      expect(res.status).to.equal(403);
    });

    it('rejects the request when the CSRF token is invalid', async function () {
      const agent = request.agent(app);
      // Trigger the CSRF cookie to be set
      await agent.get('/login');

      const res = await agent
        .post('/login')
        .type('form')
        .send({ _csrf: 'not-a-real-token', password: TEST_PASSWORD });

      expect(res.status).to.equal(403);
    });
  });

  // -------------------------------------------------------------------------
  // GET /logout
  // -------------------------------------------------------------------------
  describe('GET /logout', function () {
    it('redirects to /login', async function () {
      const res = await request(app).get('/logout');
      expect(res.status).to.equal(302);
      expect(res.headers.location).to.equal('/login');
    });

    it('destroys the session so protected routes require login again', async function () {
      setAdminPassword(TEST_PASSWORD);
      const agent = await createAuthenticatedAgent(app);

      // Confirm the session is active
      const beforeLogout = await agent.get('/version');
      expect(beforeLogout.status).to.equal(200);

      await agent.get('/logout');

      // After logout the session is gone — should redirect to /login
      const afterLogout = await agent.get('/version');
      expect(afterLogout.status).to.equal(302);
      expect(afterLogout.headers.location).to.equal('/login');
    });
  });

  // -------------------------------------------------------------------------
  // Protected routes — unauthenticated redirects
  // -------------------------------------------------------------------------
  describe('protected routes redirect to /setup when no password is set', function () {
    const routes = ['/', '/version', '/logs', '/profile-mapper', '/updater/logs'];

    routes.forEach(function (route) {
      it(`GET ${route} → /setup`, async function () {
        const res = await request(app).get(route);
        expect(res.status).to.equal(302);
        expect(res.headers.location).to.equal('/setup');
      });
    });
  });

  describe('protected routes redirect to /login when not authenticated', function () {
    beforeEach(function () {
      setAdminPassword(TEST_PASSWORD);
    });

    const routes = ['/', '/version', '/logs', '/profile-mapper', '/updater/logs'];

    routes.forEach(function (route) {
      it(`GET ${route} → /login`, async function () {
        const res = await request(app).get(route);
        expect(res.status).to.equal(302);
        expect(res.headers.location).to.equal('/login');
      });
    });
  });

  // -------------------------------------------------------------------------
  // Authenticated requests
  // -------------------------------------------------------------------------
  describe('authenticated requests', function () {
    let agent;

    before(async function () {
      setAdminPassword(TEST_PASSWORD);
      agent = await createAuthenticatedAgent(app);
    });

    beforeEach(function () {
      setAdminPassword(TEST_PASSWORD);
    });

    describe('GET /version', function () {
      it('returns the package version as plain text', async function () {
        const res = await agent.get('/version');
        expect(res.status).to.equal(200);
        expect(res.headers['content-type']).to.match(/text\/plain/);
        expect(res.text).to.match(/^\d+\.\d+\.\d+/);
      });
    });

    describe('GET /logs', function () {
      it('returns a plain-text response', async function () {
        const res = await agent.get('/logs');
        expect(res.status).to.equal(200);
        expect(res.headers['content-type']).to.match(/text\/plain/);
      });
    });

    describe('POST /logs/clear', function () {
      it('returns 200 with a valid CSRF token', async function () {
        const csrfToken = await getCsrfToken(agent);
        const res = await agent
          .post('/logs/clear')
          .type('form')
          .send({ _csrf: csrfToken });
        expect(res.status).to.equal(200);
      });

      it('returns 403 without a CSRF token', async function () {
        const res = await agent.post('/logs/clear').type('form').send({});
        expect(res.status).to.equal(403);
      });
    });

    describe('GET /profile-mapper', function () {
      it('returns a plain-text response', async function () {
        const res = await agent.get('/profile-mapper');
        expect(res.status).to.equal(200);
        expect(res.headers['content-type']).to.match(/text\/plain/);
      });
    });

    describe('GET /updater/logs', function () {
      it('returns a plain-text response', async function () {
        const res = await agent.get('/updater/logs');
        expect(res.status).to.equal(200);
        expect(res.headers['content-type']).to.match(/text\/plain/);
      });
    });

    describe('GET /users/search', function () {
      it('returns a JSON array of matching users', async function () {
        const res = await agent.get('/users/search?query=test');
        expect(res.status).to.equal(200);
        expect(res.headers['content-type']).to.match(/json/);
        expect(res.body).to.be.an('array');
      });
    });

    describe('GET /users/by-login', function () {
      it('returns user data as JSON', async function () {
        const res = await agent.get('/users/by-login?query=test');
        expect(res.status).to.equal(200);
      });
    });

    describe('POST /password', function () {
      it('redirects with an error when the new password is too short', async function () {
        const csrfToken = await getCsrfToken(agent);
        const res = await agent
          .post('/password')
          .type('form')
          .send({
            _csrf: csrfToken,
            current_password: TEST_PASSWORD,
            new_password: 'short',
            confirm_password: 'short',
          });
        expect(res.status).to.equal(302);
        expect(res.headers.location).to.include('/#security?error=');
      });

      it('redirects with an error when new passwords do not match', async function () {
        const csrfToken = await getCsrfToken(agent);
        const res = await agent
          .post('/password')
          .type('form')
          .send({
            _csrf: csrfToken,
            current_password: TEST_PASSWORD,
            new_password: 'NewSecurePassword123!',
            confirm_password: 'DifferentPassword456!',
          });
        expect(res.status).to.equal(302);
        expect(res.headers.location).to.include('/#security?error=');
      });

      it('redirects with an error when the current password is incorrect', async function () {
        const csrfToken = await getCsrfToken(agent);
        const res = await agent
          .post('/password')
          .type('form')
          .send({
            _csrf: csrfToken,
            current_password: 'WrongCurrentPassword!',
            new_password: 'NewSecurePassword123!',
            confirm_password: 'NewSecurePassword123!',
          });
        expect(res.status).to.equal(302);
        expect(res.headers.location).to.include('/#security?error=');
      });

      it('redirects to /?s=1 on a successful password change', async function () {
        const csrfToken = await getCsrfToken(agent);
        const res = await agent
          .post('/password')
          .type('form')
          .send({
            _csrf: csrfToken,
            current_password: TEST_PASSWORD,
            new_password: 'NewSecurePassword123!',
            confirm_password: 'NewSecurePassword123!',
          });
        expect(res.status).to.equal(302);
        expect(res.headers.location).to.equal('/?s=1');
      });

      it('returns 403 without a CSRF token', async function () {
        const res = await agent
          .post('/password')
          .type('form')
          .send({
            current_password: TEST_PASSWORD,
            new_password: 'NewSecurePassword123!',
            confirm_password: 'NewSecurePassword123!',
          });
        expect(res.status).to.equal(403);
      });
    });
  });
});
