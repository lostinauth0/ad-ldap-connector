const secureStorage = require('../lib/secureStorage');

/**
 * Gets the hashed admin password from the keychain. If it doesn't exist, or is empty, returns null.
 * @return {Promise<null|string>}
 */
async function getHashedAdminPassword() {
  try {
    const hashedPassword = await secureStorage.get(secureStorage.keys.ADMIN_CONSOLE_PASSWORD);
    if (!hashedPassword) {
      return null;
    }
    return hashedPassword;
  } catch {
    return null;
  }
}

/**
 * Middleware to require authentication for admin routes. If no admin password is set, redirects to the setup page.
 * If the user is not authenticated, redirects to the login page.
 *
 * @param req
 * @param res
 * @param next
 * @return {Promise<*>}
 */
async function requireAuth(req, res, next) {
  if (!(await getHashedAdminPassword())) {
    return res.redirect('/setup');
  }
  if (!req.session.authenticated) {
    return res.redirect('/login');
  }
  next();
}

/**
 * Middleware to require that an admin password is set. If not, redirects to the setup page.
 * Used for routes that are accessible without authentication but require an admin password to be set,
 * such as the login page.
 *
 * @param req
 * @param res
 * @param next
 * @return {Promise<*>}
 */
async function requireAdminPasswordSet(req, res, next) {
  if (!(await getHashedAdminPassword())) {
    return res.redirect('/setup');
  }
  next();
}

module.exports = {
  getHashedAdminPassword,
  requireAuth,
  requireAdminPasswordSet
};
