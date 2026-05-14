const xtend = require('xtend');
const config = require('../lib/config');
const { restartServer, getHashedAdminPassword } = require('./utils');

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
  try {
    if (!(await getHashedAdminPassword())) {
      return res.redirect('/setup');
    }
    if (!req.session.authenticated) {
      return res.redirect('/login');
    }
    next();
  } catch (err) {
    next(err);
  }
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
  try {
    if (!(await getHashedAdminPassword())) {
      return res.redirect('/setup');
    }
    next();
  } catch(err) {
    next(err);
  }
}

async function mergeConfig(req, res, next) {
  try {
    var newConfig = xtend(req.current_config, req.body);
    for (const key of Object.keys(newConfig)) {
      config.set(key, newConfig[key]);
    }
    await config.save(true);

    if (req.body.LDAP_URL || req.body.PORT || req.body.SERVER_URL) {
      return restartServer(function () {
        return res.redirect('/?s=1');
      });
    }

    res.redirect('/');
  } catch(err) {
    next(err);
  }
}

function setCurrentConfig(req, res, next) {
  req.current_config = config.getAll();
  next();
}

module.exports = {
  getHashedAdminPassword,
  requireAuth,
  requireAdminPasswordSet,
  mergeConfig,
  setCurrentConfig
};
