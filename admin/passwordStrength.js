const { PasswordPolicy } = require('password-sheriff');
const passwordPolicies = require('auth0-password-policies');

const MAX_PASSWORD_LENGTH = 64;

const passwordPolicy = new PasswordPolicy({
  ...passwordPolicies.good,
  maxLength: { maxBytes: MAX_PASSWORD_LENGTH },
});

module.exports.validate = (password) => {
  return passwordPolicy.missing(password);
};

module.exports.validateToString = (password) => {
  if (passwordPolicy.check(password)) {
    return '';
  } else {
    return passwordPolicy.toString();
  }
};
