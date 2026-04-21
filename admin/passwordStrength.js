const MIN_PASSWORD_LENGTH = 15;
const MAX_PASSWORD_LENGTH = 64;

module.exports.validate = (password) => {
  return password && password.length >= MIN_PASSWORD_LENGTH && password.length <= MAX_PASSWORD_LENGTH;
};

module.exports.validateToString = (password) => {
  if (!password) {
    return 'Password is required.';
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters long.`;
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    return `Password must be no more than ${MAX_PASSWORD_LENGTH} characters long.`;
  }
  return '';
};
