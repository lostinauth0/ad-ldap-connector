var release = require('os').release;
const { promisify } = require('util');
const execAsync = promisify(require('child_process').exec);
const _ = require('lodash');

const commands = {
  add: 'netsh advfirewall firewall add rule name="${ name }" dir=in action=allow program="${ program }" profile=${ profile } enable=yes',
  check: 'netsh advfirewall firewall show rule name="${ name }"'
};

async function addRule({ name, program, profile }) {
  if(await ruleExists({ name, program, profile})) {
    console.log('Firewall rule for Kerberos Proxy already exists, skipping adding rule.');
    return;
  }
  console.log('Adding firewall rule for Kerberos Proxy.');
  const command = _.template(commands.add)({
    name, program, profile
  });
  return await execAsync(command);
}

async function ruleExists({ name, program, profile }) {
  const command = _.template(commands.check)({
    name, program, profile
  });
  try {
    await execAsync(command);
    return true;
  } catch (err) {
    // if no rules are found, netsh returns a non-zero exit code
    return false;
  }
}

module.exports = {
  addRule,
  ruleExists
};
