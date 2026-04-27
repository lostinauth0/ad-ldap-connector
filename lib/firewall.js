var release = require('os').release;
const { promisify } = require('util');
const execAsync = promisify(require('child_process').exec);
const _ = require('lodash');

let commands;
if (parseFloat(release()) >= 6.0) { // vista or higher
  commands = {
    add: 'netsh advfirewall firewall add rule name="${ name }" dir=in action=allow program="${ program }" profile=${ profile } enable=yes',
    check: 'netsh advfirewall firewall show rule name="${ name }"'
  };
} else {
  commands = {
    add: 'netsh firewall add allowedprogram "${ program }" "${ name }" ENABLE',
    check: 'netsh firewall show allowedprogram "${ program }"'
  };
}

async function addRule({ name, program, profile }) {
  if(await ruleExists({ name, program, profile})) {
    return;
  }
  const command = _.template(commands.add)({
    name, program, profile
  });
  return await execAsync(command);
}

async function ruleExists({ name, program, profile }) {
  const command = _.template(commands.check)({
    name, program, profile
  });
  return await execAsync(command);
}

module.exports = {
  addRule,
  ruleExists
};
