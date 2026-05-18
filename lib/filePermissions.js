/**
 * Restrict the permissions of a file to be only accessible by the owner (and group) (and administrators on Windows).
 *
 * @param filePath full path to file to restrict access to
 * @param platform platform string like 'win32'
 * @param execAsync asynchronously executes a command and returns the output
 * @return {Promise<void>}
 */
async function restrict({
  filePath,
  platform,
  execAsync
}) {
  if (platform !== 'win32') {
    await execAsync(`chmod 600 '${filePath.replace(/'/g, '\'\\\'\'')}'`);
  } else {
    // On windows, we use powershell to set the ACL so that only administrators have access to the file
    const commands = [
      '$sddl = \'D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)\'',
      `$acl = Get-Acl -Path '${filePath}'`,
      '$acl.SetSecurityDescriptorSddlForm($sddl)',
      `Set-Acl -Path '${filePath}' -AclObject $acl`
    ];
    await execAsync('powershell -Command "' + commands.join(';') + '"');
  }
}

module.exports = {
  restrict,
};
