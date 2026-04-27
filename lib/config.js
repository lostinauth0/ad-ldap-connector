const fs = require('fs');
const nconf = require('nconf');
const execAsync = require('util').promisify(require('child_process').exec);

const defaults = {
  PORT:                                 4000,
  SESSION_SECRET:                       'a1b2c3d4567',
  AUTHENTICATION:                       'FORM',
  LDAP_SEARCH_QUERY:                    '(&(objectCategory=person)(anr={0}))',
  LDAP_SEARCH_RESULTS_OMIT_GROUPS:      true,
  LDAP_SEARCH_ALL_QUERY:                '(objectCategory=person)',
  LDAP_SEARCH_LIST_GROUPS_QUERY:        '(objectCategory=group)',
  LDAP_SEARCH_GROUPS:                   '(member:1.2.840.113556.1.4.1941:={0})',
  LDAP_USER_BY_NAME:                    '(sAMAccountName={0})',
  LDAP_NUMBER_OF_PARALLEL_BINDS:        1,
  LDAP_HEARTBEAT_SEARCH_QUERY:          '(&(objectclass=user)(|(sAMAccountName=foo)(UserPrincipalName=foo)))',
  WSFED_ISSUER:                         'urn:auth0',
  AGENT_MODE:                           true,
  GROUPS:                               true,
  LDAP_HEARTBEAT_SECONDS:               60,
  GROUPS_TIMEOUT_SECONDS:               20,
  GROUP_PROPERTY:                       'cn',
  GROUP_PROPERTIES:                     [],
  GROUPS_CACHE_SECONDS:                 600,
  GROUPS_DEREF_ALIASES:			0,
  ALLOW_PASSWORD_EXPIRED:               false,
  ALLOW_PASSWORD_CHANGE_REQUIRED:       false,
  OVERRIDE_CONFIG:                      true,
  CACHE_FILE:                           __dirname + '/../cache.db',
  SSL_CA_FILE:                          '.+.(pem|crt|cer)$',
  SSL_CA_PATH:                          false,
  SSL_OPENSSLDIR_PATTERN:               'OPENSSLDIR\\s*\\:\\s*\\"([^\\"]*)\\"',
  ENABLE_WRITE_BACK:                    false,
  ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD: false
};
const CONFIG_ALLOW_LIST = [
  'ANONYMOUS_SEARCH_ENABLED',
  'LDAP_URL',
  'LDAP_BASE',
  'LDAP_BIND_USER',
  'LDAP_SEARCH_QUERY',
  'LDAP_SEARCH_RESULTS_OMIT_GROUPS',
  'LDAP_SEARCH_ALL_QUERY',
  'LDAP_SEARCH_LIST_GROUPS_QUERY',
  'LDAP_SEARCH_GROUPS',
  'LDAP_USER_BY_NAME',
  'LDAP_NUMBER_OF_PARALLEL_BINDS',
  'LDAP_HEARTBEAT_SEARCH_QUERY',
  'LDAP_HEARTBEAT_SECONDS',
  'LDAP_BASE_GROUPS',
  'AD_HUB',
  'ALLOW_PASSWORD_EXPIRED',
  'ALLOW_PASSWORD_CHANGE_REQUIRED',
  'WITH_KERBEROS_PROXY_FRONTEND',
  'GROUPS_CACHE_SECONDS',
  'GROUPS',
  'GROUP_PROPERTY',
  'GROUP_PROPERTIES',
  'GROUPS_TIMEOUT_SECONDS',
  'GROUPS_DEREF_ALIASES',
  'WS_RECONNECT_INTERVAL_MS',
  'CONNECTION',
  'REALM',
  'WSFED_ISSUER',
  'MAX_HEADER_SIZE',
  'ENABLE_WRITE_BACK',
  'ENABLE_ACTIVE_DIRECTORY_UNICODE_PASSWORD',
  'SERVER_URL',
  'PORT',
  'HTTP_PROXY',
  'SSL_PFX',
  'SSL_KEY_PASSWORD',
  'SSL_OPENSSLDIR_PATTERN',
  'SSL_CA_PATH',
  'SSL_CA_FILE',
  'CA_CERT',
  'CLIENT_CERT_AUTH',
  'PROVISIONING_TICKET',
  'AGENT_MODE',
  'FIREWALL_RULE_CREATED',
  'SITE_NAME',
  'OVERRIDE_CONFIG',
  'TENANT_SIGNING_KEY',
  'KERBEROS_AUTH',
  'KERBEROS_DEBUG_USER',
  'SESSION_SECRET',
  'PROFILE_MAPPER',
  'PROFILE_MAPPER_FILE',
  'AUTO_UNLOCK_ON_PASSWORD_CHANGE',
];
const CONFIG_PATH = __dirname + '/../config.json';

async function initialize() {
  if (process.env.OVERRIDE_CONFIG === 'false') {
    nconf.use('memory')
      .overrides({ OVERRIDE_CONFIG: false })
      .env('||')
      .defaults(defaults);
  } else {
    // load configuration from disk and environment, allowing environment variables to override disk configuration,
    // and both to override defaults
    nconf.env('||')
      .file({
        file: CONFIG_PATH,
        logicalSeparator: '||',
        format: {
          parse: function (content) {
            return JSON.parse(content);
          },
          stringify: function (content){
            var result = JSON.stringify(content, null, 2);
            if (process.platform === 'win32') {
              result = result.replace(/\n/ig, '\r\n');
            }
            return result;
          }
        }
      })
      .defaults(defaults);
  }
}

function get(key) {
  return nconf.get(key);
}

function set(key, value) {
  nconf.set(key, value);
}

function clear(key) {
  nconf.clear(key);
}

/**
 * Persists the current configuration to disk.
 * Only keys in the allow list will be persisted, and only if OVERRIDE_CONFIG is true.
 * This is a no-op if OVERRIDE_CONFIG is false.
 */
async function save() {
  if (!get('OVERRIDE_CONFIG')) {
    return;
  }

  const configToSave = {};
  for (const key of CONFIG_ALLOW_LIST) {
    if (nconf.stores.file.get(key) !== undefined) {
      configToSave[key] = nconf.stores.file.get(key);
    }
  }

  fs.writeFileSync(CONFIG_PATH, JSON.stringify(configToSave, null, 2));

  // Setup permissions for config.json so that only admins can read/write it.
  if (process.platform !== 'win32') {
    await execAsync(`chmod 600 ${CONFIG_PATH}`);
  } else {
    // On windows, we use powershell to set the ACL so that only administrators have access to the file
    const commands = [
      `$sddl = 'D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)'`,
      `$acl = Get-Acl -Path '${CONFIG_PATH}'`,
      '$acl.SetSecurityDescriptorSddlForm($sddl)',
      `Set-Acl -Path '${CONFIG_PATH}' -AclObject $acl`
    ];
    await execAsync('powershell -Command "' + commands.join(';') + '"');
  }
}

module.exports = {
  initialize,
  get,
  set,
  clear,
  save
};
