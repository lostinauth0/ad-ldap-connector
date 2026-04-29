require('colors');

const path = require('path');

const config = require('../lib/config');
const cas = require('../lib/add_certs');
const firewall = require('../lib/firewall');
const createConnection = require('../lib/ldap').createConnection;
const certificates = require('../lib/certificates');
const secureStorage = require('../lib/secureStorage');

const { input, password } = require('@inquirer/prompts');

const { loadProvisioningTicket } = require('../lib/provisioningTicket');
const { configureConnection } = require('./steps/configureConnection');
const adLdapSettings = require('../lib/adLdapSettings');

exports.run = async function() {

  // Inject CA certificates
  await cas.injectAsync();

  // Get provisioning ticket from user input if not already set
  let provisioningTicket = config.get('PROVISIONING_TICKET');
  if (!provisioningTicket) {
    provisioningTicket = await input({
      message: 'Please enter your provisioning ticket URL: ',
      required: true
    });
    config.set('PROVISIONING_TICKET', provisioningTicket);
  }

  // Load options / settings from the provisioning ticket
  const ticketInfo = await loadProvisioningTicket(provisioningTicket);

  // Discover AD/LDAP settings if not already set
  let ldapUrl = config.get('LDAP_URL');
  let ldapBase = config.get('LDAP_BASE');
  if (!ldapUrl || !ldapBase) {
    const discoveredSettings = await adLdapSettings.discoverSettings(ticketInfo.connectionDomain);
    ldapUrl = discoveredSettings.LDAP_URL || '';
    ldapBase = discoveredSettings.LDAP_BASE || '';

    ldapUrl = await input({
      message: 'Please enter your LDAP server URL: ',
      default: ldapUrl,
      prefill: 'tab',
      required: true
    });
    ldapBase = await input({
      message: 'Please enter the LDAP server base DN: ',
      default: ldapBase,
      prefill: 'tab',
      required: true
    });
    config.set('LDAP_URL', ldapUrl);
    config.set('LDAP_BASE', ldapBase);
  }

  // Inject winston into console
  if (console.inject) {
    console.inject();
  }

  // Check if Anonymous LDAP search is enabled
  const ldapClient = createConnection();
  const anonymousSearchEnabled = await adLdapSettings.isAnonymousSearchEnabled(ldapClient, ldapBase);
  config.set('ANONYMOUS_SEARCH_ENABLED', anonymousSearchEnabled);
  console.log(`Is Anonymous LDAP search enabled? ${anonymousSearchEnabled ? 'yes' : 'no'}`);

  // If anonymous search is not enabled, ask for LDAP bind user credentials if they aren't set already
  if (
    !anonymousSearchEnabled &&
    (!config.get('LDAP_BIND_USER') || !await secureStorage.get(secureStorage.keys.LDAP_BIND_PASSWORD))
  ) {
    const ldapBindUser = await input({
      message: 'Please enter the LDAP bind user (e.g. cn=admin,dc=example,dc=com): ',
      required: true
    });
    const ldapBindPassword = await password({
      message: 'Please enter the LDAP bind password: ',
      required: true
    });
    config.set('LDAP_BIND_USER', ldapBindUser.trim());
    await secureStorage.store(secureStorage.keys.LDAP_BIND_PASSWORD, ldapBindPassword);
  }

  // Add firewall rule on windows platforms with kerberos auth enabled
  const shouldConfigureFirewall = ticketInfo.kerberos && process.platform === 'win32';
  if (shouldConfigureFirewall) {
    console.log('Adding firewall rule for Kerberos Proxy.');
    await firewall.addRule({
      name: 'Auth0ConnectorKerberos',
      program: path.resolve(
        path.join(
          __dirname,
          '/../node_modules/kerberos-server/kerberosproxy.net/KerberosProxy/bin/Debug/KerberosProxy.exe'
        )
      ),
      profile: 'private'
    });
  }

  // Update config
  config.set('AD_HUB', ticketInfo.adHub);
  config.set('PROVISIONING_TICKET', provisioningTicket);
  config.set('WSFED_ISSUER', ticketInfo.connectionDomain);
  config.set('CONNECTION', ticketInfo.connectionName);
  config.set('CLIENT_CERT_AUTH', ticketInfo.certAuth);
  config.set('KERBEROS_AUTH', ticketInfo.kerberos);
  config.set('REALM', ticketInfo.realm.name);
  config.set('SITE_NAME', config.get('SITE_NAME') || ticketInfo.connectionName);
  config.set(ticketInfo.realm.name, ticketInfo.realm.postTokenUrl);

  // Save config to file
  await config.save();

  // Generate self-signed certificates if needed
  await certificates.initialize({
    connectionDomain: ticketInfo.connectionDomain,
    connectionName: ticketInfo.connectionName,
  });

  // Configure connection using the provisioning ticket
  await configureConnection({
    provisioningTicket,
    connectionName: ticketInfo.connectionName,
  });

  // Save config to file
  await config.save();
  console.log('Connector setup complete.');
};
