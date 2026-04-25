require('colors');

const config = require('../lib/config');
const program = require('commander');
const async = require('async');
const axios = require('axios');
const urlJoin = require('url-join');
const cas = require('../lib/add_certs');
const firewall = require('../lib/firewall');
const createConnection = require('../lib/ldap').createConnection;
const path = require('path');

//steps
const certificate = require('./steps/certificate');
const configureConnection = require('./steps/configureConnection');
const adLdapSettings = require('./steps/ad-ldap-settings');

program.version(require('../package.json').version).parse(process.argv);

exports.run = function (workingPath, callback) {
  var provisioningTicket, info;

  var emptyVars = ['LDAP_URL', 'LDAP_BASE', 'LDAP_BIND_USER'];

  if (!config.get('LDAP_BIND_CREDENTIALS')) {
    emptyVars.concat(['LDAP_BIND_PASSWORD']);
  }

  async.series(
    [
      function (cb) {
        provisioningTicket = config.get('PROVISIONING_TICKET');

        if (provisioningTicket) return cb();

        program.prompt('Please enter the ticket number: ', function (pt) {
          provisioningTicket = pt;
          cb();
        });
      },
      function (cb) {
        cas.inject(cb);
      },
      function (cb) {
        var info_url = urlJoin(provisioningTicket, '/info');
        console.log('Loading settings from ticket: ' + info_url);

        axios
          .get(info_url)
          .then((response) => {
            if (!~(response.headers['content-type'] || '').indexOf('application/json')) {
              var message =
                'Unexpected response from ticket information endpoint. ' +
                'Status code: ' + response.status +
                ' Content-Type: ' + response.headers['content-type'] + '.';
              return cb(new Error(message));
            }

            info = response.data;

            cb();
          })
          .catch((err) => {
            if (err) {

              if (err.response && err.response.status === 404) {
                return cb(
                  new Error('Wrong ticket. Does this connection still exist?')
                );
              }

              if (err.response && err.response.status !== 200) {
                var message =
                'Unexpected response from ticket information endpoint. ' +
                'Status code: ' + err.response.status +
                ' Content-Type: ' + err.response.headers['content-type'] + '.';
                return cb(new Error(message));
              }

              switch (err.code) {
              case 'ECONNREFUSED':
                console.log('Unable to reach Auth0 at ' + provisioningTicket);
                break;
              case 'UNABLE_TO_VERIFY_LEAF_SIGNATURE':
              case 'CERT_UNTRUSTED':
                console.error(
                  'The Auth0 server is using a certificate issued by an untrusted Certification Authority.',
                  err
                );
                console.log(
                  'Go to https://auth0.com/docs/connector/ca-certificates for instructions on how to install your CA certificate.'
                );
                break;
              case 'DEPTH_ZERO_SELF_SIGNED_CERT':
                console.error(
                  'The Auth0 server is using a self-signed certificate',
                  err
                );
                console.log(
                  'Go to https://auth0.com/docs/connector/ca-certificates for instructions on how to install your certificate.'
                );
                break;
              default:
                console.error(
                  'Unexpected error while configuring connection:',
                  err
                );
              }
              return cb(err);
            }
          });
      },
      function (cb) {
        var ldap_url = config.get('LDAP_URL');
        var ldap_base = config.get('LDAP_BASE');

        if (ldap_url) return cb();

        adLdapSettings.discoverSettings(
          info.connectionDomain,
          function (config) {
            var detectedUrl = '';
            var detectedDN = '';
            if (config) {
              detectedUrl = config.LDAP_URL || '';
              detectedDN = config.LDAP_BASE || '';
            }

            if (console.restore) console.restore();

            program.prompt(
              'Please enter your LDAP server URL [' + detectedUrl + ']: ',
              function (url) {
                ldap_url = url && url.length > 0 ? url : detectedUrl;

                program.prompt(
                  'Please enter the LDAP server base DN [' + detectedDN + ']: ',
                  function (dn) {
                    ldap_base = dn && dn.length > 0 ? dn : detectedDN;

                    config.set('LDAP_BASE', ldap_base);
                    config.set('LDAP_URL', ldap_url);
                    config.save();

                    if (console.inject) console.inject();

                    cb();
                  }
                );
              }
            );
          }
        );
      },
      function (cb) {
        function anonymousSearchEnabled(enabled) {
          config.set('ANONYMOUS_SEARCH_ENABLED', enabled);
          console.log(
            'Is Anonymous LDAP search enabled? ' + (enabled ? 'yes' : 'no')
          );
          connection.destroy();
          return cb();
        }
        const searchOpts = {
          filter: '(objectclass=person)',
          scope: 'sub',
          sizeLimit: 1,
        };
        const connection = createConnection();
        connection.search(
          config.get('LDAP_BASE'),
          searchOpts,
          function (err, res) {
            if (err) {
              return anonymousSearchEnabled(false);
            }

            var searchEntry;
            res
              .once('searchEntry', function (entry) {
                searchEntry = entry;
              })
              .once('end', function (result) {
                const isEnabled = searchEntry && result.status === 0;
                anonymousSearchEnabled(isEnabled);
              })
              .once('error', function (err) {
                // if there are more than one entry matching the search, the server returns the one entry and a SizeLimitExceededError error
                anonymousSearchEnabled(err.name === 'SizeLimitExceededError');
              });
          }
        );
      },
      function (cb) {
        var do_not_configure_firewall =
          config.get('FIREWALL_RULE_CREATED') ||
          !info.kerberos ||
          process.platform !== 'win32';

        if (do_not_configure_firewall) {
          return cb();
        }

        // add a firewall rule the first time
        firewall.add_rule({
          name: 'Auth0ConnectorKerberos',
          program: path.resolve(
            path.join(
              __dirname,
              '/../node_modules/kerberos-server/kerberosproxy.net/KerberosProxy/bin/Debug/KerberosProxy.exe'
            )
          ),
          profile: 'private',
        });

        console.log('Firewall rule added.');

        cb();
      },
      function (cb) {
        config.set('AD_HUB', info.adHub);
        config.set('PROVISIONING_TICKET', provisioningTicket);
        config.set('WSFED_ISSUER', info.connectionDomain);
        config.set('CONNECTION', info.connectionName);
        config.set('CLIENT_CERT_AUTH', info.certAuth);
        config.set('KERBEROS_AUTH', info.kerberos);
        config.set('FIREWALL_RULE_CREATED', info.kerberos);
        config.set('REALM', info.realm.name);
        config.set('SITE_NAME', config.get('SITE_NAME') || info.connectionName);
        config.set(info.realm.name, info.realm.postTokenUrl);
        emptyVars.forEach(function (ev) {
          if (!config.get(ev)) config.set(ev, '');
        });

        config.save(cb);
        console.log('Local settings updated.');
      },
      function (cb) {
        certificate(workingPath, info, cb);
      },
      function (cb) {
        configureConnection(program, workingPath, info, provisioningTicket, cb);
      },
      function (cb) {
        console.log('Connector setup complete.');
        if (config.get('OVERRIDE_CONFIG')) {
          return config.save(cb);
        }
        cb();
      },
    ],
    function (err) {
      if (err) return callback(err);
      callback();
    }
  );
};
