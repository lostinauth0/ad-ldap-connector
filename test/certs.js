const tls = require('tls');
const expect = require('chai').expect;

describe('Connection to server with empty subject', function () {

  const PORT=19876;
  const cert = {
    publicKey: '-----BEGIN CERTIFICATE-----\n' +
      'MIIDcTCCAlmgAwIBAgIUXHdhNV2GR2v/mrSnQJ1P0qDW4QcwDQYJKoZIhvcNAQEL\n' +
      'BQAweDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcM\n' +
      'CEJlbGxldnVlMQ4wDAYDVQQKDAVBdXRoMDEfMB0GA1UECwwWQUQgTERBUCBDb25u\n' +
      'ZWN0b3IgVGVzdDEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjA0MjExNTQzNDJaFw0z\n' +
      'NjA0MTgxNTQzNDJaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ\n' +
      'NsRDDje9QcR37ypKbVUnxWAGhg7bLI6bCx3XwrJyPEie3fZuxvJQXqroPk8oy/AB\n' +
      'qsQYqQ+i8BJhaE5dh1gOYc4goT0IhJEzt3XuxlP6KZLKtbfxGDoLbqj0Er2gIwxL\n' +
      'BpcAwgl2M68PYXYDm/yh5ZDZNVf734FTlqHEq1UzLJCGbFCvJS0efl+thJlyxNmh\n' +
      'ieJs7YjiZ5l5heH1DlvJoBhcJnd6LnGhCjeH/n8UOUjNEhmzEXtDj0PWKC7z3Kyw\n' +
      'xl0urArufxjLyIQdNg1xGDhkSqY/rS5L01xcJDfZ6DitBTVspYyPmqmBxtTCCq6z\n' +
      'zf8eCfQjFP0D6B0T4PtJAgMBAAGjazBpMAsGA1UdDwQEAwIFoDAaBgNVHREEEzAR\n' +
      'hwR/AAABgglsb2NhbGhvc3QwHQYDVR0OBBYEFLq/C8saQ2mzr4GdUclJ/6HRUrQw\n' +
      'MB8GA1UdIwQYMBaAFN9+sorZtY7S3BeKw8+eZgqy79iWMA0GCSqGSIb3DQEBCwUA\n' +
      'A4IBAQBPntjkH4YP5+9VHsZYn6NUW1vmNIOtjZ+1A6Fg+LSn2IsbldSxg+b3f9jF\n' +
      'B9UU4qOanE5YYcE4fLRUwZElPV0k24m08T84Llk7+xq7NgZS8JQr4TVCcae3Nv8x\n' +
      '2Xb3RN/Lh/tsq3eZFBfIRvRp8yYhgqjvMef6520iDq7vqxLrR+Pq68nIcI7E2IY9\n' +
      'EZbSmwKN2pT2TmxGzPCBLyslN6XaG9dgXxa7IjEUlLGVj5yDLVG23yeJnoXgYfEo\n' +
      'cKDMtsvCS3NSZPzW7jJioBoDNFMUICJjTm33JljPm2kqZqVwoRAn3Z9LruCDMVcb\n' +
      '3j0nyvkCunCvR/JCqvSdaIOF9f7M\n' +
      '-----END CERTIFICATE-----',
    privateKey: '-----BEGIN PRIVATE KEY-----\n' +
      'MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDJNsRDDje9QcR3\n' +
      '7ypKbVUnxWAGhg7bLI6bCx3XwrJyPEie3fZuxvJQXqroPk8oy/ABqsQYqQ+i8BJh\n' +
      'aE5dh1gOYc4goT0IhJEzt3XuxlP6KZLKtbfxGDoLbqj0Er2gIwxLBpcAwgl2M68P\n' +
      'YXYDm/yh5ZDZNVf734FTlqHEq1UzLJCGbFCvJS0efl+thJlyxNmhieJs7YjiZ5l5\n' +
      'heH1DlvJoBhcJnd6LnGhCjeH/n8UOUjNEhmzEXtDj0PWKC7z3Kywxl0urArufxjL\n' +
      'yIQdNg1xGDhkSqY/rS5L01xcJDfZ6DitBTVspYyPmqmBxtTCCq6zzf8eCfQjFP0D\n' +
      '6B0T4PtJAgMBAAECggEAGACYN16IECO7BcqKGzBBHvoouwZ9WbBOP5j7IZyIUF+4\n' +
      'Evlr1umVCLjOPt+F7lorgmtmMoHiS1/DdYqthHMrciXBIrvRLcWwk4CASTAv3tDc\n' +
      'QaGdNF2dOPVlop3ksGhV5FJAK5c57Td7m8RWwVX3dDGQDpUSLonKIdg/alg81Np2\n' +
      '3dBpa1T+Rxwk22Di3zfPH2QFkaL5IAJbe3LLD5wZH1CldCR9TRCD1W8bhDinq5fU\n' +
      '7etVuHVUbUXYq4NFuaJvNLTyhbZMAQEZRggyLO0W2yHWRL093CghVYZ9wS0Fs5KJ\n' +
      'WkzcoBq6a4F4HvccSDpJIj5tfkO91lVsIq4DlysiLQKBgQD8EqPCj4PmsWtLVtea\n' +
      'MvyJjrz7+Ta1NpfpAAuBPCEQRB5cxPjFtKLsdmZ0C2lMXgBvKaksBfQANUBHHZ4y\n' +
      'Zri0qoqzmJ5Jp8EGNO/CP4XYCh5UciNk34yQsLWKvhLoKxLqpnhrf09Jr8UIgQiq\n' +
      'wT89T07ia1HYZFPPjZutStuupQKBgQDMWUhlZVt1AP2hxI4gMkbp/UxEXtqFBA3b\n' +
      'n6znktR3R/wQIZkBQKrzlFywp7Y78jy61R4qLEyIQeH6RxenfyUBbQ8Dkzokru29\n' +
      '3v7NJJlqlSqN4PYby2uDpDWPBeNOocjKQtQL5zffRQ5VKDoXZG4rppvSlFbuaf3E\n' +
      'Uc50N2I81QKBgD3yrsAf2QCW1ZF8VBwXL6z2oUcjZeh+9DJUyn8GMfH3a6bM2X5s\n' +
      '+CU4q9EVBNm5uE2ZZXPmOqLac2OGydwFFpt/1fpxJWVgjrVhyRJp3hDL28xRCJW/\n' +
      'wqHEa7kfITJhc5KrOqjgbrHjOn7uhxy/xTTiCrbmPQT7EwXM/VdHMFnpAoGAEYef\n' +
      'NEOLou/g0h3Aa3akqrH19u+EI2EDp1F9TahE3a6pKuEW9QqNH7Qcd3MLqPzQxN4/\n' +
      'ZjLCpfWw4v1yRAYeMI8geJgKptbywhT9GrAHESOWsPEZa6z5niNaDNjedQJf7Snq\n' +
      'ctL08gxEfH2k7hjJcqkqONhM1Mr23/58jW+q17kCgYBDfLxwNytkFIHISNTF3o69\n' +
      'bVr7l/I3UfXLjCQ+jOFDRql7VyWIqAjo8F6T4hGgAUSA7tpRULkzAGSohtVx7Ulu\n' +
      'FunX0O+lBeYRAmAtJAQ6yYQz1C01zk6UbxF3VSPjEcUJSMt3hCrcJ4c+nBigvN20\n' +
      '9z06CUm17wHk25cBkSTEFQ==\n' +
      '-----END PRIVATE KEY-----\n',
    ca : '-----BEGIN CERTIFICATE-----\n' +
      'MIID0TCCArmgAwIBAgIUIo+vwPQ8iNuFFF3iBDDJT6KHh+swDQYJKoZIhvcNAQEL\n' +
      'BQAweDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcM\n' +
      'CEJlbGxldnVlMQ4wDAYDVQQKDAVBdXRoMDEfMB0GA1UECwwWQUQgTERBUCBDb25u\n' +
      'ZWN0b3IgVGVzdDEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjA0MjExNTQzNDJaFw0z\n' +
      'NjA0MTgxNTQzNDJaMHgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9u\n' +
      'MREwDwYDVQQHDAhCZWxsZXZ1ZTEOMAwGA1UECgwFQXV0aDAxHzAdBgNVBAsMFkFE\n' +
      'IExEQVAgQ29ubmVjdG9yIFRlc3QxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqG\n' +
      'SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCI4PHmYPUlfDlz3awNPxkN6l0lwH92ncyt\n' +
      '1X5FvMe77E/JmH+SiQ+Z1m5uoHVuxzeREmwTw8lF7wBmJnsQKMMExm6QGcNQw2ID\n' +
      '6wlSeal9IQJo52cTezngui/O5X1Z6+xcsBLWy1/FH06G+h6t8O5tnJDczz2DrOf7\n' +
      'MDPd0hCRwwvYRTvLWvwSIsoXHFAfgjz8OUbGh3ZjT8Z/oby0jAJr1CfGVC6IzJ5C\n' +
      'GWVvL+REayBU2IsdbYDQAnIuFwZr/deEpr86JAvGaURiBcHIG/JpjdAFNXW7dqcp\n' +
      'CCMOBBQLdd3dLibSbBOwTaKr72++1CZbbMTGr1nMPAL8zsTtcWJHAgMBAAGjUzBR\n' +
      'MB0GA1UdDgQWBBTffrKK2bWO0twXisPPnmYKsu/YljAfBgNVHSMEGDAWgBTffrKK\n' +
      '2bWO0twXisPPnmYKsu/YljAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA\n' +
      'A4IBAQBGh3oUCAS9oj3QWS1UleP5Xa3YZh54F637TrReedcPf7P1+vvu5OSwznYU\n' +
      'WmYfhYw5oykyp7Pl+0oNFRueCuFiNUj9Kt7bveuTRYdFVM92Ei2wJqep3n/pZKCW\n' +
      'GjuOSoeqgxEzpFDR/rvWlDA1MxrQr40apWALS9+6R617CLOkNzG4lCyGMNbvjN+t\n' +
      'RcfZ7ldbHE8RqLfwGm1aC+7lnf+l3kmS9ORB5baK5RuLSHilvWS2eaa+LQeBoYES\n' +
      'LXWrULowk9wlbL0BQvQ7msViOHix1DiFMiKkhhdM9z24fB33iNA0oFwLwfUknk0V\n' +
      'BTxHz5T7JkIuQNIG9QhHuJIs2aEK\n' +
      '-----END CERTIFICATE-----'
  };

  var server;

  before(function(done) {
    server=tls.createServer({
      key: cert.privateKey,
      cert: cert.publicKey
    });
    server.on('connection', function(){});
    server.on('secureConnection', function(){});
    server.listen(PORT, done);
  });


  after(function(done) {
    if (server) {
      server.close(done);
    } else {
      done();
    }
  });

  it('should connect when using connector\'s server identity verification', function(done) {
    var socket = tls.connect(PORT, {
      ca: cert.ca,
      servername: 'localhost',
    }, function() {
      socket.end();
      done();
    });
    socket.on('error', done);
  });
});
