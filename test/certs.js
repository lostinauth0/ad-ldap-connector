const tls = require('tls');
const expect = require('chai').expect;

describe('Connection to server with empty subject', function () {

  const PORT=19876;
  const cert = {
    publicKey: '-----BEGIN CERTIFICATE-----\r\nMIIC8DCCAdigAwIBAgIJNJq/RDQuR8/QMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV\r\nBAMTCWxvY2FsaG9zdDAeFw0yNTEyMTgxNjIwMDVaFw0zNTEyMTYxNjIwMDVaMBQx\r\nEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\r\nggEBALNRDCo/BMqGSTln312mjdyFACfK/vsmfpDKaoLT3N7PMmCO3ObXPts/o2iZ\r\nKhec8YioQb2IeNHGeq2+bocNf3bmoFei/L++vAXaC1onJ1OnBp0LDwrkh/IG2Mif\r\nM3pBE6QjWS3bvDJQ22GCzdWzolVQMBlHpuW0bV+j3I2c4aUTS7/AN5UstivNRsQm\r\nofq6IWrKHoqfko/b2mH+61Y/o4L3KlP3eXrFRBUo7VEkSWwZhyCncKEtm4LWC3ng\r\nwGdyGtcNIAbHbmyvbzBkwZcXXyUXZcjEjQTFvYxvKlkfFnreTzVVLgNIbbWw3Za3\r\nbiy4r9BZy8g5cGmE3u/ka/eiZ0ECAwEAAaNFMEMwDAYDVR0TBAUwAwEB/zALBgNV\r\nHQ8EBAMCAvQwJgYDVR0RBB8wHYYbaHR0cDovL2V4YW1wbGUub3JnL3dlYmlkI21l\r\nMA0GCSqGSIb3DQEBCwUAA4IBAQBVoqEOVVBHeQs4bgZRTqnWu7eSIX4HTiDOn6Fk\r\nxIjzjpce8as/5yYQMbSyNex6Edr4jDhfXdFmud1b5meLANzSU105weUHIoQCXv/X\r\n/1xiSHJpxyCvrModg64N4s1LUWte06W74t9EKqZPIys+2SzTg/oTBFjs6IWVSaCc\r\nAAsz8ITTlufkA5XS9PQYUh33bcFlNv6wO8ucNlZMzhvww43CMrcuAg1pW4+npfl9\r\nYwl6fiviBwq5cIadYlf3yz0MDul28oR/jPQd8bciUNiKdynW8F/0UvRBA3ou4Aks\r\nIjkj9Mbx6kB4+/F3Y50kLlE1p8wdE5GH9UIRU+amJ1zVkHCn\r\n-----END CERTIFICATE-----\r\n',
    privateKey: '-----BEGIN RSA PRIVATE KEY-----\r\nMIIEowIBAAKCAQEAs1EMKj8EyoZJOWffXaaN3IUAJ8r++yZ+kMpqgtPc3s8yYI7c\r\n5tc+2z+jaJkqF5zxiKhBvYh40cZ6rb5uhw1/duagV6L8v768BdoLWicnU6cGnQsP\r\nCuSH8gbYyJ8zekETpCNZLdu8MlDbYYLN1bOiVVAwGUem5bRtX6PcjZzhpRNLv8A3\r\nlSy2K81GxCah+rohasoeip+Sj9vaYf7rVj+jgvcqU/d5esVEFSjtUSRJbBmHIKdw\r\noS2bgtYLeeDAZ3Ia1w0gBsdubK9vMGTBlxdfJRdlyMSNBMW9jG8qWR8Wet5PNVUu\r\nA0httbDdlrduLLiv0FnLyDlwaYTe7+Rr96JnQQIDAQABAoIBAAYOlJOn57PRFnpa\r\nopIq4PNsJ9cQQu24F/Hwr77DT1xp1odp2qGZWfF6jEd0AVav7xMuWXPLNIc5IMtL\r\nXvekyl5OwudZlVdt5t3nkXcDkqR0rv3L7LTxxvtIhVb9KgDvn41C7JKxWkwp9x0W\r\nN7kdGBxxCNeObWoTKVd1OnXAm7kcDSX7zfyEkt49x3gg1B4IUF8TZkTyq6v8olWt\r\nVeyV6G1lGJUd5ULiCe44pJYJlvyjCUENWxm5/wEAXnpoqPYjmLjPbnAJG3m8vbM9\r\nrehpVjQCTk4Q84m7CJrcUj9Iur9IuYsJOw+hssXuBVc+SdO9C8mS8TEsO+cOQtNK\r\n7ubAnekCgYEA1ifQbOFVNSonw6tOMAwwJjrLqMOX6Uvho0UiVnEHzDui+IViLSIU\r\njPC13S6TjPcnYMrTRbSaqO7SElPWJE2yO80xdFo2lA2u5Jq1nQkYFvmj1JoI8Tel\r\nRoR2vao/p8oXbH/VpWYzC5bLOzqTY/mbFK+kicywPOPHHq7fqwrF6ckCgYEA1lqR\r\nw1TeKWnrljLQ96GYm1FTX9tNpmKaFWLVvMILI3n6U/vZsOx3eXDaJH3OgsXdTaEV\r\n0iEvbK2isN0X3ucibf5lgfqcLNP/iqFR+aBLI+AqsK0k+e2axsn0qc669nCAepwV\r\nNnSbfLuRqRgwu7B7ifNVv8n2aGQLy356H5JzTbkCgYA2U1lDFZJY7z2xHFa0R5M7\r\nT3T0ddGmg/JUSahhR0EUJRi9dJCoJFoUOsfXuQYDH3tkyW744szNB/BQZ+YNxYvu\r\nMapW+r+XpTT1lu11TaZHxcIyn3SfRF9v2RCKIpMNTG3Ov0sCLz/Js9IQT1auaNZX\r\nVAsoTb1zZNDRTsk8iXoVSQKBgA+Wmo8X9ugQGd/cZjH8AHsbGPMZobX96bKwc1a8\r\nzc6QqlG9OQGS0MV2HYcV1xTPit6AXnPfkfFXV0OBcKD3MhvJqlwfe4gPCsBsJuf+\r\nbjh3ruMWVGAQlXbrbO2EaThOyikgfLJvHHeftGIVrkWX+gP4PD4sU80XqXvtALiX\r\nD+eRAoGBAJarGFRL4LYfIM61R9tWE6gYHx2e16jk35jpbiPBZARcqshrLhSFO3MM\r\nOnYds+/6ysIk/NwtXHeaoLvQ4EfN+fQQzjLveR+uyYIZRnnU/phWyyKsFZCZG5Oj\r\noxhQMfFfFNE8ftUA0uKHGrF2nqbYsubDxFTvgBKIE08WIAS7rJzz\r\n-----END RSA PRIVATE KEY-----\r\n',
    ca : '-----BEGIN CERTIFICATE-----\r\nMIIC8DCCAdigAwIBAgIJNJq/RDQuR8/QMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV\r\nBAMTCWxvY2FsaG9zdDAeFw0yNTEyMTgxNjIwMDVaFw0zNTEyMTYxNjIwMDVaMBQx\r\nEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\r\nggEBALNRDCo/BMqGSTln312mjdyFACfK/vsmfpDKaoLT3N7PMmCO3ObXPts/o2iZ\r\nKhec8YioQb2IeNHGeq2+bocNf3bmoFei/L++vAXaC1onJ1OnBp0LDwrkh/IG2Mif\r\nM3pBE6QjWS3bvDJQ22GCzdWzolVQMBlHpuW0bV+j3I2c4aUTS7/AN5UstivNRsQm\r\nofq6IWrKHoqfko/b2mH+61Y/o4L3KlP3eXrFRBUo7VEkSWwZhyCncKEtm4LWC3ng\r\nwGdyGtcNIAbHbmyvbzBkwZcXXyUXZcjEjQTFvYxvKlkfFnreTzVVLgNIbbWw3Za3\r\nbiy4r9BZy8g5cGmE3u/ka/eiZ0ECAwEAAaNFMEMwDAYDVR0TBAUwAwEB/zALBgNV\r\nHQ8EBAMCAvQwJgYDVR0RBB8wHYYbaHR0cDovL2V4YW1wbGUub3JnL3dlYmlkI21l\r\nMA0GCSqGSIb3DQEBCwUAA4IBAQBVoqEOVVBHeQs4bgZRTqnWu7eSIX4HTiDOn6Fk\r\nxIjzjpce8as/5yYQMbSyNex6Edr4jDhfXdFmud1b5meLANzSU105weUHIoQCXv/X\r\n/1xiSHJpxyCvrModg64N4s1LUWte06W74t9EKqZPIys+2SzTg/oTBFjs6IWVSaCc\r\nAAsz8ITTlufkA5XS9PQYUh33bcFlNv6wO8ucNlZMzhvww43CMrcuAg1pW4+npfl9\r\nYwl6fiviBwq5cIadYlf3yz0MDul28oR/jPQd8bciUNiKdynW8F/0UvRBA3ou4Aks\r\nIjkj9Mbx6kB4+/F3Y50kLlE1p8wdE5GH9UIRU+amJ1zVkHCn\r\n-----END CERTIFICATE-----\r\n'
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
