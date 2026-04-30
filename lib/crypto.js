const crypto = require('crypto');
const evp = require('evp_bytestokey'); // this is not a secure way to generate keys; it's only here for backwards compatibility.
const algorithm = 'aes256'; // or any other algorithm supported by OpenSSL
const KEY_LENGTH = 32; //in bytes
const IV_LENGTH = 16; //in bytes
const certificates = require('./certificates');

/**
 * v1 format: 
 * native crypto.createCipher() aes256
 * v2 format:
 *  $2$.[key derivation IV (scrypt 1 round in hex)].[cipherIV (aes256 in hex)].[cipher (hex)]
 */

exports.encrypt = async function (text) {
  var rawKey = certificates.getPrivateKey();
  var keyIv = crypto.randomBytes(IV_LENGTH);
  var cipherIv = crypto.randomBytes(IV_LENGTH);
  var key = crypto.scryptSync(rawKey, keyIv, KEY_LENGTH);
  var cipher = crypto.createCipheriv(algorithm, key, cipherIv);
  var encrypted = '$2$.' + keyIv.toString('hex') + '.' + cipherIv.toString('hex') + '.' + cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
};

exports.decrypt = async function (encrypted) {
  var rawKey = certificates.getPrivateKey();
  var key, iv, version;
  var cryptArray = encrypted.split('.');

  switch (cryptArray[0]) {
  case '$2$':
    version = 2;
    key = crypto.scryptSync(rawKey, Buffer.from(cryptArray[1], 'hex'), KEY_LENGTH);
    iv = Buffer.from(cryptArray[2], 'hex');
    break;
  default: //v1
    version = 1;
    var evpResult = evp(rawKey, null, KEY_LENGTH * 8, IV_LENGTH);
    key = evpResult.key;
    iv = evpResult.iv;
    break;
  }
  
  var decipher = crypto.createDecipheriv(algorithm, key, iv);
  var cryptoPayload = version === 2 ? cryptArray[3] : encrypted;
  var decrypted = decipher.update(cryptoPayload, 'hex', 'utf8') + decipher.final('utf8');
  return decrypted;
};
