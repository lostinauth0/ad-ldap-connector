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
  const rawKey = certificates.getPrivateKey();
  const keyIv = crypto.randomBytes(IV_LENGTH);
  const cipherIv = crypto.randomBytes(IV_LENGTH);
  const key = crypto.scryptSync(rawKey, keyIv, KEY_LENGTH);
  const cipher = crypto.createCipheriv(algorithm, key, cipherIv);
  const encrypted = '$2$.' + keyIv.toString('hex') + '.' + cipherIv.toString('hex') + '.' + cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
};

exports.decrypt = async function (encrypted) {
  const rawKey = certificates.getPrivateKey();
  const cryptArray = encrypted.split('.');
  let key, iv, version;

  switch (cryptArray[0]) {
  case '$2$':
    version = 2;
    key = crypto.scryptSync(rawKey, Buffer.from(cryptArray[1], 'hex'), KEY_LENGTH);
    iv = Buffer.from(cryptArray[2], 'hex');
    break;
  default: //v1
    version = 1;
    const evpResult = evp(rawKey, null, KEY_LENGTH * 8, IV_LENGTH);
    key = evpResult.key;
    iv = evpResult.iv;
    break;
  }

  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  const cryptoPayload = version === 2 ? cryptArray[3] : encrypted;
  const decrypted = decipher.update(cryptoPayload, 'hex', 'utf8') + decipher.final('utf8');
  return decrypted;
};
