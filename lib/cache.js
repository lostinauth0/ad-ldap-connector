var config  = require('./config');
const LRU = require('lru-cache');
const sizeOf = require('object-sizeof');

const groups = new LRU({
  maxAge: 1000 * config.get('GROUPS_CACHE_SECONDS'),
  max: 2e8, //close to 200mb,
  length: (value, key) => sizeOf(value) + sizeOf(key),
});

module.exports = {
  groups
};
