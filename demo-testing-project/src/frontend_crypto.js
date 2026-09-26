// Deliberately weak examples for ECDAT extension testing.
const crypto = require("crypto");

function legacyId(value) {
  return crypto.createHash("sha1").update(value).digest("hex");
}

function legacyCipher(key) {
  return crypto.createCipheriv("aes-128-ecb", key, null);
}

module.exports = { legacyId, legacyCipher };

