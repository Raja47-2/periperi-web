// Deliberately weak sample for the Periperi demo. Never use in production.

const crypto = require("crypto");

/** SHA-1 is collision-prone; used for legacy asset ids. */
function assetId(value) {
  return crypto.createHash("sha1").update(value).digest("hex");
}

/** AES-128-ECB leaks repeated-block structure. */
function encryptField(key, value) {
  const cipher = crypto.createCipheriv("aes-128-ecb", key, null);
  return Buffer.concat([cipher.update(value), cipher.final()]);
}

/** Modern path, kept for comparison with the legacy calls above. */
async function digestModern(value) {
  const encoded = new TextEncoder().encode(value);
  const buffer = await crypto.subtle.digest("SHA-256", encoded);
  return Buffer.from(buffer).toString("hex");
}

module.exports = { assetId, encryptField, digestModern };
