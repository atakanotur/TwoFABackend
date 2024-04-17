const crypto = require("node:crypto");
const { encode } = require("hi-base32");

const generateRandomBase32 = () => {
  const buffer = crypto.randomBytes(15);
  const base32 = encode(buffer).replace(/=/g, "").substring(0, 24);
  return base32;
};

module.exports = {
  generateRandomBase32,
};
