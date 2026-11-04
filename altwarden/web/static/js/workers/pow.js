// Solves the proof-of-work puzzle off the main thread, so the page stays responsive.
// Finds a counter so SHA-256(salt + counter) starts with `bits` zero bits. FIPS 180-4.
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const W = new Uint32Array(64);
const rotr = (x, n) => (x >>> n) | (x << (32 - n));

// Hashes one short message (under 56 bytes) and returns the first 32 bits of the digest.
function firstWord(bytes, length) {
  W.fill(0);
  for (let i = 0; i < length; i++) W[i >> 2] |= bytes[i] << (24 - (i & 3) * 8);
  W[length >> 2] |= 0x80 << (24 - (length & 3) * 8);
  W[15] = length * 8;
  for (let i = 16; i < 64; i++) {
    const a = W[i - 15], b = W[i - 2];
    W[i] = (W[i - 16] + (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) + W[i - 7] + (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10))) | 0;
  }
  let a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a, e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;
  for (let i = 0; i < 64; i++) {
    const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
    const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  return (a + 0x6a09e667) >>> 0;
}

self.onmessage = ({ data: { salt, bits } }) => {
  const encoder = new TextEncoder();
  const prefix = encoder.encode(salt);
  const bytes = new Uint8Array(64);
  bytes.set(prefix);
  const mask = bits >= 32 ? 0xffffffff : (0xffffffff << (32 - bits)) >>> 0;
  for (let counter = 0; counter < 0xffffffff; counter++) {
    const digits = String(counter);
    for (let i = 0; i < digits.length; i++) bytes[prefix.length + i] = digits.charCodeAt(i);
    if ((firstWord(bytes, prefix.length + digits.length) & mask) >>> 0 === 0) {
      self.postMessage({ counter });
      return;
    }
  }
  self.postMessage({ counter: -1 });
};
