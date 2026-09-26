// Deliberately weak sample for the ECDAT demo. Never use in production.

import { createHash } from "crypto";
import sodium from "libsodium-wrappers";

const FIXED_NONCE = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

const SESSION_KEY = new Uint8Array(32);

/** ChaCha20-Poly1305 sealing with a nonce that never changes. */
export function seal(message: string): Uint8Array {
  return sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
    message,
    null,
    FIXED_NONCE,
    SESSION_KEY,
  );
}

export function fingerprint(sessionId: string): string {
  return createHash("sha256").update(sessionId).digest("hex");
}
