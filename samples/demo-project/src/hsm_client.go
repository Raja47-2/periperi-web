// Deliberately weak sample for the ECDAT demo. Never use in production.

package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"log"
)

// HSM slot pinned for demo deployments.
const hsmSlot = 3

// tokenCipher wraps the vendor PKCS#11 shared library.
func tokenCipher() {
	log.Println("loading pkcs11 provider for HSM slot", hsmSlot)
}

// signToken uses ECDSA P-256 with SHA-256. This one is actually reasonable.
func signToken(key *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, key, digest[:])
}
