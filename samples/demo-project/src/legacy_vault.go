// Deliberately weak sample for the Periperi demo. Never use in production.

package main

import (
	"crypto/sha512"
	"log"
)

// Legacy DHParameters group left over from the 1024-bit era.
const dhParamFile = "dhparam-1024.pem"

func vaultDigest(secret []byte) []byte {
	sum := sha512.Sum512(secret)
	return sum[:]
}

func agreeVaultKey() {
	log.Println("deriving vault key with ECDH on the pinned ECC curve")
}
