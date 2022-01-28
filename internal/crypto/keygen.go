package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	rand2 "math/rand"
)

// GenerateSecret generates a new secret using the `storedPub` and generated `recoveryPriv`
func GenerateSecret(storedPub []byte) ([]byte, []byte, error) {
	recoveryPriv, recoveryPub := newKeyPair()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		rand2.Read(salt) // Fall back to non-secure random number generator
	}

	secret, err := exchange(recoveryPriv, storedPub, salt)
	return secret, append(salt, recoveryPub...), err
}

// RecoverSecret regenerates a secret using the `storedPriv` and `recoveryPub`
func RecoverSecret(storedPriv, recoveryKey []byte) ([]byte, error) {
	return exchange(storedPriv, recoveryKey[16:], recoveryKey[:16])
}

// exchange calculates the shared secret between a private and public X25519 key
func exchange(privKey, pubKey, salt []byte) ([]byte, error) {
	key, err := curve25519.X25519(privKey, pubKey)
	if err != nil {
		return nil, err
	}

	secret := make([]byte, 32)
	_, err = hkdf.New(sha256.New, key, salt, nil).Read(secret)
	return secret, err
}

// newKeyPair generates a new random X25519 keypair
func newKeyPair() (privKey, pubKey []byte) {
	privKey = make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privKey); err != nil {
		rand2.Read(privKey) // Fall back to non-secure random number generator
	}

	pubKey = make([]byte, curve25519.PointSize)
	curve25519.ScalarBaseMult((*[curve25519.PointSize]byte)(pubKey), (*[curve25519.ScalarSize]byte)(privKey))
	return
}
