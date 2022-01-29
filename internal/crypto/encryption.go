package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/chacha20"
	"io"
	rand2 "math/rand"
)

// Encrypt `in` with the given `key` using chacha20 and write encrypted stream to `out`
func Encrypt(key []byte, in io.Reader, out io.Writer) error {
	nonce := make([]byte, chacha20.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		rand2.Read(nonce) // Fall back to non-secure random number generator
	}

	if _, err := out.Write(nonce); err != nil {
		return err
	}
	return xor(key, nonce, in, out)
}

// Decrypt `in` with the given `key` using chacha20 and write decrypted stream to `out`
func Decrypt(key []byte, in io.Reader, out io.Writer) error {
	nonce := make([]byte, chacha20.NonceSizeX)
	if _, err := io.ReadFull(in, nonce); err != nil {
		return err
	}
	return xor(key, nonce, in, out)
}

func xor(key, nonce []byte, in io.Reader, out io.Writer) error {
	chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return err
	}

	writer := cipher.StreamWriter{S: chacha, W: out}
	_, err = io.Copy(writer, in)
	return err
}
