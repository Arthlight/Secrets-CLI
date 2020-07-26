package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Encrypt will take in a key and plaintext and return a hex
// representation of the encrypted value.
// This code is based on the standard library examples at:
// - https://golang.org/pkg/crypto/cipher/#NewCFBEncrypter
func Encrypt(key, plaintext string) (string, error) {
	block, err := newCipherBlock(key)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize + len(plaintext))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], cipherText)

	return fmt.Sprintf("%x", cipherText), nil
}

// Decrypt will take in a key and a cipherHex (hex representation of
// the ciphertext) and decrypt it.
// This code is based on the standard library examples at:
// - https://golang.org/pkg/crypto/cipher/#NewCFBDecrypter
func Decrypt(key, cipherHex string) (string, error){
	block, err := newCipherBlock(key)
	if err != nil {
		return "", err
	}

	cipherText, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", errors.New("encrypt: cipher too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil

}


func newCipherBlock(key string) (cipher.Block, error) {
	hasher := md5.New()
	fmt.Fprint(hasher, key)
	cipherKey := hasher.Sum(nil)
	return aes.NewCipher(cipherKey)
}