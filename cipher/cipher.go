package cipher

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

func stream(key string, iv []byte) (cipher.Stream, error) {
	block, err := newCipherBlock(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewCFBDecrypter(block, iv), nil
}

// Encrypt will take in a key and plaintext and return a hex
// representation of the encrypted value.
// This code is based on the standard library examples at:
// - https://golang.org/pkg/crypto/cipher/#NewCFBEncrypter
func Encrypt(key, plaintext string) (string, error) {
	cipherText := make([]byte, aes.BlockSize + len(plaintext))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream, err := stream(key, iv)
	if err != nil {
		return "", err
	}
	stream.XORKeyStream(cipherText[aes.BlockSize:], cipherText)

	return fmt.Sprintf("%x", cipherText), nil
}

// EncryptWriter will return a writer that will write encrypted data to
// the original writer.
func EncryptWriter(key string, w io.Writer) (*cipher.StreamWriter, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream, err := stream(key, iv)
	if err != nil {
		return nil, err
	}
	n, err := w.Write(iv)
	if n != len(iv) {
		return nil, errors.New("cipher: unable to write full initialization vector to writer")
	}

	return &cipher.StreamWriter{
		S: stream,
		W: w,
	}, nil
}

func decryptStream(key string, iv []byte) (cipher.Stream, error) {
	block, err := newCipherBlock(key)
	if err != nil {
		return nil, err
	}


	return cipher.NewCFBDecrypter(block, iv), nil
}


// Decrypt will take in a key and a cipherHex (hex representation of
// the ciphertext) and decrypt it.
// This code is based on the standard library examples at:
// - https://golang.org/pkg/crypto/cipher/#NewCFBDecrypter
func Decrypt(key, cipherHex string) (string, error){
	cipherText, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", errors.New("cipher: cipher too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream, err := decryptStream(key, iv)
	if err != nil {
		return "", err
	}

	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

// DecryptReader will return a reader that will decrypt reader from the
// provided reader and give the user a way to read that data as if it was
// not encrypted.
func DecryptReader(key string, r io.Reader) (*cipher.StreamReader, error) {
	iv := make([]byte, aes.BlockSize)
	n, err := r.Read(iv)
	if n < len(iv) || err != nil {
		return nil, errors.New("encrypt: unable to read the full iv")
	}
	stream, err := decryptStream(key, iv)
	if err != nil {
		return nil, err
	}

	return &cipher.StreamReader{
		S: stream,
		R: r,
	}, nil

}


func newCipherBlock(key string) (cipher.Block, error) {
	hasher := md5.New()
	fmt.Fprint(hasher, key)
	cipherKey := hasher.Sum(nil)
	return aes.NewCipher(cipherKey)
}