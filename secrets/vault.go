package secrets

import (
	"Secrets-CLI/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

type Vault struct {
	encodingKey string
	filePath string
	sync.Mutex
	keyValues map[string]string
}

func File(encodingKey, filePath string) *Vault {

	return &Vault{
		encodingKey: encodingKey,
		filePath: filePath,
	}
}

func (v *Vault) readKeyValues(r io.Reader) error {
	dec := json.NewDecoder(r)
	return dec.Decode(&v.keyValues)
}

func (v *Vault) writeKeyValues(w io.Writer) error {
	enc := json.NewEncoder(w)
	return enc.Encode(v.keyValues)
}

func (v * Vault) load() error {
	file, err := os.Open(v.filePath)
	if err != nil {
		v.keyValues = make(map[string]string)
		return nil
	}
	defer file.Close()
	reader, err := cipher.DecryptReader(v.encodingKey, file)
	if err != nil {
		return err
	}
	err = v.readKeyValues(reader)
	if err != nil {
		return err
	}

	return nil
}

func (v * Vault) save() error {
	file, err := os.OpenFile(v.filePath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer file.Close()
	writer, err := cipher.EncryptWriter(v.encodingKey, file)
	if err != nil {
		return err
	}
	return v.writeKeyValues(writer)

}

func (v *Vault) Get(key string) (string, error) {
	v.Lock()
	defer v.Unlock()
	err := v.loadKeyValues()
	if err != nil {
		return "", err
	}
	value, ok := v.keyValues[key]
	if !ok {
		return "", errors.New("secret: no value for that key")
	}

	return value, nil
}

func (v *Vault) Set(key, value string) error {
	v.Lock()
	defer v.Unlock()
	err := v.loadKeyValues()
	if err != nil {
		return err
	}
	v.keyValues[key] = value
	err = v.saveKeyValues()

	return err
}