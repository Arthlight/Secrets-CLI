package secrets

import (
	"Secrets-CLI/encrypt"
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

func (v * Vault) loadKeyValues() error {
	file, err := os.Open(v.filePath)
	if err != nil {
		v.keyValues = make(map[string]string)
		return nil
	}
	defer file.Close()
	var sb strings.Builder
	_, err = io.Copy(&sb, file)
	if err != nil {
		return err
	}
	decryptedJSON, err := encrypt.Decrypt(v.encodingKey, sb. String())
	if err != nil {
		return err
	}
	reader := strings.NewReader(decryptedJSON)

	dec := json.NewDecoder(reader)
	err = dec.Decode(&v.keyValues)
	if err != nil {
		return err
	}

	return nil
}

func (v * Vault) saveKeyValues() error {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	err := enc.Encode(v.keyValues)
	if err != nil {
		return err
	}
	encryptedJSON, err := encrypt.Encrypt(v.encodingKey, sb.String())
	if err != nil {
		return err
	}
	file, err := os.OpenFile(v.filePath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = fmt.Fprint(file, encryptedJSON)
	if err != nil {
		return err
	}

	return nil
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