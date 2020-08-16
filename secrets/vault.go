package secrets

import (
	"Secrets-CLI/encrypt"
	"encoding/json"
	"errors"
	"os"
)

type Vault struct {
	encodingKey string
	filePath string
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
	dec := json.NewDecoder(file)
	err = dec.Decode(&v.keyValues)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vault) Get(key string) (string, error) {
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

	encryptedValue, err := encrypt.Encrypt(v.encodingKey, value)
	if err != nil {
		return err
	}
	err = v.loadKeyValues()
	if err != nil {
		return err
	}
	v.keyValues[key] = encryptedValue
	err = v.saveKeyValues()

	return err
}