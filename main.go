package main

import (
	"Secrets-CLI/secrets"
	"fmt"
)

func main() {
	v := secrets.File("my-custom-key", ".secrets")
	err := v.Set("custom_key", "some custom value")
	if err != nil {
		panic(err)
	}
	plain, err := v.Get("custom_key")
	if err != nil {
		panic(err)
	}
	fmt.Println("Plain:", plain)
}