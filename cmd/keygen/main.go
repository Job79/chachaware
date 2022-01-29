package main

import (
	"chachaware/internal/crypto"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("invalid number of arguments; usage: keygen {recovery key}")
		return
	}

	storedPriv, _ := base64.RawURLEncoding.DecodeString("x22RozWlR9GAYKOxQny8-VL3KcQ8PqcfoSKLlAw_6fI")
	recovery, _ := base64.RawURLEncoding.DecodeString(os.Args[1])

	secret, err := crypto.RecoverSecret(storedPriv, recovery)
	if err != nil {
		panic(err)
	}

	fmt.Println(base64.RawURLEncoding.EncodeToString(secret))
}
