package main

import (
	"fmt"
	"os"

	"pkt.systems/kryptograf"
)

func main() {
	key, err := kryptograf.GenerateRootKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(key.EncodeToBase64())
}
