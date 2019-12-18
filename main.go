package main

import (
	"fmt"
	"log"
	"math/big"
	"path/filepath"
	"strings"
)

func GenerateProductOfNs(files []string) (*big.Int, error) {
	product := big.NewInt(1)

	for _, file := range files {
		publicKey, err := ReadPublicKey(file)
		if err != nil {
			return nil, err
		}
		product.Mul(product, publicKey.N)
	}

	return product, nil
}

func main() {
	foundKeys := 0
	pemFilePattern := "*.pem"

	files, _ := filepath.Glob(pemFilePattern)

	// Get the product of the Ns in all the PEM files.
	prodNs, err := GenerateProductOfNs(files)
	if err != nil {
		log.Fatalf("could not generate product of Ns: %v", err)
	}

	for _, file := range files {
		publicKey, err := ReadPublicKey(file)
		if err != nil {
			log.Fatalf("could not read %s: %v", file, err)
		}

		// Divide prodNs by the current N otherwise the
		// greatest common denominator will be N.
		otherNs := new(big.Int)
		otherNs.Div(prodNs, publicKey.N)

		// Calculate the greatest common denominator of
		// otherNs and N
		p := new(big.Int)
		p.GCD(nil, nil, otherNs, publicKey.N)

		// As the factors of N are primes then if the GCD
		// is greater than 1 then we know we've found a
		// a common factor between the current key and
		// one of the other keys.
		if p.Cmp(big.NewInt(1)) < 1 {
			continue
		}

		foundKeys++
		q := new(big.Int)
		q.Div(publicKey.N, p)

		// now we have p and q we can create a private key
		privateKey := BuildPrivateKey(publicKey, p, q)
		pkFile := strings.Replace(file, ".pem", ".pk", 1)

		err = WritePrivateKey(privateKey, pkFile)
		if err != nil {
			log.Fatalf("error writing %s", pkFile)
		}
	}

	fmt.Printf("Generated %d private keys for %d public keys\n", foundKeys, len(files))
}
