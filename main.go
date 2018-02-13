package main

import (
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
)

func GenerateProductOfNs(files []string) (*big.Int, error) {
	product := big.NewInt(1)

	for _, file := range files {
		public_key, err := ReadPublicKey(file)
		if err != nil {
			return nil, err
		}
		product.Mul(product, public_key.N)
	}

	return product, nil
}

func main() {
	found_keys := 0
	pem_file_pattern := "*.pem"

	files, _ := filepath.Glob(pem_file_pattern)

	// Get the product of the Ns in all the PEM files.
	prod_ns, err := GenerateProductOfNs(files)
	if err != nil {
		fmt.Errorf("could not generate product of Ns: %v", err)
	}

	for _, file := range files {
		public_key, err := ReadPublicKey(file)
		if err != nil {
			fmt.Errorf("could not read %s: %v", file, err)
		}

		// Divide prod_ns by the current N otherwise the
		// greatest common denominator will be N.
		other_ns := new(big.Int)
		other_ns.Div(prod_ns, public_key.N)

		// Calculate the greatest common denominator of
		// other_ns and N
		p := new(big.Int)
		p.GCD(nil, nil, other_ns, public_key.N)

		// As the factors of N are primes then if the GCD
		// is greater than 1 then we know we've found a
		// a common factor between the current key and
		// one of the other keys.
		if p.Cmp(big.NewInt(1)) < 1 {
			continue
		}

		found_keys += 1
		q := new(big.Int)
		q.Div(public_key.N, p)

		// now we have p and q we can create a private key
		private_key := BuildPrivateKey(public_key, p, q)
		pk_file := strings.Replace(file, ".pem", ".pk", 1)

		err = WritePrivateKey(private_key, pk_file)
		if err != nil {
			fmt.Errorf("error writing %s", pk_file)
		}
	}

	fmt.Printf("Generated %d private keys for %d public keys\n", found_keys, len(files))
}
