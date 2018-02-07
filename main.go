package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

func ReadPublicKey(pempath string) *rsa.PublicKey {
	pemfile, err := ioutil.ReadFile(pempath)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(pemfile)
	if block == nil || block.Type != "PUBLIC KEY" {
		panic("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}

	return pub.(*rsa.PublicKey)
}

func WritePrivateKey(private_key *rsa.PrivateKey, out_path string) error {
	der_bytes := x509.MarshalPKCS1PrivateKey(private_key)

	der_block := new(pem.Block)
	der_block.Type = "RSA PRIVATE KEY"
	der_block.Bytes = der_bytes

	file, err := os.OpenFile(out_path, os.O_CREATE|os.O_WRONLY, 0600)
	defer file.Close()
	if err != nil {
		panic(err)
	}

	return pem.Encode(file, der_block)
}

func GenerateProductOfNs(files []string) (product *big.Int) {
	product = big.NewInt(1)

	for _, file := range files {
		public_key := ReadPublicKey(file)
		product.Mul(product, public_key.N)
	}

	return
}

func BuildPrivateKey(public_key *rsa.PublicKey, p, q *big.Int) *rsa.PrivateKey {
	// Using E from the public key, p and q we can calculate the other
	// values needed to make a private key.

	qd := new(big.Int)
	qd.Sub(q, big.NewInt(1))
	pd := new(big.Int)
	pd.Sub(p, big.NewInt(1))

	// phi = (p-1)*(q-1)
	phi := new(big.Int)
	phi.Mul(pd, qd)

	// d = E^(-1) mod phi
	g := new(big.Int)
	d := new(big.Int)
	g.GCD(d, nil, big.NewInt(int64(public_key.E)), phi)

	private_key := new(rsa.PrivateKey)
	private_key.N = public_key.N
	private_key.E = public_key.E
	private_key.D = d
	private_key.Primes = []*big.Int{p, q}

	return private_key
}

func main() {
	found_keys := 0
	pem_file_pattern := "*.pem"

	files, _ := filepath.Glob(pem_file_pattern)

	// Get the product of the Ns in all the PEM files.
	prod_ns := GenerateProductOfNs(files)

	for _, file := range files {
		public_key := ReadPublicKey(file)

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
		if p.Cmp(big.NewInt(1)) == 1 {
			found_keys += 1
			q := new(big.Int)
			q.Div(public_key.N, p)

			// now we have p and q we can create a private key
			private_key := BuildPrivateKey(public_key, p, q)
			pk_file := strings.Replace(file, ".pem", ".pk", 1)
			WritePrivateKey(private_key, pk_file)
		}

	}

	fmt.Printf("Generated %d private keys for %d public keys\n", found_keys, len(files))
}
