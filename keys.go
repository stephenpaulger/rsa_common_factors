package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
)

func ReadPublicKey(pempath string) (*rsa.PublicKey, error) {
	pemfile, err := ioutil.ReadFile(pempath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemfile)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub.(*rsa.PublicKey), nil
}

func WritePrivateKey(private_key *rsa.PrivateKey, out_path string) error {
	der_bytes := x509.MarshalPKCS1PrivateKey(private_key)

	der_block := new(pem.Block)
	der_block.Type = "RSA PRIVATE KEY"
	der_block.Bytes = der_bytes

	file, err := os.OpenFile(out_path, os.O_CREATE|os.O_WRONLY, 0600)
	defer file.Close()
	if err != nil {
		return err
	}

	return pem.Encode(file, der_block)
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
