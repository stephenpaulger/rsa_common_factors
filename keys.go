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

func ReadPublicKey(pemPath string) (*rsa.PublicKey, error) {
	pemFile, err := ioutil.ReadFile(pemPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemFile)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub.(*rsa.PublicKey), nil
}

func WritePrivateKey(privateKey *rsa.PrivateKey, outPath string) error {
	derBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	derBlock := new(pem.Block)
	derBlock.Type = "RSA PRIVATE KEY"
	derBlock.Bytes = derBytes

	file, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY, 0600)
	defer file.Close()
	if err != nil {
		return err
	}

	return pem.Encode(file, derBlock)
}

func BuildPrivateKey(publicKey *rsa.PublicKey, p, q *big.Int) *rsa.PrivateKey {
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
	g.GCD(d, nil, big.NewInt(int64(publicKey.E)), phi)

	privateKey := new(rsa.PrivateKey)
	privateKey.N = publicKey.N
	privateKey.E = publicKey.E
	privateKey.D = d
	privateKey.Primes = []*big.Int{p, q}

	return privateKey
}
