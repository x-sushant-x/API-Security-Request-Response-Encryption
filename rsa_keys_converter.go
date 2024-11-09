package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func ParsePrivateKeyFromString(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))

	if block == nil {
		return nil, errors.New("invalid private key. block does not contain private key")
	}

	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode. block private key type is invalid")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	CheckPanic(err)

	return privateKey, nil
}

func ParsePublicKeyFromString(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))

	if block == nil {
		return nil, errors.New("invalid public key. block does not contain public key")
	}

	if block.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("failed to decode. block private key type is invalid")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}
