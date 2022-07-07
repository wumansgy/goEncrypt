package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
)

type EccKey struct {
	PrivateKey string
	PublicKey  string
}

func GenerateEccKeyHex() (EccKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return EccKey{}, err
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return EccKey{}, err
	}
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return EccKey{}, err
	}

	return EccKey{
		PrivateKey: hex.EncodeToString(privateBytes),
		PublicKey:  hex.EncodeToString(publicBytes),
	}, nil
}

func GenerateEccKeyBase64() (EccKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return EccKey{}, err
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return EccKey{}, err
	}
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return EccKey{}, err
	}
	return EccKey{
		PrivateKey: base64.StdEncoding.EncodeToString(privateBytes),
		PublicKey:  base64.StdEncoding.EncodeToString(publicBytes),
	}, nil
}
