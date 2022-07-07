package ecc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"runtime"

	log "github.com/sirupsen/logrus"
	"github.com/wumansgy/goEncrypt/hash"
)

func eccSign(msg []byte, priKey []byte) (rSign []byte, sSign []byte, err error) {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Errorf("runtime err=%v,Check that the key or text is correct", err)
			default:
				log.Errorf("error=%v,check the cipherText ", err)
			}
		}
	}()
	privateKey, err := x509.ParseECPrivateKey(priKey)
	if err != nil {
		return nil, nil, err
	}
	resultHash := hash.Sha256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, resultHash)
	if err != nil {
		return nil, nil, err
	}

	rText, err := r.MarshalText()
	if err != nil {
		return nil, nil, err
	}
	sText, err := s.MarshalText()
	if err != nil {
		return nil, nil, err
	}
	return rText, sText, nil
}

func eccVerifySign(msg []byte, pubKey []byte, rText, sText []byte) bool {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Errorf("runtime err=%v,Check that the key or text is correct", err)
			default:
				log.Errorf("error=%v,check the cipherText ", err)
			}
		}
	}()
	publicKeyInterface, _ := x509.ParsePKIXPublicKey(pubKey)
	publicKey := publicKeyInterface.(*ecdsa.PublicKey)
	resultHash := hash.Sha256(msg)

	var r, s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)
	result := ecdsa.Verify(publicKey, resultHash, &r, &s)
	return result
}

func EccSignBase64(msg []byte, base64PriKey string) (base64rSign, base64sSign string, err error) {
	priBytes, err := base64.StdEncoding.DecodeString(base64PriKey)
	if err != nil {
		return "", "", err
	}
	rSign, sSign, err := eccSign(msg, priBytes)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(rSign), base64.StdEncoding.EncodeToString(sSign), nil
}

func EccVerifySignBase64(msg []byte, base64rSign, base64sSign, base64PubKey string) bool {
	rSignBytes, err := base64.StdEncoding.DecodeString(base64rSign)
	if err != nil {
		return false
	}
	sSignBytes, err := base64.StdEncoding.DecodeString(base64sSign)
	if err != nil {
		return false
	}
	pubBytes, err := base64.StdEncoding.DecodeString(base64PubKey)
	if err != nil {
		return false
	}
	return eccVerifySign(msg, pubBytes, rSignBytes, sSignBytes)
}

func EccSignHex(msg []byte, hexPriKey string) (hexrSign, hexsSign string, err error) {
	priBytes, err := hex.DecodeString(hexPriKey)
	if err != nil {
		return "", "", err
	}
	rSign, sSign, err := eccSign(msg, priBytes)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(rSign), hex.EncodeToString(sSign), nil
}

func EccVerifySignHex(msg []byte, hexrSign, hexsSign, hexPubKey string) bool {
	rSignBytes, err := hex.DecodeString(hexrSign)
	if err != nil {
		return false
	}
	sSignBytes, err := hex.DecodeString(hexsSign)
	if err != nil {
		return false
	}
	pubBytes, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return false
	}
	return eccVerifySign(msg, pubBytes, rSignBytes, sSignBytes)
}
