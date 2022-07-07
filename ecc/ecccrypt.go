package ecc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"runtime"

	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetReportCaller(true)
}

// The public key and plaintext are passed in for encryption
func eccEncrypt(plainText, pubKey []byte) (cipherText []byte, err error) {
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
	tempPublicKey, err := x509.ParsePKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	// Decode to get the private key in the ecdsa package
	publicKey1 := tempPublicKey.(*ecdsa.PublicKey)
	// Convert to the public key in the ecies package in the ethereum package
	publicKey := ImportECDSAPublic(publicKey1)
	cipherText, err = Encrypt(rand.Reader, publicKey, plainText, nil, nil)
	return cipherText, err

}

// The private key and plaintext are passed in for decryption
func eccDecrypt(cipherText, priKey []byte) (msg []byte, err error) {
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
	tempPrivateKey, err := x509.ParseECPrivateKey(priKey)
	if err != nil {
		return nil, err
	}
	// Decode to get the private key in the ecdsa package
	// Convert to the private key in the ecies package in the ethereum package
	privateKey := ImportECDSA(tempPrivateKey)
	plainText, err := privateKey.Decrypt(cipherText, nil, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func EccEncryptToBase64(plainText []byte, base64PubKey string) (base64CipherText string, err error) {
	pub, err := base64.StdEncoding.DecodeString(base64PubKey)
	if err != nil {
		return "", err
	}
	cipherBytes, err := eccEncrypt(plainText, pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

//
func EccDecryptByBase64(base64CipherText, base64PriKey string) (plainText []byte, err error) {
	privateBytes, err := base64.StdEncoding.DecodeString(base64PriKey)
	if err != nil {
		return nil, err
	}
	cipherTextBytes, err := base64.StdEncoding.DecodeString(base64CipherText)
	if err != nil {
		return nil, err
	}
	return eccDecrypt(cipherTextBytes, privateBytes)
}

func EccEncryptToHex(plainText []byte, hexPubKey string) (hexCipherText string, err error) {
	pub, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return "", err
	}
	cipherBytes, err := eccEncrypt(plainText, pub)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(cipherBytes), nil
}

func EccDecryptByHex(hexCipherText, hexPriKey string) (plainText []byte, err error) {
	privateBytes, err := hex.DecodeString(hexPriKey)
	if err != nil {
		return nil, err
	}
	cipherTextBytes, err := hex.DecodeString(hexCipherText)
	if err != nil {
		return nil, err
	}
	return eccDecrypt(cipherTextBytes, privateBytes)
}
