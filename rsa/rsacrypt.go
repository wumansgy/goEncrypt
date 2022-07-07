package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"runtime"

	log "github.com/sirupsen/logrus"
)

/*
	Operation with rsa encryption
*/
func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetReportCaller(true)
}

func rsaEncrypt(plainText, publicKey []byte) (cipherText []byte, err error) {
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
	pub, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	cipherText, err = rsa.EncryptPKCS1v15(rand.Reader, pub, plainText)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

func rsaDecrypt(cryptText, privateKey []byte) (plainText []byte, err error) {
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
	pri, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		return []byte{}, err
	}
	plainText, err = rsa.DecryptPKCS1v15(rand.Reader, pri, cryptText)
	if err != nil {
		return []byte{}, err
	}
	return plainText, nil
}

func RsaEncryptToBase64(plainText []byte, base64PubKey string) (base64CipherText string, err error) {
	pub, err := base64.StdEncoding.DecodeString(base64PubKey)
	if err != nil {
		return "", err
	}
	cipherBytes, err := rsaEncrypt(plainText, pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

//
func RsaDecryptByBase64(base64CipherText, base64PriKey string) (plainText []byte, err error) {
	privateBytes, err := base64.StdEncoding.DecodeString(base64PriKey)
	if err != nil {
		return nil, err
	}
	cipherTextBytes, err := base64.StdEncoding.DecodeString(base64CipherText)
	if err != nil {
		return nil, err
	}
	return rsaDecrypt(cipherTextBytes, privateBytes)
}

func RsaEncryptToHex(plainText []byte, hexPubKey string) (hexCipherText string, err error) {
	pub, err := hex.DecodeString(hexPubKey)
	if err != nil {
		return "", err
	}
	cipherBytes, err := rsaEncrypt(plainText, pub)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(cipherBytes), nil
}

func RsaDecryptByHex(hexCipherText, hexPriKey string) (plainText []byte, err error) {
	privateBytes, err := hex.DecodeString(hexPriKey)
	if err != nil {
		return nil, err
	}
	cipherTextBytes, err := hex.DecodeString(hexCipherText)
	if err != nil {
		return nil, err
	}
	return rsaDecrypt(cipherTextBytes, privateBytes)
}
