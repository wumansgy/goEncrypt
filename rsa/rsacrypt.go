package rsa

import (
	"bytes"
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
	pubSize, plainTextSize := pub.Size(), len(plainText)
	// EncryptPKCS1v15 encrypts the given message with RSA and the padding
	// scheme from PKCS #1 v1.5.  The message must be no longer than the
	// length of the public modulus minus 11 bytes.
	//
	// The rand parameter is used as a source of entropy to ensure that
	// encrypting the same message twice doesn't result in the same
	// ciphertext.
	//
	// WARNING: use of this function to encrypt plaintexts other than
	// session keys is dangerous. Use RSA OAEP in new protocols.
	offSet, once := 0, pubSize-11
	buffer := bytes.Buffer{}
	for offSet < plainTextSize {
		endIndex := offSet + once
		if endIndex > plainTextSize {
			endIndex = plainTextSize
		}
		bytesOnce, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plainText[offSet:endIndex])
		if err != nil {
			return nil, err
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	cipherText = buffer.Bytes()
	return cipherText, nil
}

func rsaDecrypt(cipherText, privateKey []byte) (plainText []byte, err error) {
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
	priSize, cipherTextSize := pri.Size(), len(cipherText)
	var offSet = 0
	var buffer = bytes.Buffer{}
	for offSet < cipherTextSize {
		endIndex := offSet + priSize
		if endIndex > cipherTextSize {
			endIndex = cipherTextSize
		}
		bytesOnce, err := rsa.DecryptPKCS1v15(rand.Reader, pri, cipherText[offSet:endIndex])
		if err != nil {
			return nil, err
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	plainText = buffer.Bytes()
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
