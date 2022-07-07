package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"runtime"

	log "github.com/sirupsen/logrus"
	"github.com/wumansgy/goEncrypt"
)

/*
	AES CTR mode encryption and decryption
*/
func AesCtrEncrypt(plainText, key, ivAes []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, goEncrypt.ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var iv []byte
	if len(ivAes) != 0 {
		if len(ivAes) != block.BlockSize() {
			return nil, goEncrypt.ErrIvAes
		} else {
			iv = ivAes
		}
	} else {
		iv = []byte(goEncrypt.Ivaes)
	}
	stream := cipher.NewCTR(block, iv)

	cipherText := make([]byte, len(plainText))
	stream.XORKeyStream(cipherText, plainText)

	return cipherText, nil
}

func AesCtrDecrypt(cipherText, key, ivAes []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, goEncrypt.ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

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

	var iv []byte
	if len(ivAes) != 0 {
		if len(ivAes) != block.BlockSize() {
			return nil, goEncrypt.ErrIvAes
		} else {
			iv = ivAes
		}
	} else {
		iv = []byte(goEncrypt.Ivaes)
	}
	stream := cipher.NewCTR(block, iv)

	plainText := make([]byte, len(cipherText))
	stream.XORKeyStream(plainText, cipherText)

	return plainText, nil
}

func AesCtrEncryptBase64(plainText, key, ivAes []byte) (string, error) {
	encryBytes, err := AesCtrEncrypt(plainText, key, ivAes)
	return base64.StdEncoding.EncodeToString(encryBytes), err
}

func AesCtrEncryptHex(plainText, key, ivAes []byte) (string, error) {
	encryBytes, err := AesCtrEncrypt(plainText, key, ivAes)
	return hex.EncodeToString(encryBytes), err
}

func AesCtrDecryptByBase64(cipherTextBase64 string, key, ivAes []byte) ([]byte, error) {
	plainTextBytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return []byte{}, err
	}
	return AesCtrDecrypt(plainTextBytes, key, ivAes)
}

func AesCtrDecryptByHex(cipherTextHex string, key, ivAes []byte) ([]byte, error) {
	plainTextBytes, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return []byte{}, err
	}
	return AesCtrDecrypt(plainTextBytes, key, ivAes)
}