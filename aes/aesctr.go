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
func AesCtrEncrypt(plainText, secretKey, ivAes []byte) (cipherText []byte, err error) {
	if len(secretKey) != 16 && len(secretKey) != 24 && len(secretKey) != 32 {
		return nil, goEncrypt.ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(secretKey)
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

	cipherText = make([]byte, len(plainText))
	stream.XORKeyStream(cipherText, plainText)

	return cipherText, nil
}

func AesCtrDecrypt(cipherText, secretKey, ivAes []byte) (plainText []byte, err error) {
	if len(secretKey) != 16 && len(secretKey) != 24 && len(secretKey) != 32 {
		return nil, goEncrypt.ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(secretKey)
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

	plainText = make([]byte, len(cipherText))
	stream.XORKeyStream(plainText, cipherText)

	return plainText, nil
}

func AesCtrEncryptBase64(plainText, secretKey, ivAes []byte) (cipherTextBase64 string, err error) {
	encryBytes, err := AesCtrEncrypt(plainText, secretKey, ivAes)
	return base64.StdEncoding.EncodeToString(encryBytes), err
}

func AesCtrEncryptHex(plainText, secretKey, ivAes []byte) (cipherTextHex string, err error) {
	encryBytes, err := AesCtrEncrypt(plainText, secretKey, ivAes)
	return hex.EncodeToString(encryBytes), err
}

func AesCtrDecryptByBase64(cipherTextBase64 string, secretKey, ivAes []byte) (plainText []byte, err error) {
	plainTextBytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return []byte{}, err
	}
	return AesCtrDecrypt(plainTextBytes, secretKey, ivAes)
}

func AesCtrDecryptByHex(cipherTextHex string, secretKey, ivAes []byte) (plainText []byte, err error) {
	plainTextBytes, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return []byte{}, err
	}
	return AesCtrDecrypt(plainTextBytes, secretKey, ivAes)
}
