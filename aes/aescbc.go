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

/**
eencrypt
	Note: the key length is 16 bytes
*/

func init() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetReportCaller(true)
}

// encrypt
func AesCbcEncrypt(plainText, key, ivAes []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, goEncrypt.ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	paddingText := goEncrypt.PKCS5Padding(plainText, block.BlockSize())

	var iv []byte
	if len(ivAes) != 0 {
		if len(ivAes) != block.BlockSize() {
			return nil, goEncrypt.ErrIvAes
		} else {
			iv = ivAes
		}
	} else {
		iv = []byte(goEncrypt.Ivaes)
	} // To initialize the vector, it needs to be the same length as block.blocksize
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(paddingText))
	blockMode.CryptBlocks(cipherText, paddingText)
	return cipherText, nil
}

// decrypt
func AesCbcDecrypt(cipherText, key, ivAes []byte) ([]byte, error) {
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
	blockMode := cipher.NewCBCDecrypter(block, iv)
	paddingText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(paddingText, cipherText)

	plainText, err := goEncrypt.PKCS5UnPadding(paddingText, block.BlockSize())
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func AesCbcEncryptBase64(plainText, key, ivAes []byte) (string, error) {
	encryBytes, err := AesCbcEncrypt(plainText, key, ivAes)
	return base64.StdEncoding.EncodeToString(encryBytes), err
}

func AesCbcEncryptHex(plainText, key, ivAes []byte) (string, error) {
	encryBytes, err := AesCbcEncrypt(plainText, key, ivAes)
	return hex.EncodeToString(encryBytes), err
}

func AesCbcDecryptByBase64(cipherTextBase64 string, key, ivAes []byte) ([]byte, error) {
	plainTextBytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return []byte{}, err
	}
	return AesCbcDecrypt(plainTextBytes, key, ivAes)
}

func AesCbcDecryptByHex(cipherTextHex string, key, ivAes []byte) ([]byte, error) {
	plainTextBytes, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return []byte{}, err
	}
	return AesCbcDecrypt(plainTextBytes, key, ivAes)
}
