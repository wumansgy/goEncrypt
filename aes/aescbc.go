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
func AesCbcEncrypt(plainText, secretKey, ivAes []byte) (cipherText []byte, err error) {
	if len(secretKey) != 16 && len(secretKey) != 24 && len(secretKey) != 32 {
		return nil, goEncrypt.ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(secretKey)
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
	cipherText = make([]byte, len(paddingText))
	blockMode.CryptBlocks(cipherText, paddingText)
	return cipherText, nil
}

// decrypt
func AesCbcDecrypt(cipherText, secretKey, ivAes []byte) (plainText []byte, err error) {
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
	blockMode := cipher.NewCBCDecrypter(block, iv)
	paddingText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(paddingText, cipherText)

	plainText, err = goEncrypt.PKCS5UnPadding(paddingText, block.BlockSize())
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func AesCbcEncryptBase64(plainText, secretKey, ivAes []byte) (cipherTextBase64 string, err error) {
	encryBytes, err := AesCbcEncrypt(plainText, secretKey, ivAes)
	return base64.StdEncoding.EncodeToString(encryBytes), err
}

func AesCbcEncryptHex(plainText, secretKey, ivAes []byte) (cipherTextHex string, err error) {
	encryBytes, err := AesCbcEncrypt(plainText, secretKey, ivAes)
	return hex.EncodeToString(encryBytes), err
}

func AesCbcDecryptByBase64(cipherTextBase64 string, secretKey, ivAes []byte) (plainText []byte, err error) {
	plainTextBytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return []byte{}, err
	}
	return AesCbcDecrypt(plainTextBytes, secretKey, ivAes)
}

func AesCbcDecryptByHex(cipherTextHex string, secretKey, ivAes []byte) (plainText []byte, err error) {
	plainTextBytes, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return []byte{}, err
	}
	return AesCbcDecrypt(plainTextBytes, secretKey, ivAes)
}
