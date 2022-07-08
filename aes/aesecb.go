package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"

	"github.com/wumansgy/goEncrypt"
)

/*
 Ecb is not recommended,use cbc
*/
type aesEcb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *aesEcb {
	return &aesEcb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter aesEcb

func newECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		return
	}
	if len(dst) < len(src) {
		return
	}

	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypter aesEcb

func newECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int {
	return x.blockSize
}

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		return
	}
	if len(dst) < len(src) {
		return
	}

	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func AesEcbEncrypt(plainText, secretKey []byte) (cipherText []byte, err error) {
	if len(secretKey) != 16 && len(secretKey) != 24 && len(secretKey) != 32 {
		return nil, goEncrypt.ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	paddingText := goEncrypt.PKCS5Padding(plainText, block.BlockSize())

	crypted := make([]byte, len(paddingText))
	encrypter := newECBEncrypter(block)
	encrypter.CryptBlocks(crypted, paddingText)

	return crypted, nil
}

func AesEcbDecrypt(plainText, secretKey []byte) (cipjerText []byte, err error) {
	if len(secretKey) != 16 && len(secretKey) != 24 && len(secretKey) != 32 {
		return nil, goEncrypt.ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	ecbDecrypter := newECBDecrypter(block)
	decrypted := make([]byte, len(plainText))
	ecbDecrypter.CryptBlocks(decrypted, plainText)

	return goEncrypt.PKCS5UnPadding(decrypted, ecbDecrypter.BlockSize())
}

func AesEcbEncryptBase64(plainText, key []byte) (cipherTextBase64 string, err error) {
	encryBytes, err := AesEcbEncrypt(plainText, key)
	return base64.StdEncoding.EncodeToString(encryBytes), err
}

func AesEcbEncryptHex(plainText, key []byte) (cipherTextHex string, err error) {
	encryBytes, err := AesEcbEncrypt(plainText, key)
	return hex.EncodeToString(encryBytes), err
}

func AesEcbDecryptByBase64(cipherTextBase64 string, key []byte) (plainText []byte, err error) {
	plainTextBytes, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return []byte{}, err
	}
	return AesEcbDecrypt(plainTextBytes, key)
}

func AesEcbDecryptByHex(cipherTextHex string, key []byte) (plainText []byte, err error) {
	plainTextBytes, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return []byte{}, err
	}
	return AesEcbDecrypt(plainTextBytes, key)
}
