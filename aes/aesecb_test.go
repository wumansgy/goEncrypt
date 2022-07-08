package aes

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAesEcb(t *testing.T) {
	var (
		key       = "1234567812345678"
		plaintext = "TestAesEcb"
	)
	cipherBytes, err := AesEcbEncrypt([]byte(plaintext), []byte(key))
	assert.Nil(t, err)
	text, err := AesEcbDecrypt(cipherBytes, []byte(key))
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)
}

func TestAesEcbEncryptBase64(t *testing.T) {
	var (
		key       = "1234567812345678"
		plaintext = "TestAesEcb"
	)
	cipher, err := AesEcbEncryptBase64([]byte(plaintext), []byte(key))
	assert.Nil(t, err)
	text, err := AesEcbDecryptByBase64(cipher, []byte(key))
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

	_, err = AesEcbDecryptByBase64("11111", []byte(key))
	assert.NotNil(t, err)
}

func TestAesEcbEncryptHex(t *testing.T) {
	var (
		key       = "1234567812345678"
		plaintext = "TestAesEcb"
	)
	cipher, err := AesEcbEncryptHex([]byte(plaintext), []byte(key))
	assert.Nil(t, err)
	text, err := AesEcbDecryptByHex(cipher, []byte(key))
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

	_, err = AesEcbDecryptByHex("11111", []byte(key))
	assert.NotNil(t, err)
}
