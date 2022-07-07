package aes

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAesCtr(t *testing.T) {
	var (
		key       = "111"
		key16     = "1234567812345678"
		key24     = "123456781234567812345678"
		key32     = "12345678123456781234567812345678"
		plaintext = "TestAesCtr"
	)
	cipherBytes, err := AesCtrEncrypt([]byte(plaintext), []byte(key16), nil)
	assert.Nil(t, err)
	text, err := AesCtrDecrypt(cipherBytes, []byte(key16), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

	cipherBytes, err = AesCtrEncrypt([]byte(plaintext), []byte(key24), nil)
	assert.Nil(t, err)
	text, err = AesCtrDecrypt(cipherBytes, []byte(key24), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

	cipherBytes, err = AesCtrEncrypt([]byte(plaintext), []byte(key32), nil)
	assert.Nil(t, err)
	text, err = AesCtrDecrypt(cipherBytes, []byte(key32), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

	cipherBytes, err = AesCtrEncrypt([]byte(plaintext), []byte(key), nil)
	assert.NotNil(t, err)
	text, err = AesCtrDecrypt(cipherBytes, []byte(key), nil)
	assert.NotNil(t, err)
}