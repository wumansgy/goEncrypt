package des

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	key24     = "123456781234567812345678"
	plainText = "TestTripleDes"
)

func TestTripleDesCbc(t *testing.T) {
	cipherBytes, err := TripleDesEncrypt([]byte(plaintext), []byte(key24), nil)
	assert.Nil(t, err)
	text, err := TripleDesDecrypt(cipherBytes, []byte(key24), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)
	assert.NotEqual(t, string(text), "test")

	cipherBytes, err = TripleDesEncrypt([]byte(plaintext), []byte(key24), []byte(goodiv))
	assert.Nil(t, err)
	text, err = TripleDesDecrypt(cipherBytes, []byte(key24), []byte(goodiv))
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)
	assert.NotEqual(t, string(text), "test")

	cipherBytes, err = TripleDesEncrypt([]byte(plaintext), []byte(key24), []byte(badiv))
	assert.NotNil(t, err)

	cipherBytes, err = TripleDesEncrypt([]byte(plaintext), []byte(badiv), []byte(badiv))
	assert.NotNil(t, err)

}

func TestTripleDesEncryptBase64(t *testing.T) {
	cipher, err := TripleDesEncryptBase64([]byte(plainText), []byte(key24), nil)
	assert.Nil(t, err)
	text, err := TripleDesDecryptByBase64(cipher, []byte(key24), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plainText)

	_, err = TripleDesDecryptByBase64("11111", []byte(key24), nil)
	assert.NotNil(t, err)
}

func TestTripleDesEncryptHex(t *testing.T) {
	cipher, err := TripleDesEncryptHex([]byte(plainText), []byte(key24), nil)
	assert.Nil(t, err)
	text, err := TripleDesDecryptByHex(cipher, []byte(key24), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plainText)

	_, err = TripleDesDecryptByHex("11111", []byte(key24), nil)
	assert.NotNil(t, err)
}