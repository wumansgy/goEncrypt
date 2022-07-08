package des

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	key       = "111"
	key8      = "12345678"
	plaintext = "TestDesCbc"
	badiv     = "11111"
	goodiv    = "12345678"
)

func TestDesCbc(t *testing.T) {

	cipherBytes, err := DesCbcEncrypt([]byte(plaintext), []byte(key8), nil)
	assert.Nil(t, err)
	text, err := DesCbcDecrypt(cipherBytes, []byte(key8), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

	cipherBytes, err = DesCbcEncrypt([]byte(plaintext), []byte(key), nil)
	assert.NotNil(t, err)

	cipherBytes, err = DesCbcEncrypt([]byte(plaintext), []byte(key8), []byte(badiv))
	assert.NotNil(t, err)

	cipherBytes, err = DesCbcEncrypt([]byte(plaintext), []byte(key8), []byte(goodiv))
	assert.Nil(t, err)
	text, err = DesCbcDecrypt(cipherBytes, []byte(key8), []byte(goodiv))
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

}

func TestDesEncryptBase64(t *testing.T) {
	cipher, err := DesCbcEncryptBase64([]byte(plaintext), []byte(key8), nil)
	assert.Nil(t, err)
	text, err := DesCbcDecryptByBase64(cipher, []byte(key8), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

	_, err = DesCbcDecryptByBase64("11111", []byte(key8), nil)
	assert.NotNil(t, err)
}

func TestDesEncryptHex(t *testing.T) {
	cipher, err := DesCbcEncryptHex([]byte(plaintext), []byte(key8), nil)
	assert.Nil(t, err)
	text, err := DesCbcDecryptByHex(cipher, []byte(key8), nil)
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)

	_, err = DesCbcDecryptByHex("11111", []byte(key8), nil)
	assert.NotNil(t, err)
}