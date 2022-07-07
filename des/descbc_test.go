package des

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDesCbc(t *testing.T) {
	var (
		key       = "111"
		key8      = "12345678"
		plaintext = "TestDesCbc"
		badiv     = "11111"
		goodiv    = "12345678"
	)
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
