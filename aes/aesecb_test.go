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
	cipherBytes, err := AesEcbEncrypt([]byte(plaintext),[]byte(key))
	assert.Nil(t, err)
	text, err := AesEcbDecrypt(cipherBytes,[]byte(key))
	assert.Nil(t, err)
	assert.Equal(t, string(text), plaintext)
}
