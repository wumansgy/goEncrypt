package des

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTripleDesCbc(t *testing.T) {
	var (
		key24     = "123456781234567812345678"
		plaintext = "TestTripleDes"
		badiv     = "11111"
		goodiv    = "12345678"
	)
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
