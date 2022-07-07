package hash

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	hmac256="ee59ba4d767a2122cd5acebc538b31adce6d378719872e4b2b961d26a87b01cd"
	hmac512="ed697fcce5cc626037d96f8f27fe86f4bfbf12ddf1236b9f4a9172acab1d6c02fb987bb453c525f6dbc0167164e7ac18fcf8d36ed09ece8a7a03222473f57363"
)

func TestHmacSha256Hex(t *testing.T) {
	res:=HmacSha256Hex([]byte("test"),"hmac text")
	assert.Equal(t, res, hmac256)
}

func TestHmacSha512Hex(t *testing.T) {
	res:=HmacSha512Hex([]byte("test"),"hmac text")
	assert.Equal(t, res, hmac512)
}

