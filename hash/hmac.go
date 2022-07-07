package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"io"
)

func HmacSha256(key []byte, body string) []byte {
	h := hmac.New(sha256.New, key)
	io.WriteString(h, body)
	return h.Sum(nil)
}

func HmacSha256Hex(key []byte, body string) string {
	return hex.EncodeToString(HmacSha256(key, body))
}

func HmacSha512(key []byte, body string) []byte {
	h := hmac.New(sha512.New, key)
	io.WriteString(h, body)
	return h.Sum(nil)
}

func HmacSha512Hex(key []byte, body string) string {
	return hex.EncodeToString(HmacSha512(key, body))
}