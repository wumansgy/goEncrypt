package hash

import (
	"crypto/sha1"
	"encoding/hex"
)

func Sha1Hex(data []byte) string {
	return hex.EncodeToString(Sha1(data))
}

func Sha1(data []byte) []byte {
	digest := sha1.New()
	digest.Write(data)
	return digest.Sum(nil)
}
