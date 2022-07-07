package hash

import (
	"crypto/sha256"
	"encoding/hex"
)


func Sha256Hex(data []byte) string {
	return hex.EncodeToString(Sha256(data))
}

func Sha256(data []byte) []byte {
	digest := sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}
