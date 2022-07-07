package hash

import (
	"crypto/sha512"
	"encoding/hex"
)


func Sha512Hex(data []byte)string{
	return hex.EncodeToString(Sha512(data))
}

func Sha512(data []byte)[]byte{
	digest:=sha512.New()
	digest.Write(data)
	return digest.Sum(nil)
}