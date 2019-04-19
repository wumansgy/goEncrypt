package goEncrypt

import (
	"crypto/sha256"
	"encoding/hex"
)

/*
@Time : 2018/11/2 17:05 
@Author : wuman
@File : sha256
@Software: GoLand
*/

func Sha256Hex(data []byte)string{
	return hex.EncodeToString(Sha256(data))
}

func Sha256(data []byte)[]byte{
	digest:=sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}