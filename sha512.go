package goEncrypt

import (
	"crypto/sha512"
	"encoding/hex"
)

/*
@Time : 2018/11/2 17:05 
@Author : wuman
@File : sha512
@Software: GoLand
*/

func Sha512Hex(data []byte)string{
	return hex.EncodeToString(Sha512(data))
}

func Sha512(data []byte)[]byte{
	digest:=sha512.New()
	digest.Write(data)
	return digest.Sum(nil)
}