package goEncrypt

import (
	"bytes"
)

/*
@Time : 2018/11/1 21:16
@Author : wuman
@File : padding
@Software: GoLand
*/
/**
1. Group plaintext
	If the blocksize is not an integer multiple of blocksize, the blocksize bit should be considered
    If des algorithm is used, the block size is 8 bytes
	With the AES algorithm, 16 bytes of fast size are filled in
    A tool for populating data when using block encryption mode
*/

// It is populated using pkcs5

func PKCS5Padding(plainText []byte, blockSize int) []byte {
	padding := blockSize - (len(plainText) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	newText := append(plainText, padText...)
	return newText
}

func PKCS5UnPadding(plainText []byte, blockSize int) ([]byte, error) {
	length := len(plainText)
	number := int(plainText[length-1])
	if number >= length || number > blockSize {
		return nil, ErrPaddingSize
	}
	return plainText[:length-number], nil
}
