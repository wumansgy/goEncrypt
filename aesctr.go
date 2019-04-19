package goEncrypt

import (
	"crypto/aes"
	"crypto/cipher"
)

/*
@Time : 2018/11/1 22:53 
@Author : wuman
@File : AES_CTR
@Software: GoLand
*/
/*
	AES CTR mode encryption and decryption
*/
func AesCtrEncrypt(plainText ,key []byte)([]byte,error){
	if len(key)!=16{
		return nil,ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(key)
	if err!=nil{
		return nil,err
	}
	iv := []byte(iv)
	stream := cipher.NewCTR(block, iv)

	cipherText := make([]byte,len(plainText))
	stream.XORKeyStream(cipherText,plainText)

	return  cipherText,nil
}

func AesCtrDecrypt(cipherText ,key []byte)([]byte,error){
	if len(key)!=16{
		return nil,ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(key)
	if err!=nil{
		return nil,err
	}
	iv := []byte(iv)
	stream := cipher.NewCTR(block, iv)

	plainText := make([]byte,len(cipherText))
	stream.XORKeyStream(plainText,cipherText)

	return plainText,nil
}
