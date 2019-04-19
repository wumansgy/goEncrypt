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
func AesCtrEncrypt(plainText []byte,key[16]byte)([]byte,error){
	cipherKey:=key[:]
	block, err := aes.NewCipher(cipherKey)
	if err!=nil{
		return nil,err
	}
	iv := []byte(iv)
	stream := cipher.NewCTR(block, iv)

	cipherText := make([]byte,len(plainText))
	stream.XORKeyStream(cipherText,plainText)

	return  cipherText,nil
}

func AesCtrDecrypt(cipherText []byte,key [16]byte)([]byte,error){
	cipherKey:=key[:]
	block, err:= aes.NewCipher(cipherKey)
	if err!=nil{
		return nil,err
	}
	iv := []byte(iv)
	stream := cipher.NewCTR(block, iv)

	plainText := make([]byte,len(cipherText))
	stream.XORKeyStream(plainText,cipherText)

	return plainText,nil
}
