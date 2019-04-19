package goEncrypt

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"runtime"
)

/*
@Time : 2018/11/1 22:50 
@Author : wuman
@File : TripleDES_CBC
@Software: GoLand
*/
/**
	Triple des encryption and decryption
      algorithm : Encryption: key one encryption -> key two decryption -> key three encryption
                  Decryption: key three decryption -> key two encryption -> key one decryption
 */
func TripleDesEncrypt(plainText []byte,key [24]byte)([]byte,error){
	cipherKey:=key[:]
	block, err := des.NewTripleDESCipher(cipherKey)
	if err != nil{
		return nil,err
	}
	paddingText := PKCS5Padding(plainText, block.BlockSize())

	iv :=[]byte(ivdes)
	blockMode := cipher.NewCBCEncrypter(block, iv)

	cipherText := make([]byte,len(paddingText))
	blockMode.CryptBlocks(cipherText,paddingText)
	return cipherText,nil
}

func TripleDesDecrypt(cipherText []byte,key [24]byte) ([]byte,error){
	cipherKey:=key[:]
	// 1. Specifies that the 3des decryption algorithm creates and returns a cipher.Block interface using the TDEA algorithm。
	block, err := des.NewTripleDESCipher(cipherKey)
	if err!=nil{
		return nil,err
	}

	iv :=[]byte(ivdes)
	blockMode := cipher.NewCBCDecrypter(block, iv)

	paddingText := make([]byte,len(cipherText)) //
	blockMode.CryptBlocks(paddingText,cipherText)

	// 2. Delete the filling
	// Before deleting, prevent the user from entering different keys twice and causing panic, so do an error handling
	defer func(){
		if err:=recover();err!=nil{
			switch err.(type){
			case runtime.Error:
				fmt.Println("runtime error:",err,"Check that the key is correct")
			default:
				fmt.Println("error:",err)
			}
		}
	}()
	plainText := PKCS5UnPadding(paddingText)
	return plainText,nil
}