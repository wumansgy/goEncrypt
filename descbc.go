package goEncrypt

import (
	"crypto/cipher"
	"crypto/des"
	"log"
	"runtime"
)

/*
@Time : 2018/11/1 21:28 
@Author : wuman
@File : DES_CBC
@Software: GoLand
*/
/**
1. Group plaintext
	DES CBC mode encryption and decryption, is an 8-byte block encryption
	If the group is not an integer multiple of 8, you need to consider completing the 8 bits2.
 */
func init(){
	log.SetFlags(log.Ldate|log.Lshortfile)
}

func DesCbcEncrypt(plainText ,key []byte)([]byte,error){
	if len(key)!=8{
		return nil,ErrKeyLengtheEight
	}
	block, err := des.NewCipher(key)
	if err!=nil{
		return nil,err
	}
	paddingText := PKCS5Padding(plainText, block.BlockSize())

	iv:=[]byte(ivdes)   // Initialization vector
	blockMode := cipher.NewCBCEncrypter(block, iv)

	cipherText := make([]byte,len(paddingText))
	blockMode.CryptBlocks(cipherText,paddingText)
	return cipherText,nil
}

func DesCbcDecrypt(cipherText ,key []byte) ([]byte,error){
	if len(key)!=8{
		return nil,ErrKeyLengtheEight
	}
	block, err := des.NewCipher(key)
	if err!=nil{
		return nil,err
	}
	iv:=[]byte(ivdes)   // Initialization vector
	blockMode := cipher.NewCBCDecrypter(block, iv)

	plainText := make([]byte,len(cipherText))
	blockMode.CryptBlocks(plainText,cipherText)

	defer func(){
		if err:=recover();err!=nil{
			switch err.(type){
			case runtime.Error:
				log.Println("runtime err:",err,"Check that the key is correct")
			default:
				log.Println("error:",err)
			}
		}
	}()
	unPaddingText := PKCS5UnPadding(plainText)
	return unPaddingText,nil
}