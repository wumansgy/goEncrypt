package goEncrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"runtime"
)

/*
@Time : 2018/11/1 22:53 
@Author : wuman
@File : AES_CBC
@Software: GoLand
*/
/**
eencrypt
	Note: the key length is 16 bytes
 */

func init(){
	log.SetFlags(log.Ldate|log.Lshortfile)
}
// encrypt
func AesCbcEncrypt(plainText,key []byte,ivAes ...byte )([]byte,error){
	if len(key) != 16 && len(key) != 24 && len(key) != 32{
		return nil,ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(key)
	if err!=nil{
		return nil,err
	}
	paddingText := PKCS5Padding(plainText, block.BlockSize())

	var iv []byte
	if len(ivAes)!=0{
		if len(ivAes)!=16{
			return nil,ErrIvAes
		}else{
			iv=ivAes
		}
	}else{
		iv =[]byte(ivaes)
	} // To initialize the vector, it needs to be the same length as block.blocksize
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte,len(paddingText))
	blockMode.CryptBlocks(cipherText,paddingText)
	return cipherText,nil
}

// decrypt
func AesCbcDecrypt(cipherText,key []byte,ivAes ...byte) ([]byte,error){
	if len(key) != 16 && len(key) != 24 && len(key) != 32{
		return nil,ErrKeyLengthSixteen
	}
	block, err := aes.NewCipher(key)
	if err!=nil{
		return nil,err
	}

	defer func(){
		if err:=recover();err!=nil{
			switch err.(type){
			case runtime.Error:
				log.Println("runtime err:",err,"Check that the key or text is correct")
			default:
				log.Println("error:",err)
			}
		}
	}()
	var iv []byte
	if len(ivAes)!=0{
		if len(ivAes)!=16{
			return nil,ErrIvAes
		}else{
			iv=ivAes
		}
	}else{
		iv =[]byte(ivaes)
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	paddingText := make([]byte,len(cipherText))
	blockMode.CryptBlocks(paddingText,cipherText)


	plainText,err := PKCS5UnPadding(paddingText)
	if err!=nil{
		return nil,err
	}
	return plainText,nil
}
