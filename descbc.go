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

func DesCbcEncrypt(plainText ,key []byte,ivDes...byte)([]byte,error){
	if len(key)!=8{
		return nil,ErrKeyLengtheEight
	}
	block, err := des.NewCipher(key)
	if err!=nil{
		return nil,err
	}
	paddingText := PKCS5Padding(plainText, block.BlockSize())

	var iv []byte
	if len(ivDes)!=0{
		if len(ivDes)!=8{
			return nil,ErrIvDes
		}else{
			iv=ivDes
		}
	}else{
		iv =[]byte(ivdes)
	}   // Initialization vector
	blockMode := cipher.NewCBCEncrypter(block, iv)

	cipherText := make([]byte,len(paddingText))
	blockMode.CryptBlocks(cipherText,paddingText)
	return cipherText,nil
}

func DesCbcDecrypt(cipherText ,key []byte,ivDes...byte) ([]byte,error){
	if len(key)!=8{
		return nil,ErrKeyLengtheEight
	}
	block, err := des.NewCipher(key)
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
	if len(ivDes)!=0{
		if len(ivDes)!=8{
			return nil,ErrIvDes
		}else{
			iv=ivDes
		}
	}else{
		iv =[]byte(ivdes)
	}   // Initialization vector
	blockMode := cipher.NewCBCDecrypter(block, iv)

	plainText := make([]byte,len(cipherText))
	blockMode.CryptBlocks(plainText,cipherText)


	unPaddingText,err := PKCS5UnPadding(plainText)
	if err!=nil{
		return nil,err
	}
	return unPaddingText,nil
}