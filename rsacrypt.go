package goEncrypt

import (
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"runtime"
	"log"
)

/*
@Time : 2018/11/2 19:04 
@Author : wuman
@File : rsacrypt
@Software: GoLand
*/

/*
	Operation with rsa encryption
*/
func init(){
	log.SetFlags(log.Ldate|log.Lshortfile)
}

func RsaEncrypt(plainText ,key []byte)(cryptText []byte,err error){
	block, _:= pem.Decode(key)
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
	publicKeyInterface,err := x509.ParsePKIXPublicKey(block.Bytes)
	if err!=nil{
		return nil,err
	}
	publicKey := publicKeyInterface.(*rsa.PublicKey)

	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err!=nil{
		return nil,err
	}
	return cipherText,nil
}

func RsaDecrypt(cryptText ,key []byte)(plainText []byte,err error){
	block, _ := pem.Decode(key)

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
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err!=nil{
		return []byte{},err
	}
	plainText,err= rsa.DecryptPKCS1v15(rand.Reader, privateKey, cryptText)
	if err!=nil{
		return []byte{},err
	}
	return plainText,nil
}