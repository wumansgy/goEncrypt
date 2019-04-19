package goEncrypt

import (
	"encoding/pem"
	"crypto/x509"
	"runtime"
	"crypto/sha256"
	"crypto/rsa"
	"crypto/rand"
	"crypto"
	"log"
)

/*
@Time : 2018/11/4 17:13 
@Author : wuman
@File : RsaSign
@Software: GoLand
*/

func init(){
	log.SetFlags(log.Ldate|log.Lshortfile)
}

func RsaSign(msg ,Key []byte)(cryptText []byte,err error){
	block, _ := pem.Decode(Key)
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
	privateKey,err := x509.ParsePKCS1PrivateKey(block.Bytes)
	myHash := sha256.New()
	myHash.Write(msg)
	hashed := myHash.Sum(nil)
	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err!=nil{
		return nil,err
	}
	return sign,nil
}

func RsaVerifySign(msg []byte,sign []byte,Key []byte)bool{
	block, _ := pem.Decode(Key)
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
	publicInterface,_ := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey:=publicInterface.(*rsa.PublicKey)
	myHash := sha256.New()
	myHash.Write(msg)
	hashed := myHash.Sum(nil)
	result := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, sign)
	return result == nil
}