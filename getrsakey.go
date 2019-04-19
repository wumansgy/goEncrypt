package goEncrypt

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"os"
	"encoding/pem"
)

/*
@Time : 2018/11/2 18:44 
@Author : wuman
@File : getkey
@Software: GoLand
*/
/*
	Asymmetric encryption requires the generation of a pair of keys rather than a key, so before encryption here you need to get a pair of keys, public and private, respectively
	Generate the public and private keys all at once
		Encryption: plaintext to the power E Mod N to output ciphertext
		Decryption: ciphertext to the power D Mod N outputs plaintext

		Encryption operations take a long time? Encryption is faster

		The data is encrypted and cannot be easily decrypted
*/

func GetRsaKey()error{
	privateKey, err:= rsa.GenerateKey(rand.Reader, 2048)
	if err!=nil{
		return err
	}
	x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	privateFile, err := os.Create(privateFileName)
	if err!=nil{
		return err
	}
	defer privateFile.Close()
	privateBlock := pem.Block{
		Type:privateKeyPrefix,
		Bytes:x509PrivateKey,
	}

	if err=pem.Encode(privateFile,&privateBlock);err!=nil{
		return err
	}
	publicKey := privateKey.PublicKey
	x509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	publicFile,_ :=os.Create(publicFileName)
	defer publicFile.Close()
	publicBlock := pem.Block{
		Type:publicKeyPrefix,
		Bytes:x509PublicKey,
	}
	if err=pem.Encode(publicFile,&publicBlock);err!=nil{
		return err
	}
	return nil
}