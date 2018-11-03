package rsa

import (
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
)

/*
@Time : 2018/11/2 19:05 
@Author : wuman
@File : rsadecrypt
@Software: GoLand
*/

/*
	rsa解密操作
*/

func RsaDecrypt(cryptText ,key []byte)(plainText []byte,err error){

	/*//1.打开文件
	file, _ := os.Open(path)
	defer file.Close()

	//1.1 读取文件的内容
	// 获取文件的本身大小
	fileInfo, _ := file.Stat()
	buf := make([]byte,fileInfo.Size())
	//1.2 将文件内容读取到buf中
	file.Read(buf)

	//2. pem 解码
	block, _ := pem.Decode(buf)*/
	//1. pem格式解码
	block, _ := pem.Decode(key)

	//2.x509解码
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err!=nil{
		return []byte{},err
	}

	//3. 解密操作
	plainText,err= rsa.DecryptPKCS1v15(rand.Reader, privateKey, cryptText)
	if err!=nil{
		return []byte{},err
	}

	return plainText,nil
}