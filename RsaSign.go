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
//实现的是利用RSA数字签名的函数，注意：用公钥加密，私钥解密就是加密通信，用私钥加密，公钥验证相当于数字签名
func RsaSign(msg []byte,Key []byte)(cryptText []byte,err error){
	//1. pem格式解码
	block, _ := pem.Decode(Key)

	//防止用户传的密钥不正确导致panic,这里恢复程序并打印错误
	defer func(){
		if err:=recover();err!=nil{
			switch err.(type){
			case runtime.Error:
				log.Println("runtime err:",err,"请检查密钥是否正确")
			default:
				log.Println("error:",err)
			}
		}
	}()
	//2.x509解码
	privateKey,err := x509.ParsePKCS1PrivateKey(block.Bytes)
	// 计算消息的hash值
	myHash := sha256.New()
	myHash.Write(msg)
	hashed := myHash.Sum(nil)

	//SignPKCS1v15使用RSA PKCS#1 v1.5规定的RSASSA-PKCS1-V1_5-SIGN签名方案计算签名。注意hashed必须是使用提供给本函数的hash参数对（要签名的）原始数据进行hash的结果。
	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err!=nil{
		return []byte{},err
	}
	return sign,nil    //返回签名后的消息

}

//验证签名，验证签名用公钥验证，如果可以解密验证说明签名正确，否则错误
func RsaVerifySign(msg []byte,sign []byte,Key []byte)bool{    //如果解密正确，那么就返回true,否着返回false

	//1. pem格式解码
	block, _ := pem.Decode(Key)

	//防止用户传的密钥不正确导致panic,这里恢复程序并打印错误
	defer func(){
		if err:=recover();err!=nil{
			switch err.(type){
			case runtime.Error:
				log.Println("runtime err:",err,"请检查密钥是否正确")
			default:
				log.Println("error:",err)
			}
		}
	}()
	//2.x509解码
	publicInterface,_ := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey:=publicInterface.(*rsa.PublicKey)
	// 计算hash值
	myHash := sha256.New()
	myHash.Write(msg)
	hashed := myHash.Sum(nil)
	// 校验签名
	result := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, sign)

	// 若返回nil 表示的是校验通过
	return result == nil
}