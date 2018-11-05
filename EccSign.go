package goEncrypt

import (
	"crypto/sha256"
	"crypto/rand"
	"encoding/pem"
	"crypto/x509"
	"log"
	"runtime"
	"crypto/ecdsa"
	"math/big"
)

/*
@Time : 2018/11/4 18:51 
@Author : wuman
@File : EccSign
@Software: GoLand
*/

func init(){
	log.SetFlags(log.Ldate|log.Lshortfile)
}   //处理日志的格式

func EccSign(msg []byte,Key []byte)(rtext []byte,stext []byte){
	// 获取私钥
	//2. pem格式解码
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
	//3.x509解码
	privateKey, _ := x509.ParseECPrivateKey(block.Bytes)
	/*if err!=nil{
		return []byte{},err
	}*/

	// 计算消息的hash值
	myhash := sha256.New()
	myhash.Write(msg)
	resultHash := myhash.Sum(nil)

	//使用私钥对任意长度的hash值（必须是较大信息的hash结果）进行签名，返回签名结果（一对大整数）
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, resultHash)

	rText, _ := r.MarshalText()
	sText, _ := s.MarshalText()

	return rText,sText


}

func EccVerifySign(msg []byte,Key []byte,rText,sText []byte) bool {
	// 获取公钥
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
	// x509解码
	publicKeyInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey:=publicKeyInterface.(*ecdsa.PublicKey)  //返回的接口类型需要类型断言一下


	myhash := sha256.New()
	myhash.Write(msg)
	resultHash := myhash.Sum(nil)

	var r,s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)
	// 校验签名
	result := ecdsa.Verify(publicKey, resultHash, &r, &s)
	return result
}