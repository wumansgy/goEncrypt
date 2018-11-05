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
	用rsa加密操作
*/
//输出日志的格式
func init(){
	log.SetFlags(log.Ldate|log.Lshortfile)
}
func RsaEncrypt(plainText ,key []byte)(cryptText []byte,err error){

	/*file, _ := os.Open(path)
	defer file.Close()

	//1.1 读取文件的内容
	// 获取文件的本身大小
	fileInfo, _ := file.Stat()
	buf := make([]byte,fileInfo.Size())
	//1.2 将文件内容读取到buf中
	file.Read(buf)

	//2. pem 解码
	fmt.Println(buf)
	block, _ := pem.Decode(buf)*/
	//1. pem 解码
	block, _:= pem.Decode(key)

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
	//2. block中的Bytes是x509编码的内容, x509解码
	publicKeyInterface,err := x509.ParsePKIXPublicKey(block.Bytes)
	if err!=nil{
		return []byte{},err   //出错返回错误
	}
	//3.1 类型断言
	publicKey := publicKeyInterface.(*rsa.PublicKey)

	//4. 使用公钥对明文进行加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err!=nil{
		return []byte{},err   //出错返回错误
	}

	return cipherText,nil
}

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