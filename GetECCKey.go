package goEncrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"log"
)

/*
@Time : 2018/11/4 16:22 
@Author : wuman
@File : GetECCKey
@Software: GoLand
*/
func init(){
	log.SetFlags(log.Ldate|log.Lshortfile)
}
//ECC椭圆曲线密钥对生成
func GetEccKey(){
	//1.生成密钥对
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	//2.将密钥保存到相关的文件中
	// x509标准编码
	x509PrivateKey, _ := x509.MarshalECPrivateKey(privateKey)

	//pem 编码,构建block对象
	block := pem.Block{
		Type:  "WUMAN ECC PRIVATE KEY",
		Bytes: x509PrivateKey,
	}
	// pem编码
	file, err := os.Create("eccprivate.pem")
	if err!=nil{
		log.Println(err)  //打印错误
	}
	defer file.Close()    //最后关闭文件
	pem.Encode(file, &block)

	//3. 对公钥进行x509编码
	x509PublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err!=nil {
		panic(err)
	}
	//4, 对公钥进行pem编码
	publicBlock := pem.Block{
		Type:  "WUMAN ECC PUBLIC KEY",
		Bytes: x509PublicKey,
	}
	publicFile, err := os.Create("eccpublic.pem")
	if err!=nil {
		log.Println(err)  //打印错误
	}
	defer publicFile.Close()  //最后关闭文件
	pem.Encode(publicFile,&publicBlock)  //写入文件

}