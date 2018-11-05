package goEncrypt

import (
	"log"
	"crypto/rand"
	"encoding/pem"
	"runtime"
	"crypto/x509"
	"crypto/ecdsa"
)

/*
@Time : 2018/11/4 16:43 
@Author : wuman
@File : EccCrypt
@Software: GoLand
*/
func init(){
	log.SetFlags(log.Ldate|log.Lshortfile)
}   //处理日志的格式
//Ecc椭圆曲线的公钥加密，如果要解密对应着私钥解密
/*func EccEnCrypt(plainText []byte,prv2 *ecies.PrivateKey)(crypText []byte,err error){

	ct, err := ecies.Encrypt(rand.Reader, &prv2.PublicKey, plainText, nil, nil)
	return ct, err
}
//直接解密
func EccDeCrypt(cryptText []byte,prv2 *ecies.PrivateKey) ([]byte, error) {
	pt, err := prv2.Decrypt(cryptText, nil, nil)
	return pt, err
}*/

//传入公钥和明文用来加密
func EccPublicEncrypt(plainText []byte,key []byte)( cryptText []byte,err error){  //用私钥解密
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
	tempPublicKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
	//解码得到ecdsa包中的私钥
	//类型断言
	publicKey1:=tempPublicKey.(*ecdsa.PublicKey)
	//转换为以太坊包中的ecies包中的私钥
	publicKey:=ImportECDSAPublic(publicKey1)
	//用私钥来解密密文
	crypttext,err:=Encrypt(rand.Reader, publicKey, plainText, nil, nil)

	return  crypttext,err


}

//传入私钥和明文用来解密
func EccPrivateDeCrypt(cryptText []byte,key []byte)( msg []byte,err error){  //用私钥解密
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
	tempPrivateKey, _ := x509.ParseECPrivateKey(block.Bytes)
	//解码得到ecdsa包中的私钥
	//转换为以太坊包中的ecies包中的私钥
	privateKey:=ImportECDSA(tempPrivateKey)

	//用私钥来解密密文
	plainText,err:=privateKey.Decrypt(cryptText,nil,nil)

	return plainText,err


}