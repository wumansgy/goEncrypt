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
	非对称加密需要生成一对密钥而不是一个密钥，所以这里加密之前需要获取一对密钥分别为公钥和私钥
	一次性生成公钥和私钥
		加密:  明文的E	次方 Mod N  输出密文
		解密:  密文的D   次方 Mod N  输出明文

		加密操作需要消耗很长的时间 ? 加密速度会快

		数据加密之后不能被轻易的解密出来

*/

func GetRsaKey(){
	//1. GetKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥。
	//Reader是一个全局、共享的密码用强随机数生成器。在Unix类型系统中，会从/dev/urandom读取；而Windows中会调用CryptGenRandom API。
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// 将公钥和私钥持久的保存下来, 将这些内容保存到文件中

	//2.x509标准 按照一定标准的标准对数据进行格式化.序列化.编码
	// MarshalPKCS1PrivateKey将rsa私钥序列化为ASN.1 PKCS#1 DER编码。
	x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	//3.使用pem格式对x509输出的内容进行编码 base64编码--> 64个字符 0-9 a-z A-Z + /  总共64个字符
	// base64 反向编码
	// 需要将数据输出到文件中
	privateFile, _ := os.Create("private.pem")
	defer privateFile.Close()
	// 构建一个block结构体
	privateBlock := pem.Block{
		Type:" WUMAN  PRIVATE KEY",
		Bytes:x509PrivateKey,
	}

	pem.Encode(privateFile,&privateBlock)


	//=================================保存公钥===============================================
	//1.获取公钥的数据
	publicKey := privateKey.PublicKey

	//2.x509对公钥进行编码,有很多不可见的字符,乱码 MarshalPKIXPublicKey将公钥序列化为PKIX格式DER编码。
	// 注意,这里传入的必须是指针
	x509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}


	//3.pem格式编码,并且保存到文件中
	//3.1 构建输出的文件
	publicFile,_ :=os.Create("public.pem")
	// 关闭文件
	defer publicFile.Close()

	//3.2 构建一个block对象
	publicBlock := pem.Block{
		Type:"WUMAN  PUBLIC KEY",
		Bytes:x509PublicKey,
	}
	//3.3 使用pem编码
	pem.Encode(publicFile,&publicBlock)


}