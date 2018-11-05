package goEncrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"bytes"
	"runtime"
	"log"
)

/*
@Time : 2018/11/1 22:53 
@Author : wuman
@File : AES_CBC
@Software: GoLand
*/
/**
加密
	注意 : 这里采用key长度为16字节
 */
func init(){
	log.SetFlags(log.Ldate|log.Lshortfile)
}
func AesCBC_Encrypt(plainText,key []byte)[]byte{
	//判断用户传过来的key是否符合16字节，如果不符合16字节加以处理
	keylen:=len(key)
	if keylen==0{   //如果用户传入的密钥为空那么就用默认密钥
		key=[]byte("wumansgygoaescbc")   //默认密钥
	}else if keylen>0&&keylen<16{  //如果密钥长度在0到16之间，那么用0补齐剩余的
		key=append(key,bytes.Repeat([]byte{0},(16-keylen))...)
	}else if keylen>16{
		key=key[:16]
	}
	//1.指定一个aes算法,返回一个block接口
	block, err := aes.NewCipher(key)
	if err!=nil{
		panic(err)
	}
	//2.分组填充数据 blockSize 16
	paddingText := PKCS5Padding(plainText, block.BlockSize())
	//3.创建使用cbc分组模式的blockMode接口
	iv :=[]byte("wumansgy12345678")//初始化向量，需要和block.blocksize长度一样
	blockMode := cipher.NewCBCEncrypter(block, iv)
	//4. 加密
	cipherText := make([]byte,len(paddingText))
	blockMode.CryptBlocks(cipherText,paddingText)
	// 5. 返回数据
	return cipherText
}

//解密
func AesCBC_Decrypt(cipherText,key []byte) []byte{
	//判断用户传过来的key是否符合16字节，如果不符合16字节加以处理
	keylen:=len(key)
	if keylen==0{   //如果用户传入的密钥为空那么就用默认密钥
		key=[]byte("wumansgygoaescbc")   //默认密钥
	}else if keylen>0&&keylen<16{  //如果密钥长度在0到16之间，那么用0补齐剩余的
		key=append(key,bytes.Repeat([]byte{0},(16-keylen))...)
	}else if keylen>16{
		key=key[:16]
	}

	//1.指定使用aes算法
	block, err := aes.NewCipher(key)
	if err!=nil{
		panic(err)
	}
	//2.获取一个CBC模式的blockMode接口
	iv :=[]byte("wumansgy12345678")//初始化向量，需要和block.blocksize长度一样
	blockMode := cipher.NewCBCDecrypter(block, iv)
	//3.解密,内容包含有填充的数据
	paddingText := make([]byte,len(cipherText))
	blockMode.CryptBlocks(paddingText,cipherText)
	//4.删除填充的数据,防止出错，错误检查一下

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

	plainText := PKCS5UnPadding(paddingText)

	//5.返回明文
	return plainText
}
