package goEncrypt

import (
	"crypto/des"
	"crypto/cipher"
	"bytes"
	"runtime"
	"fmt"
)

/*
@Time : 2018/11/1 22:50 
@Author : wuman
@File : TripleDES_CBC
@Software: GoLand
*/
/**
	三重des加密解密
      算法: 加密：密钥一加密->密钥二解密->密钥三加密
            解密：密钥三解密->密钥二加密->密钥一解密
 */
func TripleDesEncrypt(plainText,key []byte)[]byte{
	//判断用户传过来的key是否符合24字节，如果不符合24字节加以处理
	keylen:=len(key)
	if keylen==0{   //如果用户传入的密钥为空那么就用默认密钥
		key=[]byte("wumansgy12345678qazwsxop")   //默认密钥
	}else if keylen>0&&keylen<24{  //如果密钥长度在0到24之间，那么用0补齐剩余的
		key=append(key,bytes.Repeat([]byte{0},(24-keylen))...)
	}else if keylen>24{
		key=key[:24]
	}
	//1. 指定算法3des 创建并返回一个使用TDEA算法的cipher.Block接口。
	block, err := des.NewTripleDESCipher(key)
	if err != nil{
		panic(err)
	}
	//2. 分组填充
	paddingText := PKCS5Padding(plainText, block.BlockSize())

	//3.创建CBC分组模式blockMode
	iv :=[]byte("wumansgy")
	blockMode := cipher.NewCBCEncrypter(block, iv)

	//4. 加密操作
	cipherText := make([]byte,len(paddingText))
	blockMode.CryptBlocks(cipherText,paddingText)
	//5. 返回
	return cipherText
}

func TripleDesDecrypt(cipherText,key []byte) []byte{
	//判断用户传过来的key是否符合24字节，如果不符合24字节加以处理
	keylen:=len(key)
	if keylen==0{   //如果用户传入的密钥为空那么就用默认密钥
		key=[]byte("wumansgy12345678qazwsxop")   //默认密钥
	}else if keylen>0&&keylen<24{  //如果密钥长度在0到24之间，那么用0补齐剩余的
		key=append(key,bytes.Repeat([]byte{0},(24-keylen))...)
	}else if keylen>24{
		key=key[:24]
	}
	//1.指定3des解密算法 创建并返回一个使用TDEA算法的cipher.Block接口。
	block, err := des.NewTripleDESCipher(key)
	if err!=nil{
		panic(err)
	}

	//2.创建一个cbc分组模式的解密blockMode
	iv :=[]byte("wumansgy")
	blockMode := cipher.NewCBCDecrypter(block, iv)

	//3.解密操作
	paddingText := make([]byte,len(cipherText)) //
	blockMode.CryptBlocks(paddingText,cipherText)

	//4. 删除填充
	//删除之前防止出现用户输入两次密钥不一样，引起panic,所以做一个错误处理
	defer func(){
		if err:=recover();err!=nil{
			switch err.(type){
			case runtime.Error:
				fmt.Println("runtime error:",err,"请检查两次密钥是否一样")
			default:
				fmt.Println("error:",err)
			}
		}     //防止用户输入两次密钥不一样，然后返回错误
	}()
	plainText := PKCS5UnPadding(paddingText)

	return plainText
}