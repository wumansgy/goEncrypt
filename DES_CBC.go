package goEncrypt

import (
	"crypto/des"
	"crypto/cipher"
	"bytes"
	"runtime"
	"log"
)

/*
@Time : 2018/11/1 21:28 
@Author : wuman
@File : DES_CBC
@Software: GoLand
*/
//DES的CBC模式加密解密，是以8字节一个块加密
/**
1. 对明文进行分组
	若分组不是8的整数倍,需要考虑补齐8位
2. 选择使用哪种加密算法 des算法
3. 选择按照怎样的套路进行每组的迭代加密  CBC
4. 加密输出结果
 */
func init(){
	log.SetFlags(log.Ldate|log.Lshortfile)
}

func DesCBC_Encrypt(plainText ,key []byte)[]byte{//加密密钥是要8字节的
	//判断用户传过来的key是否符合8字节，如果不符合8字节加以处理
	keylen:=len(key)
	if keylen==0{   //如果用户传入的密钥为空那么就用默认密钥
		key=[]byte("wumansgy")   //默认密钥
	}else if keylen>0&&keylen<8{  //如果密钥长度在0到8之间，那么用0补齐剩余的
		key=append(key,bytes.Repeat([]byte{0},(8-keylen))...)
	}else if keylen>8{
		key=key[:8]
	}
	//1. 指定使用des算法,创建并返回一个使用DES算法的cipher.Block接口。
	block, err := des.NewCipher(key)
	if err!=nil{
		panic(err)
	}
	//2.对明文进行分组填充处理
	paddingText := PKCS5Padding(plainText, block.BlockSize())

	//3.指定使用哪种分组模式 返回一个密码分组链接模式的、底层用b加密的BlockMode接口，初始向量iv的长度必须等于b的块尺寸。
	iv:=[]byte("wumansgy")   //初始化向量
	blockMode := cipher.NewCBCEncrypter(block, iv)

	//4.加密dst src
	cipherText := make([]byte,len(paddingText))
	// 将填充好的paddingText传入进去, 加密的结果 : ciherText
	blockMode.CryptBlocks(cipherText,paddingText)
	//5. 返回加密之后的数据
	return cipherText
}

func DesCBC_Decrypt(cipherText ,key []byte) []byte{
	//判断用户传过来的key是否符合8字节，如果不符合8字节加以处理
	keylen:=len(key)
	if keylen==0{   //如果用户传入的密钥为空那么就用默认密钥
		key=[]byte("wumansgy")   //默认密钥
	}else if keylen>0&&keylen<8{  //如果密钥长度在0到8之间，那么用0补齐剩余的
		key=append(key,bytes.Repeat([]byte{0},(8-keylen))...)
	}else if keylen>8{
		key=key[:8]
	}
	//1.指定解密算法des
	block, err := des.NewCipher(key)
	if err!=nil{
		panic(err)
	}

	//2.指定使用哪种分组模式进行解密 返回一个密码分组链接模式的、底层用b解密的BlockMode接口，初始向量iv必须和加密时使用的iv相同。
	iv:=[]byte("wumansgy")   //初始化向量
	blockMode := cipher.NewCBCDecrypter(block, iv)

	//3. 解密
	plainText := make([]byte,len(cipherText))
	blockMode.CryptBlocks(plainText,cipherText)

	//5. 删除填充的内容
	//删除之前防止出现用户输入两次密钥不一样，引起panic,所以做一个错误处理
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
	unPaddingText := PKCS5UnPadding(plainText)

	return unPaddingText
}