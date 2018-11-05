package goEncrypt

import (
	"bytes"
)

/*
@Time : 2018/11/1 21:16 
@Author : wuman
@File : padding
@Software: GoLand
*/
/**
1. 对明文进行分组
	若分组不是blocksize的整数倍,需要考虑补齐blocksize位
  若使用des算法, 块大小8字节
	若使用AES算法，快大小16字节就填充16字节
	hellowor ld666666
	hellowor 88888888
   使用分组加密模式的时候填充数据的工具
 */

// 使用pks5的方式填充
func PKCS5Padding(plainText []byte, blockSize int) []byte{
	// 1. 计算最后一个分组缺多少个字节
	padding := blockSize - (len(plainText)%blockSize)
	// 2. 创建一个大小为padding的切片, 每个字节的值为padding
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	// 3. 将padText添加到原始数据的后边, 将最后一个分组缺少的字节数补齐
	newText := append(plainText, padText...)
	return newText
}

func PKCS5UnPadding(plainText []byte)[]byte{
	//0. 获取总长度
	length := len(plainText)
	// 1.获取最后一个字节
	number:= int(plainText[length-1])
	//2. 删除最后一个字节数
	return plainText[:length-number]
}