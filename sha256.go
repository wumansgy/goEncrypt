package goEncrypt

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"io"
)

/*
@Time : 2018/11/2 17:05 
@Author : wuman
@File : sha256
@Software: GoLand
*/

/*
利用sha256，包含两种获取哈希值函数，传入文件路径函数和传入字符串切片函数
*/
//文件路径不能传入文件夹
func GetFileStringHash256(filePath string)(hash string,err error){
	//0.创建一个sha256 hash对象
	myhash := sha256.New()
	//1. 读取文件
	file, err := os.Open(filePath)
	if err!=nil{
		return "",err
	}
	defer file.Close()
	// 计算hash值 sha256 , write([]byte)  sum(nil)
	_, err = io.Copy(myhash, file)
	if err != nil {
		return "",err
	}

	// 计算hash值
	sumResult := myhash.Sum(nil)

	// 转成16进制的数据
	hash = hex.EncodeToString(sumResult)

	return hash,nil

}
//返回切片类型
func GetFileHash256(filePath string)(hash []byte,err error){
	//0.创建一个sha256 hash对象
	myhash := sha256.New()
	//1. 读取文件
	file, err := os.Open(filePath)
	if err!=nil{
		return []byte{},err
	}
	defer file.Close()
	// 计算hash值 sha256 , write([]byte)  sum(nil)
	_, err = io.Copy(myhash, file)
	if err != nil {
		return []byte{},err
	}

	// 计算hash值
	hash= myhash.Sum(nil)

	return hash,nil

}

func GetStringHash256(text string)string{
	//1.new一个指定的hash函数
	stringHash:=sha256.New()   //返回hash.Hash
	//2.向hash中添加数据
	stringHash.Write([]byte(text))
	//3. 计算hash结果
	temp:=stringHash.Sum(nil)
	//4. 固定长度的字符串
	hash:=hex.EncodeToString(temp)
	return hash  //返回哈希
}
func GetHash256(text string)[]byte{
	//1.new一个指定的hash函数
	stringHash:=sha256.New()   //返回hash.Hash
	//2.向hash中添加数据
	stringHash.Write([]byte(text))
	//3. 计算hash结果
	hash:=stringHash.Sum(nil)

	return hash  //返回哈希
}