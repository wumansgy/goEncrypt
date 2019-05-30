## goEncrypt

[![](https://img.shields.io/badge/Auther-blog-blue.svg)](https://github.com/wumansgy)   [![](https://img.shields.io/badge/Open%20Source-Y-brightgreen.svg)](https://github.com/wumansgy)

go语言封装的各种对称加密和非对称加密，可以直接使用，包括3重DES，AES的CBC和CTR模式，还有RSA非对称加密

下载到本地可以直接调用

使用方法

```
go get github.com/wumansgy/goEncrypt
```

然后下载到本地可以直接调用，包括了DES的CBC模式的加密解密（虽然DES早就被破解，但是可以参考使用），三重DES的加密解密（可以使用），AES的CBC模式和CTR模式（对称加密中常用的加密算法），非对称加密RSA的加密解密（比较常用的非对称加密算法），椭圆曲线加密算法（后面更新），还有哈希函数sha256，sha512的快速使用（MD5，SHA1已经在2004，2005年被陆续攻破，现在常用sha256和sha512）

## 1.1DES的快速使用

```
func main(){
	plaintext := []byte("床前明月光，疑是地上霜，举头望明月，学习go语言") //明文
    	fmt.Println("明文为：", string(plaintext))
    
    	// 传入明文和自己定义的密钥，密钥为8字节
    	cryptText, err := goEncrypt.DesCbcEncrypt(plaintext, []byte("asd12345")) //得到密文
    	if err != nil {
    		fmt.Println(err)
    	}
    	fmt.Println("DES的CBC模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))
    
    	// 传入密文和自己定义的密钥，需要和加密的密钥一样，不一样会报错，8字节 如果解密秘钥错误解密后的明文会为空
    	newplaintext, err := goEncrypt.DesCbcDecrypt(cryptText, []byte("asd12345")) //解密得到密文
    	if err != nil {
    		fmt.Println(err)
    	}
    
    	fmt.Println("DES的CBC模式解密完：", string(newplaintext))
}
```

![](image/1.png)

## 1.2三重DES的快速使用

```
func main(){
	plaintext := []byte("床前明月光，疑是地上霜，举头望明月，学习go语言")
    	fmt.Println("明文为：", string(plaintext))
    
    	// 传入明文和自己定义的密钥，密钥为24字节
    	cryptText, err := goEncrypt.TripleDesEncrypt(plaintext, []byte("wumansgy12345678asdfghjk"))
    	if err != nil {
    		fmt.Println(err)
    	}
    	fmt.Println("三重DES的CBC模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))
    
    	// 传入密文和自己定义的密钥，需要和加密的密钥一样，不一样会报错
    	newplaintext, err := goEncrypt.TripleDesDecrypt(cryptText, []byte("wumansgy12345678asdfghjk"))
    	if err != nil {
    		fmt.Println(err)
    	}
    
    	fmt.Println("三重DES的CBC模式解密完：", string(newplaintext))
}
```

![](image/2.png)

## 2.1AES的CBC模式的快速使用

```
func main(){
	plaintext := []byte("床前明月光，疑是地上霜，举头望明月，学习go语言")
    	fmt.Println("明文为：",string(plaintext))
    
    	// 传入明文和自己定义的密钥，密钥为16字节
    	cryptText,err := goEncrypt.AesCbcEncrypt(plaintext, []byte("wumansgygoaescry"))
    	if err!=nil{
    		fmt.Println(err)
    	}
    	fmt.Println("AES的CBC模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))
    
    	// 传入密文和自己定义的密钥，需要和加密的密钥一样，不一样会报错
    	newplaintext ,err:= goEncrypt.AesCbcDecrypt(cryptText, []byte("wumansgygoaescry"))
    	if err!=nil{
    		fmt.Println(err)
    	}
    
    	fmt.Println("AES的CBC模式解密完：", string(newplaintext))
}
```

![](image/3.png)

## 2.1AES的CTR模式的快速使用

```
func main(){
	plaintext := []byte("床前明月光，疑是地上霜，举头望明月，学习go语言")
    	fmt.Println("明文为：",string(plaintext))
    
    	//传入明文和自己定义的密钥，密钥为16字节
    	cryptText ,err:= goEncrypt.AesCtrEncrypt(plaintext, []byte("wumansgygoaesctr"))
    	if err!=nil{
    		fmt.Println(err)
    	}
    	fmt.Println("AES的CTR模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))
    
    	//传入密文和自己定义的密钥，需要和加密的密钥一样，不一样会报错
    	newplaintext ,err:= goEncrypt.AesCtrDecrypt(cryptText, []byte("wumansgygoaesctr"))
    	if err!=nil{
    		fmt.Println(err)
    	}
    
    	fmt.Println("AES的CTR模式解密完：", string(newplaintext))
}
```

![](image/4.png)

## 3. 非对称加密RSA的快速使用

##### 非对称加密需要先生成一对公钥和私钥，公钥和私钥是成对出现的，公钥加密只能私钥解密，私钥加密只能公钥解密，（一般加密都是使用私钥加密，公钥解密，数字签名就是使用私钥加密消息的哈希，然后公钥解密得到哈希查看是否和消息的哈希一样）

#### 3.1 使用

先直接调用GetKey()就可以在本地生成一个私钥文件，一个公钥文件

```
func main() {
	goEncrypt.GetRsaKey()
}
```

![](image/7.png)

![](image/5.png)

![](image/6.png)

#### 3.2 RSA加解密使用（公钥加密私钥解密）

```
const (
	privateKey = `-----BEGIN  WUMAN RSA PRIVATE KEY -----
MIIEpQIBAAKCAQEArDuxlkVpBB4zPoNzBh9F0OLeR8kk/8/ewryuVlj2/SM5gLaN
I8jXt1Fpc9nNBMZlqNttZyf+h0PA9N2QDLhhLreB566m+H4TrobaRfrhe2ZQG/E2
8XuebqcWRLsqOBc/6ydywcpmk3JSlIMYCLzTM1p1XlA1mrJPc7GlDKCRcUiPDn+n
Z67n2dbXqrpDCykNh3gAFNIrD4vCuB5LEcW8NLGMSBW8/zOxNdeC3S+8ni6HjXsj
Wft85zlcvoe0nGgsPITa0PGBSC/BIVZwYCW7A0+CrDSvVGp9QPuQhdCyf6INduHp
INzeoz7RS2rqoo0ERgctwn62vL7mOnubAruJnwIDAQABAoIBAQCOcG/WD2Fifndy
49Nk5MggkP+z7q4iwg9AjjrAPqNFhrQvtsnTJm8AtNu5bA8aO9onZBF+lpzx0R7r
Y7GWU4ZL1Igiy1ZbfCla1Tv/VBTWsS7fbQY7gDju2lCYVxH7gX7jQ6SskG900b9q
A2EFGOSyO8WFUmCCp6T90ZTmdITUYgk8iNO2bhte0ypHVef3MUrxAu6YnQUIrFIA
zP+Aq09He68ddun38uymOrIpglL5c9pQBpMLZCz866kYfHiyGbGEUyJ60rpqj6u8
1GHDIxtpM9ltwig8nygwrDmkkJw+t1QkxhIPMNbI9B7S/lzMFIZG25puWdoOg5K+
El5zRbBBAoGBAOOQtxYWKQLIDPvddbdGD3qA9J3gAOlGUO8l4V558i+aCdfwZ9NX
O744TvqlMc4P3BrqAt5naKo4tV8mxHz7bo846Y/zOAj/eO72s3Acrn0H6Pmakndn
2TIvl04m6cqoIISoorBuN9KwUImhzar1+0xxuMK2yjChGQivb4wSuC9bAoGBAMHB
CGMSaW73Cv8VBb+9RbLBOUmD7JZcqg5ENvPb50YVEVKpCre/CF1G4QZnbg85FRR3
LjG+NLJBk1dQn4EEE44iwhEGgj1jdO4lCziuJoAWTsFwHpTiJDhdW78ZNsgHejC+
tNrQB0y+Uah5c06p4VJu/kSbr/MoFzenqiva3wYNAoGBAIbZ1uTrtNnFGoyWK4+z
oLCDgnGbsG6MEKHm3KpTsUSsD3E7MQt4Ahsy2vqEsgLeOxxn19NbjBZzDGeaXY2C
oX2VyDJZerc6TLuuzZ5+IJhO+6wOAQVpMLggo5TYUmqZPsvd8qqCZeogOVmV3H6W
zZf7O/WGxEIU9PTEoWFsJmFJAoGAFpD1+hv93ae2Rylapw9TW9N3aaGM36JhSBIX
2GUnVZlEkD0R+36rabnEoatQPUOnud97qN1/Y7eRgpzoRu2DnY1czwDUEHRR/R6h
ZPObllWCzLLTTQHduBbfha1ZHQkJ6T188PNDtmOAPUAP9vyAOsqkoLcFUiu8MIY9
oqf2S80CgYEAppFtMX0bCbBZJwMWY4oskk1IC4y99ogEL0itMGOyxcaVffKRJtkD
v3jylXAUVxu55chy0rbPe4jtgDx/E5k1ZkTNTytOoB1VGblmuGtKWYQe3ITS6V0x
ss2ih/aaR47pzNvK5Z6G/AKtkAy6EubKKGBgMfg+9iiX/IbweFvvb7Y=
-----END  WUMAN RSA PRIVATE KEY -----`
	publicKey = `-----BEGIN  WUMAN  RSA PUBLIC KEY -----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArDuxlkVpBB4zPoNzBh9F
0OLeR8kk/8/ewryuVlj2/SM5gLaNI8jXt1Fpc9nNBMZlqNttZyf+h0PA9N2QDLhh
LreB566m+H4TrobaRfrhe2ZQG/E28XuebqcWRLsqOBc/6ydywcpmk3JSlIMYCLzT
M1p1XlA1mrJPc7GlDKCRcUiPDn+nZ67n2dbXqrpDCykNh3gAFNIrD4vCuB5LEcW8
NLGMSBW8/zOxNdeC3S+8ni6HjXsjWft85zlcvoe0nGgsPITa0PGBSC/BIVZwYCW7
A0+CrDSvVGp9QPuQhdCyf6INduHpINzeoz7RS2rqoo0ERgctwn62vL7mOnubAruJ
nwIDAQAB
-----END  WUMAN  RSA PUBLIC KEY -----`
)

func main() {
	privateKey := []byte(privateKey)
	publicKey := []byte(publicKey)

	plaintext := []byte("床前明月光，疑是地上霜,举头望明月，低头学编程")
	// 直接传入明文和公钥加密得到密文
	crypttext, err := goEncrypt.RsaEncrypt(plaintext, publicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("密文", hex.EncodeToString(crypttext))
	// 解密操作，直接传入密文和私钥解密操作，得到明文
	plaintext, err = goEncrypt.RsaDecrypt(crypttext, privateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("明文：", string(plaintext))
}
```

![](image/8.png)

> **RSA在非对称加密中使用比较广泛**
>

#### 3.3 RSA加数字签名使用（私钥加密，公钥解密，函数内部是加密消息的哈希）

**快速实现**

```
const (
	privateKey = `-----BEGIN  WUMAN RSA PRIVATE KEY -----
MIIEpQIBAAKCAQEArDuxlkVpBB4zPoNzBh9F0OLeR8kk/8/ewryuVlj2/SM5gLaN
I8jXt1Fpc9nNBMZlqNttZyf+h0PA9N2QDLhhLreB566m+H4TrobaRfrhe2ZQG/E2
8XuebqcWRLsqOBc/6ydywcpmk3JSlIMYCLzTM1p1XlA1mrJPc7GlDKCRcUiPDn+n
Z67n2dbXqrpDCykNh3gAFNIrD4vCuB5LEcW8NLGMSBW8/zOxNdeC3S+8ni6HjXsj
Wft85zlcvoe0nGgsPITa0PGBSC/BIVZwYCW7A0+CrDSvVGp9QPuQhdCyf6INduHp
INzeoz7RS2rqoo0ERgctwn62vL7mOnubAruJnwIDAQABAoIBAQCOcG/WD2Fifndy
49Nk5MggkP+z7q4iwg9AjjrAPqNFhrQvtsnTJm8AtNu5bA8aO9onZBF+lpzx0R7r
Y7GWU4ZL1Igiy1ZbfCla1Tv/VBTWsS7fbQY7gDju2lCYVxH7gX7jQ6SskG900b9q
A2EFGOSyO8WFUmCCp6T90ZTmdITUYgk8iNO2bhte0ypHVef3MUrxAu6YnQUIrFIA
zP+Aq09He68ddun38uymOrIpglL5c9pQBpMLZCz866kYfHiyGbGEUyJ60rpqj6u8
1GHDIxtpM9ltwig8nygwrDmkkJw+t1QkxhIPMNbI9B7S/lzMFIZG25puWdoOg5K+
El5zRbBBAoGBAOOQtxYWKQLIDPvddbdGD3qA9J3gAOlGUO8l4V558i+aCdfwZ9NX
O744TvqlMc4P3BrqAt5naKo4tV8mxHz7bo846Y/zOAj/eO72s3Acrn0H6Pmakndn
2TIvl04m6cqoIISoorBuN9KwUImhzar1+0xxuMK2yjChGQivb4wSuC9bAoGBAMHB
CGMSaW73Cv8VBb+9RbLBOUmD7JZcqg5ENvPb50YVEVKpCre/CF1G4QZnbg85FRR3
LjG+NLJBk1dQn4EEE44iwhEGgj1jdO4lCziuJoAWTsFwHpTiJDhdW78ZNsgHejC+
tNrQB0y+Uah5c06p4VJu/kSbr/MoFzenqiva3wYNAoGBAIbZ1uTrtNnFGoyWK4+z
oLCDgnGbsG6MEKHm3KpTsUSsD3E7MQt4Ahsy2vqEsgLeOxxn19NbjBZzDGeaXY2C
oX2VyDJZerc6TLuuzZ5+IJhO+6wOAQVpMLggo5TYUmqZPsvd8qqCZeogOVmV3H6W
zZf7O/WGxEIU9PTEoWFsJmFJAoGAFpD1+hv93ae2Rylapw9TW9N3aaGM36JhSBIX
2GUnVZlEkD0R+36rabnEoatQPUOnud97qN1/Y7eRgpzoRu2DnY1czwDUEHRR/R6h
ZPObllWCzLLTTQHduBbfha1ZHQkJ6T188PNDtmOAPUAP9vyAOsqkoLcFUiu8MIY9
oqf2S80CgYEAppFtMX0bCbBZJwMWY4oskk1IC4y99ogEL0itMGOyxcaVffKRJtkD
v3jylXAUVxu55chy0rbPe4jtgDx/E5k1ZkTNTytOoB1VGblmuGtKWYQe3ITS6V0x
ss2ih/aaR47pzNvK5Z6G/AKtkAy6EubKKGBgMfg+9iiX/IbweFvvb7Y=
-----END  WUMAN RSA PRIVATE KEY -----`
	publicKey = `-----BEGIN  WUMAN  RSA PUBLIC KEY -----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArDuxlkVpBB4zPoNzBh9F
0OLeR8kk/8/ewryuVlj2/SM5gLaNI8jXt1Fpc9nNBMZlqNttZyf+h0PA9N2QDLhh
LreB566m+H4TrobaRfrhe2ZQG/E28XuebqcWRLsqOBc/6ydywcpmk3JSlIMYCLzT
M1p1XlA1mrJPc7GlDKCRcUiPDn+nZ67n2dbXqrpDCykNh3gAFNIrD4vCuB5LEcW8
NLGMSBW8/zOxNdeC3S+8ni6HjXsjWft85zlcvoe0nGgsPITa0PGBSC/BIVZwYCW7
A0+CrDSvVGp9QPuQhdCyf6INduHpINzeoz7RS2rqoo0ERgctwn62vL7mOnubAruJ
nwIDAQAB
-----END  WUMAN  RSA PUBLIC KEY -----`
)

func main() {
	privateKey := []byte(privateKey)
	publicKey := []byte(publicKey)
	msg := []byte("RSA数字签名测试")
	signmsg, err := goEncrypt.RsaSign(msg, privateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("RSA数字签名的消息为：", hex.EncodeToString(signmsg))

	// 验证数字签名正不正确
	result := goEncrypt.RsaVerifySign(msg, signmsg, publicKey)
	if result { // 如果result返回的是 true 那么就是本人签名，否则不是，只有私钥加密，相对的公钥验证才可以认为是本人
		fmt.Println("RSA数字签名正确，是本人")
	} else {
		fmt.Println("RSA数字签名错误，不是本人")
	}
}
```

![](image/11.png)

## 4.ECC椭圆曲线应用

**（GO里面只有ECC数字签名的接口，所以我们这里实现了ECC的数字签名功能，ECC椭圆曲线加密使用了区块链以太坊中的相关接口,ECC一般只签名使用加密一般不使用）**

#### 4.1 ECC使用

和RSA使用一样，先直接调用GetEccKey()就可以在本地生成一个私钥文件，一个公钥文件

```
func main(){
    goEncrypt.GetEccKey()
}
```

![](image/12.png)

![](image/13.png)

![](image/14.png)

#### 4.2 ECC数字签名快速使用实现

```
const (
	privateKey = `-----BEGIN WUMAN ECC PRIVATE KEY-----
MHcCAQEEIKozbXD9G6bGPJ26cCAfEdLrqAe697F8SiLRMdqxzNQ5oAoGCCqGSM49
AwEHoUQDQgAEk3/hltyR0r0J2Wkkhi4HaREJXS1vFooGpsKCbLvrdUW4peVIwKEW
+yC3/g2X7Q2A8ftJlYv2X4kDU180GhIQpA==
-----END WUMAN ECC PRIVATE KEY-----`
	publicKey = `-----BEGIN WUMAN ECC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk3/hltyR0r0J2Wkkhi4HaREJXS1v
FooGpsKCbLvrdUW4peVIwKEW+yC3/g2X7Q2A8ftJlYv2X4kDU180GhIQpA==
-----END WUMAN ECC PUBLIC KEY-----`
)

func main() {
	privateKey := []byte(privateKey)
	publicKey := []byte(publicKey)
	msg := []byte("数字签名测试")
	rtext, stext, err := goEncrypt.EccSign(msg, privateKey)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("数字签名的消息为：", hex.EncodeToString(rtext)+hex.EncodeToString(stext))

	// 验证数字签名正不正确
	result := goEncrypt.EccVerifySign(msg, publicKey, rtext, stext)
	if result { // 如果result返回的是true那么就是本人签名，否则不是，只有私钥加密，相对的公钥验证才可以认为是本人
		fmt.Println("数字签名正确，是本人")
	} else {
		fmt.Println("数字签名错误，不是本人")
	}
}
```

![](image/15.png)

> ECC椭圆曲线技术应用广泛，目前我国居民身份证数字签名技术就是使用的ECC，虚拟货币比特币和以太坊中也使用了ECC技术,ECC加密一般不使用。

#### 4.3 ECC用作加密使用（非对称加密是用公钥来加密，私钥来解密的，由于GO标准包中没有实现ECC加密的接口，只实现了ECC数字签名的接口，我们找了以太坊源码中的ECC加密的使用方法，稍加改造了一下，拿过来用了，在这里调用了以太坊加密包里面的接口来实现ECC加密的方法，我们把加密的东西二次封装了一下，下载包后就可以直接使用）

首先还是先得到公钥和私钥

```
func main(){
    goEncrypt.GetEccKey()
}     // 这里我们得到的密钥是通过P256曲线得到的，由于之前验证用别的曲线调用以太坊接口会报错
```

然后就可以快速使用了

```
const (
	privateKey = `-----BEGIN WUMAN ECC PRIVATE KEY-----
MHcCAQEEIKozbXD9G6bGPJ26cCAfEdLrqAe697F8SiLRMdqxzNQ5oAoGCCqGSM49
AwEHoUQDQgAEk3/hltyR0r0J2Wkkhi4HaREJXS1vFooGpsKCbLvrdUW4peVIwKEW
+yC3/g2X7Q2A8ftJlYv2X4kDU180GhIQpA==
-----END WUMAN ECC PRIVATE KEY-----`
	publicKey = `-----BEGIN WUMAN ECC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk3/hltyR0r0J2Wkkhi4HaREJXS1v
FooGpsKCbLvrdUW4peVIwKEW+yC3/g2X7Q2A8ftJlYv2X4kDU180GhIQpA==
-----END WUMAN ECC PUBLIC KEY-----`
)

func main() {
	plainText := []byte("窗前明月光，疑是地上霜,ECC加密解密")

	// 这里传入的私钥和公钥是要用GetECCKey里面得到的私钥和公钥，如果自己封装的话，
	// 获取密钥时传入的第一个参数是要用这条曲线elliptic.P256()，如果用别的会报无效公钥错误，
	// 例如用P521()这条曲线
	privateKey := []byte(privateKey)
	publicKey := []byte(publicKey)

	cryptText, _ := goEncrypt.EccEncrypt(plainText, publicKey)
	fmt.Println("ECC传入公钥加密的密文为：", hex.EncodeToString(cryptText))

	msg, err := goEncrypt.EccDecrypt(cryptText, privateKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("ECC传入私钥解密后的明文为：", string(msg))
}
```

![](image/16.png)

## 5.附带的哈希函数sha256和sha512使用非常简单

#### 5.1 sh256的快速使用

```
func main() {
	// sha256 和 sha256Hex
	hash := goEncrypt.Sha256Hex([]byte("test"))
	fmt.Println(hash)
}
```

![](image/9.png)

#### 5.2 sha512的快速使用

```
func main() {
	// sha512 和 sha512Hex
	hash := goEncrypt.Sha512Hex([]byte("test"))
	fmt.Println(hash)
}
```




