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
	plaintext := []byte("床前明月光，疑是地上霜，举头望明月，学习go语言")//明文
	fmt.Println("明文为：",string(plaintext))

	//传入明文和自己定义的密钥，密钥为8字节，如果不足8字节函数内部自动补全，超过8字节函数内部截取
	cryptText := goEncrypt.DesCBC_Encrypt(plaintext, []byte("asd12345")) //得到密文
	fmt.Println("DES的CBC模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))

	//传入密文和自己定义的密钥，需要和加密的密钥一样，不一样会报错，8字节，如果不足8字节函数内部自动补全，超过8字节函数内部截取
	newplaintext := goEncrypt.DesCBC_Decrypt(cryptText, []byte("asd12345"))  //解密得到密文

	fmt.Println("DES的CBC模式解密完：", string(newplaintext))
}
```

![](image/1.png)

## 1.2三重DES的快速使用

```
func main(){
	plaintext := []byte("床前明月光，疑是地上霜，举头望明月，学习go语言")
	fmt.Println("明文为：",string(plaintext))

	//传入明文和自己定义的密钥，密钥为24字节，如果不足24字节函数内部自动补全，不过超过24字节函数内部截取
	cryptText := goEncrypt.TripleDesEncrypt(plaintext, []byte("wumansgy12345678asdfghjk"))
	fmt.Println("三重DES的CBC模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))

	//传入密文和自己定义的密钥，需要和加密的密钥一样，不一样会报错，24字节，如果不足24字节函数内部自动补全，超过24字节函数内部截取
	newplaintext := goEncrypt.TripleDesDecrypt(cryptText, []byte("wumansgy12345678asdfghjk"))

	fmt.Println("三重DES的CBC模式解密完：", string(newplaintext))
}
```

![](image/2.png)

## 2.1AES的CBC模式的快速使用

```
func main(){
	plaintext := []byte("床前明月光，疑是地上霜，举头望明月，学习go语言")
	fmt.Println("明文为：",string(plaintext))

	//传入明文和自己定义的密钥，密钥为16字节，如果不足16字节函数内部自动补全，超过16字节函数内部截取
	cryptText := goEncrypt.AesCBC_Encrypt(plaintext, []byte("wumansgygoaescry"))
	fmt.Println("AES的CBC模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))

	//传入密文和自己定义的密钥，需要和加密的密钥一样，不一样会报错，16字节，如果不足16字节函数内部自动补全，超过16字节函数内部截取
	newplaintext := goEncrypt.AesCBC_Decrypt(cryptText, []byte("wumansgygoaescry"))

	fmt.Println("AES的CBC模式解密完：", string(newplaintext))
}
```

![](image/3.png)

## 2.1AES的CTR模式的快速使用

```
func main(){
	plaintext := []byte("床前明月光，疑是地上霜，举头望明月，学习go语言")
	fmt.Println("明文为：",string(plaintext))

	//传入明文和自己定义的密钥，密钥为16字节，如果不足16字节函数内部自动补全，超过16字节函数内部截取
	cryptText := goEncrypt.AesCTR_Encrypt(plaintext, []byte("wumansgygoaesctr"))
	fmt.Println("AES的CTR模式加密后的密文为:", base64.StdEncoding.EncodeToString(cryptText))

	//传入密文和自己定义的密钥，需要和加密的密钥一样，不一样会报错，16字节，如果不足16字节函数内部自动补全，超过16字节函数内部截取
	newplaintext := goEncrypt.AesCTR_Decrypt(cryptText, []byte("wumansgygoaesctr"))

	fmt.Println("AES的CTR模式解密完：", string(newplaintext))
}
```

![](image/4.png)

## 3. 非对称加密RSA的快速使用

##### 非对称加密需要先生成一对公钥和私钥，公钥和私钥是成对出现的，公钥加密只能私钥解密，私钥加密只能公钥解密，（一般加密都是使用私钥加密，公钥解密，数字签名就是使用私钥加密消息的哈希，然后公钥解密得到哈希查看是否和消息的哈希一样）

#### 3.1 使用

先直接调用GetKet()就可以在本地生成一个私钥文件，一个公钥文件

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
func main() {
	plaintext := []byte("床前明月光，疑是地上霜,举头望明月，低头学编程")
	//把生成的文件里面复制过来，头和尾也需要，用反引号包含起来
	privatekey := []byte(`-----BEGIN  wuman private key-----
MIIEpAIBAAKCAQEAzwD90zCxWsoV7in9XifMYqZlWM9FUcbDDMqgYQJ06IAT+DJb
w9yMdlw/bWYZ6usDkaKoShauXhafcWME0N6rRubRfYT5K0Ye1pav+7HyEBOBihvW
Cc6XzOCd4Z5Zws9/ustqzdTTFQDrXDJGNZ1I0PVa6ERYJFyFkyaIuhM1P29yat6/
zWmkvkz91E6cJyLEKSbuWLeSz0zqYur77/+c+A/xg9IimPjimwxFB/pjieBwDsq8
/PRDfxgezhVCgZikKexp7fl4yEbqxrPbQgNwad6gP18x4SD9oHZEkQsMHADpGK57
k6tNkxnnB+AlAjXOuzwXh/8Q0vN9FsSW++hW/wIDAQABAoIBABMSTlBkzhJFSBv3
Nma0V/pGxlOWVRahr1rAWGJXrZm2IyDc0uOKsE4/VYCoxX6FRIDocYTR7iKxBuOV
cd4khbc0kNx1oddA0JqIq5IO5PRiN68XvXKN3CJ+F02wHyj5oRT+pMpt7zyiJw0J
fLp30TufP07i7RP8ijnydOpf1qoPWd/v4RLvx4RvrcYI/QmQYLmC0XqbzRIJtn8y
NwVSv/GbPznl7q0th2kkSpa2qgMU3KgiC5ojaHKgI0zQuYfh7Z9HSAypMi7NJp4e
UMwhAQYIlKshH94+wUo4gu4Xy52e+mh1HMhM/CDBWguyQ6xXBrvfZ0vnbxaMaAuI
yk/unNECgYEA/1J65iLIp3kbHPwtxrG5NF9KM+ArAxRjkRyQynzg05n2en/4/q6I
KJJc2/bBnS1XuZsPcRTVnaaGIEvFykC5kW0m0y5K9Xtzj6gaU/yxIc9v6iMDeEbi
Vp5/mttCTbHWQpGv81Nm3uXPU8QUsz5GkMyecq5fEr3psLpMhnI/k00CgYEAz42s
elImcH/Sulvej/yv7ivn9t7CVf2c7LJv+gMy6hV2nufQ+bmWxnh1lz0X19ccxzMW
S04r754JOI3Xd+Ny5OVvjJNdfyUrUHdXhJ+NnZbjRskY3P1CqFKysTs5BsVMJNAb
52rYTIPZFXetSJ0RdD+XJl0HO3m2gM9q18dEVXsCgYAF0gWHNYfJeZNKp90LSIXm
Ub3JTPTuDwruBe6vDwW5DSt3Q2+Trrrf4eZIBWoIgT4ctxI1C7qK637nQZLyt2MD
k69s5QNEcVoDDlv7SilnkekFN2Me3M7QFrDmANWUG9e8kMGoFGCl+Csvx6qJI4RM
TL3X822rabToGHciIXydiQKBgQC1bDtluMVM9Q54Q7Gp3tDRuaNL0a/BhqxS4i6r
NXydzSEhCbVLdIRs/AKdrpNW4fuPzAIi1TPmghfBTYsYisJ1fnAhSvchGpZgAdGI
ZgddxvTnfQS0ttQ7Wf5EmWXhmzhRvW+Gu4hSabWp5DCeFl2ZZbRznkGiJWP3+FaG
QvJiXQKBgQCKAI0z3LHCam8HfxO2Wh3XHahUOcCIeLW/rpYGBBLEX7e2/KAG9j1h
WETHrMwZieNcwXPC6BIf1dpq7uAgLCStHuEdf4RK4GkcObu9+Da8pJ7JMz+6Up+c
MHF5Er1BJwsLFlc1TXMRnj49hoK1k5YhGwd2jhWhvGNF562zYtaZSA==
-----END  wuman private key-----
`)
	publickey := []byte(`-----BEGIN wuman public key-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzwD90zCxWsoV7in9XifM
YqZlWM9FUcbDDMqgYQJ06IAT+DJbw9yMdlw/bWYZ6usDkaKoShauXhafcWME0N6r
RubRfYT5K0Ye1pav+7HyEBOBihvWCc6XzOCd4Z5Zws9/ustqzdTTFQDrXDJGNZ1I
0PVa6ERYJFyFkyaIuhM1P29yat6/zWmkvkz91E6cJyLEKSbuWLeSz0zqYur77/+c
+A/xg9IimPjimwxFB/pjieBwDsq8/PRDfxgezhVCgZikKexp7fl4yEbqxrPbQgNw
ad6gP18x4SD9oHZEkQsMHADpGK57k6tNkxnnB+AlAjXOuzwXh/8Q0vN9FsSW++hW
/wIDAQAB
-----END wuman public key-----`)

	//直接传入明文和公钥加密得到密文
	crypttext, err := goEncrypt.RsaEncrypt(plaintext, publickey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("密文", hex.EncodeToString(crypttext))
	//解密操作，直接传入密文和私钥解密操作，得到明文
	plaintext, err = goEncrypt.RsaDecrypt(crypttext, privatekey)
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
func main(){
	privateKey:=[]byte(`-----BEGIN  WUMAN  PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Pmhu/ECgMytk5SxCVmsntiSCv8wKvhCpTTX9DBWNFWYPk9+
9M0m4FszP2dXoz2TfFi4JYhAWx0S558pAAE71RmEZ4juF0Ah7ESnXsMNqjh04yL+
CnaYaPnJR6hpA1yuCoVmOmlDUQazJ5d+xc1SJt+hxpJBq/fqyCkMaXfAKKR/IWSY
Q8csKeSdQfXkf01vjTr0FniCwBEn8QaWin0ltX+sB2YRfrPNPAYc0LcjUCVs+OX8
qeEthgZj+MAEJe5KE6d2BaXXEPQBuTClXfG+LuQ+kK5350RFfwe1YH6a/Mjun9g0
z0Faljf96n4JvCIruHoGUUXOadIlaLRFfXvFJwIDAQABAoIBACMqHoEVqSorRvoS
h0ffgyCnqMuY7W4NoIlUPxKkH51m2duCXQasjuIp9pGwvhqF/g9qjnIiX1H1rnyz
V57clkjhploVvJrE+/BaDR/xCpeeMG0YMk9obXUcszYPrLwYGGFE2VLy65Ty36rF
31tBlZVdBEf5zHs3mJZd8ey9beRom+h2AgD7cRXaRNL1iEpc4RLETchDAiP8vUQc
ov55CBkuj8pNrRwdIDfX52j5CruXebJOx3YXDO1SjN/UX3fG91Ev+i4s8KDnURcG
dULxFrqc7U3uCb4ZzARyNdBySqHa94NA1E0+xYijHKXADT/7OFsKceQNRfRUR4Cn
f0uOuOECgYEA727Y1pJAKODTwDV0el3FIPVujCcSCem15yD6q6YWkqnaQeaeWOz3
kQ+33z+ICLtAhygv2/cGQbL5/3FXhCpKPRNU7GgzuIcjzOBGfeZilF+PLiNJp0L6
QZ5Vst1DwnZxc/uK69JXEtUUNb7CcAApbf/3XtMllj4hG+OUsok//K0CgYEA329G
VkjA/7oVuP4mto1+wY4cD/0f2MeGlk/c9DLE8qJhVGFHsCu6phj9MiArZYAi5Qfy
6AmF46UBMvtyi2aNghZYZu4oJFhqfAMsidxAegsLtgN2R34LMkC/g5yTotn3b4pj
NYh/P1GDfDIfoMpaapA9RTHRni49WCVp293mz6MCgYEAluV+JSTA6MJg0Xce9Gua
bB4h0JRjCvpO2N5w/LLM8Ru44OWOEC8wCy0jzcAFZLNWhJewKenx+H/qjLGK3VGl
vf4r/F3jkr0gs+L4qioDIM1kuEgnCBHvFGHMUtCd/rWU5Oq37819cPH3LbQOaHXB
poC2Dv31Z026og/4y9gyCnUCgYEAhUQIbtRsENs7s6AbFQ0mCmopgLvYL+Mp+iNe
RWS2pYWGid6P9JrQc9s5wZkAaUTZC0QHdLChZBr5sR/avRyI0ItlZNctqCf4M0lt
Wji9WE2YSZKdDJ04LlwCHozYXeylsaiX7ckhJHII+52l0bB/50lq0geZ4D/yJM4D
6rjavwMCgYAKDPYuEO4vaES2B5bE3aFiLFySBV+VjmLpiOndymC8OdYF5J+p0XWG
lDQfXWXnrHJ/e6rcH4BmhGz4qk6EN9SLUrd2DNbQ+tzXJIkPBBBZ8ykyQ/p0u/52
edc9SE3vb69yiVPqDinw63ZWFkIqMjh5uSXXQAn/dYSWGhaCzFhcaA==
-----END  WUMAN  PRIVATE KEY-----
`)
	publicKey:=[]byte(`-----BEGIN WUMAN  PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Pmhu/ECgMytk5SxCVms
ntiSCv8wKvhCpTTX9DBWNFWYPk9+9M0m4FszP2dXoz2TfFi4JYhAWx0S558pAAE7
1RmEZ4juF0Ah7ESnXsMNqjh04yL+CnaYaPnJR6hpA1yuCoVmOmlDUQazJ5d+xc1S
Jt+hxpJBq/fqyCkMaXfAKKR/IWSYQ8csKeSdQfXkf01vjTr0FniCwBEn8QaWin0l
tX+sB2YRfrPNPAYc0LcjUCVs+OX8qeEthgZj+MAEJe5KE6d2BaXXEPQBuTClXfG+
LuQ+kK5350RFfwe1YH6a/Mjun9g0z0Faljf96n4JvCIruHoGUUXOadIlaLRFfXvF
JwIDAQAB
-----END WUMAN  PUBLIC KEY-----`)
	msg:=[]byte("RSA数字签名测试")
	signmsg,err:=goEncrypt.RsaSign(msg,privateKey)
	if err!=nil{
		fmt.Println(err)
		return
	}
	fmt.Println("RSA数字签名的消息为：",hex.EncodeToString(signmsg))

	//验证数字签名正不正确
	result:=goEncrypt.RsaVerifySign(msg,signmsg,publicKey)
	if result{   //如果result返回的是true那么就是本人签名，否则不是，只有私钥加密，相对的公钥验证才可以认为是本人
		fmt.Println("RSA数字签名正确，是本人")
	}else{
		fmt.Println("RSA数字签名错误，不是本人")
	}

}
```

![](image/11.png)

## 4.ECC椭圆曲线应用

**（GO里面只有ECC数字签名的接口，所以我们这里先实现一下ECC的数字签名功能，后期再把ECC椭圆曲线加密的函数封装好上传）**

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
func main(){
	privateKey:=[]byte(`-----BEGIN WUMAN ECC PRIVATE KEY-----
MIHcAgEBBEIAZEdmSEQlu9jHzVTOHzGnQOhGNtj79Z/Hu14bYb7SidfyCS39ITZ4
ShSJ4E5OfXcXI2eXTX9jQb/BPbufumLxdf2gBwYFK4EEACOhgYkDgYYABAEAmpB3
ckiCr/9GIj6ujTs9fl7K2kBaM+0MhAnFDcCe8VtBqgn7SC860WxHyNFVUPaUvABC
ytMOTf4v9m+aEaHONwA2xf/V35oCMAiVKwx9kovR42m/0XRPEpbuocaIflVDdQK9
6BDdzYQrU+s/GL3TXxBE+L1b9+c5ZfJdDsMHXqMxJA==
-----END WUMAN ECC PRIVATE KEY-----`)
	publicKey:=[]byte(`-----BEGIN WUMAN ECC PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBAJqQd3JIgq//RiI+ro07PX5eytpA
WjPtDIQJxQ3AnvFbQaoJ+0gvOtFsR8jRVVD2lLwAQsrTDk3+L/ZvmhGhzjcANsX/
1d+aAjAIlSsMfZKL0eNpv9F0TxKW7qHGiH5VQ3UCvegQ3c2EK1PrPxi9018QRPi9
W/fnOWXyXQ7DB16jMSQ=
-----END WUMAN ECC PUBLIC KEY-----`)
	msg:=[]byte("数字签名测试")
	rtext,stext:=goEncrypt.EccSign(msg,privateKey)

	fmt.Println("数字签名的消息为：",hex.EncodeToString(rtext)+hex.EncodeToString(stext))

	//验证数字签名正不正确
	result:=goEncrypt.EccVerifySign(msg,publicKey,rtext,stext)
	if result{   //如果result返回的是true那么就是本人签名，否则不是，只有私钥加密，相对的公钥验证才可以认为是本人
		fmt.Println("数字签名正确，是本人")
	}else{
		fmt.Println("数字签名错误，不是本人")
	}
}
```

![](image/15.png)

> ECC椭圆曲线技术应用广泛，目前我国居民身份证数字签名技术就是使用的ECC，虚拟货币比特币和以太坊中也使用了ECC技术，后面我们会把ECC加密的方法也实现好。

#### 4.3 ECC用作加密十用（非对称加密是用公钥来加密，私钥来解密的，由于GO标准包中没有实现ECC加密的接口，只实现了ECC数字签名的接口，我们找了以太坊源码中的ECC加密的使用方法，稍加改造了一下，拿过来用了，在这里调用了以太坊加密包里面的接口来实现ECC加密的方法，我们把加密的东西二次封装了一下，下载包后就可以直接使用）

首先还是先得到公钥和私钥

```
func main(){
    goEncrypt.GetEccKey()
}     //这里我们得到的密钥是通过P256曲线得到的，由于之前验证用别的曲线调用以太坊接口会报错
```

然后就可以快速使用了

```
func main(){
	plainText:=[]byte("窗前明月光，疑是地上霜,ECC加密解密")

	//这里传入的私钥和公钥是要用GetECCKey里面得到的私钥和公钥，如果自己封装的话，
	// 获取密钥时传入的第一个参数是要用这条曲线elliptic.P256()，如果用别的会报无效公钥错误，
	// 例如用P521()这条曲线
	privateKey:=[]byte(`-----BEGIN WUMAN ECC PRIVATE KEY-----
MHcCAQEEIKozbXD9G6bGPJ26cCAfEdLrqAe697F8SiLRMdqxzNQ5oAoGCCqGSM49
AwEHoUQDQgAEk3/hltyR0r0J2Wkkhi4HaREJXS1vFooGpsKCbLvrdUW4peVIwKEW
+yC3/g2X7Q2A8ftJlYv2X4kDU180GhIQpA==
-----END WUMAN ECC PRIVATE KEY-----
`)
	publicKey:=[]byte(`-----BEGIN WUMAN ECC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk3/hltyR0r0J2Wkkhi4HaREJXS1v
FooGpsKCbLvrdUW4peVIwKEW+yC3/g2X7Q2A8ftJlYv2X4kDU180GhIQpA==
-----END WUMAN ECC PUBLIC KEY-----
`)

	cryptText,_:=goEncrypt.EccPublicEncrypt(plainText,publicKey)
	fmt.Println("ECC传入公钥加密的密文为：",hex.EncodeToString(cryptText))

	msg,err:=goEncrypt.EccPrivateDeCrypt(cryptText,privateKey)
	if err!=nil{
		fmt.Println(err)
	}
	fmt.Println("ECC传入私钥解密后的明文为：",string(msg))


}
```

![](image/16.png)

## 5.附带的哈希函数sha256和sha512使用非常简单

#### 5.1 sh256的快速使用

```
func main(){
	//获取文件哈希的时候，需要传入文件的路径就行了，如果传入文件夹会报错
	fileHash,err:=goEncrypt.GetFileStringHash256("D:/gocode/播放器.zip")
	if err!=nil{
		fmt.Println(err)
		return
	}
	fmt.Println("文件的哈希为：",fileHash)

	//得到普通字符串哈希直接传入字符串就行
	Hash:=goEncrypt.GetStringHash256("得到普通哈希")
	fmt.Println("普通字符串哈希:",Hash)

}
```

![](image/9.png)

#### 5.2 sha512的快速使用

```
func main(){
	//获取文件哈希的时候，需要传入文件的路径就行了，如果传入文件夹会报错
	fileHash,err:=goEncrypt.GetFileStringHash512("D:/gocode/播放器.zip")   
	if err!=nil{
		fmt.Println(err)
		return
	}
	fmt.Println("文件的哈希为：",fileHash)

	//得到普通字符串哈希直接传入字符串就行
	Hash:=goEncrypt.GetStringHash512("得到普通哈希")
	fmt.Println("普通字符串哈希:",Hash)
}
```

![](image/10.png)

#### 5.3  上面两个函数内部已经转换为16进制的字符串了，如果需要返回哈希切片[]byte类型用下面两个函数就行了

```
func main(){
    goEncrypt.GetFileHash256
    goEncrypt.GetFileHash512
    goEncrypt.GetHash256
    goEncrypt.GetHash512
}   //用这几个函数就可以了，得到的就是哈希的[]byte类型
```



