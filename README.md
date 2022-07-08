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

```go
// des
func main() {
	msg := "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	desSecretKey := "12345678"
	base64Text, err := des.DesCbcEncryptBase64([]byte(msg), []byte(desSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("DES模式加密后的base64密文为:\n%s\n", base64Text)
	plaintext, err := des.DesCbcDecryptByBase64(base64Text, []byte(desSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("DES模式解密后:\n%s\n", string(plaintext))

	/*DES模式加密后的base64密文为:
	kzott0GFh9Rg0rsg1X2RP/F4YQ0tOBe6NfKjmAqiDfUrgqcw1P8Dix6IWe07DS2kJ7RZinPynHyiG+xB3NTajXBog4ayohan
	DES模式解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/

	hexText, err := des.DesCbcEncryptHex([]byte(msg), []byte(desSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("DES模式加密后的hex密文为:\n%s\n", hexText)
	plaintext, err = des.DesCbcDecryptByHex(hexText, []byte(desSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("DES模式解密后:\n%s\n", string(plaintext))

	/*DES模式加密后的hex密文为:
	933a2db7418587d460d2bb20d57d913ff178610d2d3817ba35f2a3980aa20df52b82a730d4ff038b1e8859ed3b0d2da427b4598a73f29c7ca21bec41dcd4da8d70688386b2a216a7
	DES模式解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/
}
```

## 1.2三重DES的快速使用

```go
// triple_des
func main() {

	msg := "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	tripleDesSecretKey := "123456781234567812345678"
	base64Text, err := des.TripleDesEncryptBase64([]byte(msg), []byte(tripleDesSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("三重DES模式加密后的base64密文为:\n%s\n", base64Text)
	plaintext, err := des.TripleDesDecryptByBase64(base64Text, []byte(tripleDesSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("三重DES模式解密后:\n%s\n", string(plaintext))

	/*三重DES模式加密后的base64密文为:
	kzott0GFh9Rg0rsg1X2RP/F4YQ0tOBe6NfKjmAqiDfUrgqcw1P8Dix6IWe07DS2kJ7RZinPynHyiG+xB3NTajXBog4ayohan
	三重DES模式解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/

	hexText, err := des.TripleDesEncryptHex([]byte(msg), []byte(tripleDesSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("三重DES模式加密后的hex密文为:\n%s\n", hexText)
	plaintext, err = des.TripleDesDecryptByHex(hexText, []byte(tripleDesSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("三重DES模式解密后:\n%s\n", string(plaintext))

	/*三重DES模式加密后的hex密文为:
	933a2db7418587d460d2bb20d57d913ff178610d2d3817ba35f2a3980aa20df52b82a730d4ff038b1e8859ed3b0d2da427b4598a73f29c7ca21bec41dcd4da8d70688386b2a216a7
	三重DES模式解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/
}

```


## 2.1AES的CBC模式的快速使用

```go
func main() {
	msg := "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	aesSecretKey := "1234567812345678"
	base64Text, err := aes.AesCbcEncryptBase64([]byte(msg), []byte(aesSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("AES的CBC模式加密后的base64密文为:\n%s\n", base64Text)
	plaintext, err := aes.AesCbcDecryptByBase64(base64Text, []byte(aesSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("AES的CBC模式解密后:\n%s\n", string(plaintext))

	/*AES的CBC模式加密后的base64密文为:
	Y8uCrLL8SavXyiUzpnU+Lmn4mODprYL/odSK3MVmGlseuftpJ6A6szrGl/bfDK18z+EkD7TXNI4WemUdvbHZCtSQ1OwexzDtDWcFETU2Ml8=
	AES的CBC模式解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/

	hexText, err := aes.AesCbcEncryptHex([]byte(msg), []byte(aesSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("AES的CBC模式加密后的hex密文为:\n%s\n", hexText)
	plaintext, err = aes.AesCbcDecryptByHex(hexText, []byte(aesSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("AES的CBC模式解密后:\n%s\n", string(plaintext))

	/*AES的CBC模式加密后的hex密文为:
	63cb82acb2fc49abd7ca2533a6753e2e69f898e0e9ad82ffa1d48adcc5661a5b1eb9fb6927a03ab33ac697f6df0cad7ccfe124067a651dbdb1d90ad490d4ec1ec730ed0d6705113536325f
	AES的CBC模式解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/
}
```


## 2.2AES的CTR模式的快速使用

```go
func main() {

	msg := "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	aesSecretKey := "1234567812345678"
	base64Text, err := aes.AesCtrEncryptBase64([]byte(msg), []byte(aesSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("AES的CTR模式加密后的base64密文为:\n%s\n", base64Text)
	plaintext, err := aes.AesCtrDecryptByBase64(base64Text, []byte(aesSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("AES的CTR模式解密后:\n%s\n", string(plaintext))

	/*AES的CTR模式加密后的base64密文为:
	PzO1cjrO1q1PZeJEPw/fDM/TmZ2r4V+yao+MkDVTvR6pdlxdbFhzs1LF6rrZhUgC257ZQbofd0NTJFUUDwsc6rCcEL50
	AES的CTR模式解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/

	hexText, err := aes.AesCtrEncryptHex([]byte(msg), []byte(aesSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("AES的CTR模式加密后的hex密文为:\n%s\n", hexText)
	plaintext, err = aes.AesCtrDecryptByHex(hexText, []byte(aesSecretKey), nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("AES的CTR模式解密后:\n%s\n", string(plaintext))

	/*AES的CTR模式加密后的hex密文为:
	3f33b5723aced6ad4f65e2443f0fdf0ccfd3999dabe15fb26a8f8c903553bd1ea9765c5d6c5873b352c5eabad9854802db9ed941ba1f7743532455140f0b1ceab09c10be74
	AES的CTR模式解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/

}
```

## 2.3AES的ECB模式的快速使用-不推荐

```go
func main() {

	msg := "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	aesSecretKey := "1234567812345678"
	base64Text, err := aes.AesEcbEncryptBase64([]byte(msg), []byte(aesSecretKey))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("AES的ECB模式加密后的base64密文为:\n%s\n", base64Text)
	plaintext, err := aes.AesEcbDecryptByBase64(base64Text, []byte(aesSecretKey))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("AES的ECB模式解密后:\n%s\n", string(plaintext))

	/*AES的ECB模式加密后的base64密文为:
	piizmMYegn4S5xLmEPEdcixb4gmyq1OpncCkUzWU21kXe6N7SHjvbf5zvmeQ3FH2ZFEb2J21FTNpzVpHGaBNP7wr+6xw7Ucu3vTiAuzaIew=
	AES的ECB模式解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/

	hexText, err := aes.AesEcbEncryptHex([]byte(msg), []byte(aesSecretKey))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("AES的ECB模式加密后的hex密文为:\n%s\n", hexText)
	plaintext, err = aes.AesEcbDecryptByHex(hexText, []byte(aesSecretKey))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("AES的ECB模式解密后:\n%s\n", string(plaintext))

	/*AES的ECB模式加密后的hex密文为:
	a628b398c61e827e12e712e610f11d722c5be209b2ab53a99dc0a4533594db59177ba37b4878ef6dfe73be6790dc51f664511bd89db5153369cd5a4719a04d3fbc2bfbac70ed472edef4e202ecda21ec
	AES的ECB模式解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/
}
```

## 3. 非对称加密RSA的快速使用

##### 非对称加密需要先生成一对公钥和私钥，公钥和私钥是成对出现的，公钥加密只能私钥解密，私钥签名只能公钥验签，（加密都是使用私钥加密，公钥解密，数字签名就是使用私钥签名消息的哈希，然后公钥验证签名）

#### 3.1 使用


```go
func main() {
	msg := "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	rsaBase64Key, err := rsa.GenerateRsaKeyBase64(1024)
	if err != nil {
		fmt.Println(err)
		return
	}
	base64Text, err := rsa.RsaEncryptToBase64([]byte(msg), rsaBase64Key.PublicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("rsa加密后的base64密文为:\n%s\n", base64Text)
	plaintext, err := rsa.RsaDecryptByBase64(base64Text, rsaBase64Key.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("rsa解密后:\n%s\n", string(plaintext))

	/*rsa加密后的base64密文为:
	seAZe5Bojdp58eIf9hh5jf8PiIREr19IOXTc+re4z5crNR29mmXM6UFq5Uc1S53QLggL1+3nVNkA8AUnrw8jr4BM+oSqIvGqa92STz2XKcF7ukjTIakirWkOMRz3/dl8VIIucuJHedH7AOGtN1zhKVQbL3lejwq03J6cLEvz4WE=
	rsa解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/

	base64Sign, err := rsa.RsaSignBase64([]byte(msg), rsaBase64Key.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("rsa签名的base64为:\n%s\n", base64Sign)
	res := rsa.RsaVerifySignBase64([]byte(msg), base64Sign, rsaBase64Key.PublicKey)
	fmt.Printf("rsa验签结果为:\n%v\n", res)

	/*rsa签名的base64为:
	cxe5nwMJB5dJwdvAmk7DPKSw46lL8mkwdhauwEWUXbcxKhh5EQN+ed/YTvTZh/yoWIQMKRqOlPszd6AnKA48Cy7Z5rfjj8rPobmYwGJzCkIWCCISZcaKYN5MOgLwRhyHSRwEwUcb3ZUdlj0QgCZHwleNq++FTtfTDwa9JuwWlSo=
	rsa验签结果为:
	true*/
}
```

```go
func main() {

	msg := "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	rsaHexKey, err := rsa.GenerateRsaKeyHex(1024)
	if err != nil {
		fmt.Println(err)
		return
	}
	HexText, err := rsa.RsaEncryptToHex([]byte(msg), rsaHexKey.PublicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("rsa加密后的Hex密文为:\n%s\n", HexText)
	plaintext, err := rsa.RsaDecryptByHex(HexText, rsaHexKey.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("rsa解密后:\n%s\n", string(plaintext))

	/*rsa加密后的Hex密文为:
	7ff6e0cb36bbb537ffdb142344cf3383a2878253b4123845a16d048c1c22ec5f5e474f6ae3dea15b7d791ded3d34379ccdd452dfd11a21ddd4b35864d97f46798396baeb404b7e0f85239f81f1ed6d7c5b69b5ca7e1590413b7332557f5e02333210c18ad0863f606ff4473cfa70fdfda12ea0f7e8559e304686bda7016a695c
	rsa解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/

	hexSign, err := rsa.RsaSignHex([]byte(msg), rsaHexKey.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("rsa签名的hex为:\n%s\n", hexSign)
	res := rsa.RsaVerifySignHex([]byte(msg), hexSign, rsaHexKey.PublicKey)
	fmt.Printf("rsa验签结果为:\n%v\n", res)

	/*rsa签名的hex为:
	48b2232ac4183ece8aa2f60393d27befff1e38a4d124cff97daa5877cd30d426ce8d78a2f13bab49e1964a340a35a8c90c8c0cca483ae2bba45e68523d32f0427d3c4f82c812fe79dc65d3729a6f9c45161ae00da955954e8d1b2e16a930d567fbe9fb3232e3c115d278e57397d073f0b8181f44ade76ce6bf548178d29bbf32
	rsa验签结果为:
	true
	*/
}
```


> **RSA在非对称加密中使用比较广泛**
>

## 4.ECC椭圆曲线应用

**（GO里面只有ECC数字签名的接口，所以我们这里实现了ECC的数字签名功能，ECC椭圆曲线加密使用了区块链以太坊中的相关接口,ECC一般只签名使用加密一般不使用）**

#### 4.1 ECC使用


```go
func main() {

	msg := "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	eccBase64Key, err := ecc.GenerateEccKeyBase64()
	if err != nil {
		fmt.Println(err)
		return
	}
	base64Text, err := ecc.EccEncryptToBase64([]byte(msg), eccBase64Key.PublicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("ecc加密后的base64密文为:\n%s\n", base64Text)
	plaintext, err := ecc.EccDecryptByBase64(base64Text, eccBase64Key.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("ecc解密后:\n%s\n", string(plaintext))

	/*ecc加密后的base64密文为:
	BAeEe7isXcDruhexWZixs0DqDJT4GUGEp9666ssgtgyixWpE4kxB/RsUbuFGR/eMA7ix+xJ9jet2glQVxUtPzRrLdmW6a31Dya0/bCb3WqpOsrGuC5MaZ3y6z0xkAbw1LGBVms6Ig/56JseK7jbOPCegvtgAO+5kESpjqptX6C/VynGyqEYDj/8PU0UnBwS2TFeAyG5rmwy1Z5P+kmbfNNfaIvKX4yODvJT4BdhATg9tUDkDDXw=
	ecc解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/

	rSign, sSign, err := ecc.EccSignBase64([]byte(msg), eccBase64Key.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("ecc签名的为:\nrSign=%s\nsSign=%s\n", rSign, sSign)
	res := ecc.EccVerifySignBase64([]byte(msg), rSign, sSign, eccBase64Key.PublicKey)
	fmt.Printf("ecc验签结果为:\n%v\n", res)

	/*ecc签名的为:
	rSign=MzA3NTQyOTA4NzE0MzY1Nzg4MzU0OTkxNzk0NDIxODcyMTk4NjY0NzY5NzgzNDI5MjYxMjUwMTUxNjE1MzYzODM5MDI0ODMyNDg0MDU=
	sSign=MTUxMjc1NDAyMTY5NDE1NjY3MDU2ODU2ODk4MjcxNjcxMDMwNzAwODMyMjUwMjUwMTQ3MTU3NDY3NjgyNTEyODE2NDA5NzYwNTYxODQ=
	ecc验签结果为:
	true
	*/
}
```

```go
func main() {

	msg := "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	eccHexKey, err := ecc.GenerateEccKeyHex()
	if err != nil {
		fmt.Println(err)
		return
	}
	hexText, err := ecc.EccEncryptToHex([]byte(msg), eccHexKey.PublicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("ecc加密后的hex密文为:\n%s\n", hexText)
	plaintext, err := ecc.EccDecryptByHex(hexText, eccHexKey.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("ecc解密后:\n%s\n", string(plaintext))

	/*ecc加密后的hex密文为:
	04689a2f57eee52e36d16fa8628353cdb8a13f2686597f6d6b45d1bcc0d4cd75be09562d9ff565879cb333ef16b3c21e2411035d8aaaaf7e2dedc1803a879ca1382d40202aa7122365d71091a4d0683c36fa291f6b1d4ef4b30359cd7bd9c3ae875dc20f2c5e0d33121f01768373ac8b8cecff84511b76331510982753787e38da9ccd6f9f78f46641882cfe08e81db8a7cc1bf9213a63824b3d6d8dddeeaee448cfa0990e1a85c628e23eb2b9b37628b10efcc27c4c
	ecc解密后:
	床前明月光，疑是地上霜，举头望明月，低头思故乡*/

	rSign, sSign, err := ecc.EccSignHex([]byte(msg), eccHexKey.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("ecc签名的为:\nrSign=%s\nsSign=%s\n", rSign, sSign)
	res := ecc.EccVerifySignHex([]byte(msg), rSign, sSign, eccHexKey.PublicKey)
	fmt.Printf("ecc验签结果为:\n%v\n", res)

	/*ecc签名的为:
	rSign=35333235363338393635343330383234313231383931333332313533373634353032373036323933363630343834303735383739313330343130353033383139333235373530363834323337
	sSign=3533383435343038323339303534363136303332373435323435353130343139313530393637383432373237333735323038333836353934343135343638363231383335383831373838323632
	ecc验签结果为:
	true

	*/
}
```


## 5.sha256和sha512 hmac

```
func main() {
	msg := "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	fmt.Println(hash.Sha1Hex([]byte(msg)))
	fmt.Println(hash.Sha256Hex([]byte(msg)))
	fmt.Println(hash.Sha512Hex([]byte(msg)))

	// d2f1f816e0d40a1eb3f8aa60001f70a5b4ac21c4
	// 0f721dc0f0b9697a060c5541a389a7e5560e7b9a2dd3eca7f7688e477eee0243
	// f81bc5e4f057c28102adf27d31a98c5af8f259b213235225dce3b75815a4b76dccd0b181c7cb5347e118ab89b62542236d317dce584ce18c7c4a3c7f63fdaa52

	fmt.Println(hash.HmacSha256Hex([]byte("key"),msg))
	fmt.Println(hash.HmacSha512Hex([]byte("key"),msg))

	// e95c72fcfdd336559e6512198bc7b5d4f2c7c6ad2ece0f9e664548a809268904
	// 42603a67b53a572cdd6d8d4b8310ca8478391b4676822b66ccc473bf8d989b8f2d7afac8c75e7f7e9e723d2c8fbd7c575d897d6aba272dbfaaf903dfb750b323
}
}
```




