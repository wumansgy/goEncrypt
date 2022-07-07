package rsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	msg              = "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	base64PubKey1024 = "MIGJAoGBAL8Om9dxnaqfKarF4bewdCTXmymXt4K5FBf3FPT413bq/3zoAaHTWUfzNBmrcAW+rYr5tXDPD+WncqKqI9yo+zW+w+mgOOkSbQsGUDQuah5B4tRNBgV533w+ljSGM+7PxgOhapFyh2vwD/BGQ4GafrZeU2hyHXQDgfL95dfrsbI/AgMBAAE="
	base64PriKey1024 = "MIICWwIBAAKBgQC/DpvXcZ2qnymqxeG3sHQk15spl7eCuRQX9xT0+Nd26v986AGh01lH8zQZq3AFvq2K+bVwzw/lp3KiqiPcqPs1vsPpoDjpEm0LBlA0LmoeQeLUTQYFed98PpY0hjPuz8YDoWqRcodr8A/wRkOBmn62XlNoch10A4Hy/eXX67GyPwIDAQABAoGAYgaDzOk9ROJ+xWDb65w8Kv74XEG8ZPTCq30ZIoteOWRfC14aIEZI45KTo6wDQN9ROSHfhu6mMGVWesEivz9wC4K/Qt5D0wxxQudx5NU8pHj9eDl5OIuWzk5YwjV92rDIl+b/XdeF3HqnphZzzbI9ad0PEbOH2v49wcEh4W7xDMkCQQDtY6vTCOM7faYzyJ5PRg39/sJRPgCyp9zD1VsYvX2Hb9pwpd7/tGWr6sVURACsGpO1fvzBFttrnEZ2dD83SunTAkEAzgkQQRalH/AAEbEZXnal6qmZC50f7dCAIF3i54MnzQsUgg/fcciWJcgz4+gRihtZxOiPVTJO4T0g/9waeeWGZQJAOZqpFEGg2kvIK+Kvv67RMGREhPBVvQSMxpycSWmZ72aODC3D6iq9TTVgAu2peBnO5AjXjodcYUV/t7jHqkQsbwJAAuU7tj50OZus1JLRkXNHZ6HUhcZCgZwRgOLw4mIEeCw0sJM6h6XS/lru58AGJxO1UkAWa5MWarHqOc5FDPt9xQJAU32KUvN2KbchqOqLKCP59dBDMQorv/Y8Ej7whQ//iBhO0APXBBzchM3D948+PRdL3R0be2jJ5eBJTdWNp3BsdQ=="
	base64PubKey2048 = "MIIBCgKCAQEA7MnuJs/PIF/lARA3P5KKLwul1sUnlQYBY0mZyi7dgIqDAbfOWAvfGMjryTOqiQ2D06hBKNc5BZXMtD5H3oipDUzGMbtlb+VwnX7xaqWDJlwH1/ZJ/IAkV8fBPukRNhNoeGSdTVPpS9oq3M9w3L1x71wgI77Lnv4lBGDvIi4Qc3etReErWIMrCbttRjv2zXTSJv9r9VCVBQcUJvQDf9Ad3eVwT6Q5iC9frJui8e1psYhfeiqhB2Wo4TUCKnU+6ZaYt3lHgJQ0RTGh0CssoCU56z6DZu9PjsReCNKhGBAN2S/KhrdbQHU+JQzMnNOBkdzfyzLSHz8+c3lgWSTx3uYfMQIDAQAB"
	base64PriKey2048 = "MIIEpQIBAAKCAQEA7MnuJs/PIF/lARA3P5KKLwul1sUnlQYBY0mZyi7dgIqDAbfOWAvfGMjryTOqiQ2D06hBKNc5BZXMtD5H3oipDUzGMbtlb+VwnX7xaqWDJlwH1/ZJ/IAkV8fBPukRNhNoeGSdTVPpS9oq3M9w3L1x71wgI77Lnv4lBGDvIi4Qc3etReErWIMrCbttRjv2zXTSJv9r9VCVBQcUJvQDf9Ad3eVwT6Q5iC9frJui8e1psYhfeiqhB2Wo4TUCKnU+6ZaYt3lHgJQ0RTGh0CssoCU56z6DZu9PjsReCNKhGBAN2S/KhrdbQHU+JQzMnNOBkdzfyzLSHz8+c3lgWSTx3uYfMQIDAQABAoIBAQC6Wb0UTG2M5As9B/8DCBe6KKeOW8Dn9j73XcArrzBhbiDmJDq/bjBYuB9gTEoE7F74Hy2Qr7jPnXHp1C4Jg3HP5sD/+KQ/KMm1GWdzb+jEMp91pf3aOxre/nUmRpRmA2YvgbeOWOB88qjS+GqxPmLBZrZgi1KCwS5uwL7SHoCR7XUb1YnGBD6sGKTPu6food58PkDBlpIk0W/9v8qjSoktwto4fR3onyWC39lEJRViYIZqBhRi0v2jByJLMGtHnFhByhNjQD8lRr+0LG5ih4PAhlwlA/Hw4jGfGQErE9GJhWVb+DZqicA8WDRWI9rowAK6s3mqV3NCq+LwcpqFnq1FAoGBAPn7PnwxZM3MVjIhLe2WT6ENQXXajYsmcweW/V8sDA0ZJi1rQH/nfeXodkjN9R5jmSAQpbTR9hKZv3EHUOfxKjOMIOHDylCxeDKcaqGt49lra/G5w5HZwbD2IUrwCCJ1bLiNotgeHV4ISGrbjUTFSwXikNaRc31hkSinKWSXnlk/AoGBAPJ9X6ebCPVZHWAmfzMUqQpV3t++togv+JmCM2wj+NCTId2G3dL2ZFfKj9ZbHLQTXwkehN22Ad4cMafHaKoO9t3CvSeVXuZYFD2oSIxrr86ym6exRS3P/bmZbXCuP2ry4Oax3yDec8vFjBFvRvT62rUU0kPpeauqvG1MgxbKL3uPAoGBAL8KwH0fLn+Mys7yxmvNNLvLKpzL0uJmFwDU5nvmaKtV7fRGA/v7yR58InGPXOXFjg+QSWNAFoOuljzmL3Giv/K3A6YmACbdChP7sA4xm3DchJkus4RyW3FHGLhxanYTMWx1ad8qXJ0xTU7EzViiQqyTsscYT5+hgdMEtUCYEr73AoGAZ1HsM+nnA0MZNSKyB/3BmNnFwOfttlFaR24moukg1x4Zy93vHjhFwPJaHydrL38hey05x44Jda3lqmtYuTzvCsYy+m62pMbauPq/DrXDjvqjP+xUYZTBsxcgfmaANv2Nvj4DqGmgRS7C45raTP+luIpKnQ0Z/n8dEiULpeY4HRkCgYEAs63wYb0EsFsAPTjYqiAo3n7MofaPbt2VvCG+6T6cNubHScA3vU1kah3YoxEhvQdAVUd5yC59+KfgINJitI9RjeOqULBpA22rFmVtQVaYlABRzrFW4gwPgZtuPoFr4th1fd+5CM4SxYffO9FtcpLUPx6COxLejgTNeo301r7TepE="

	hexPubKey1024 = "30818902818100a751e464a258e5b55c3b3595a14c342d5f9f19e03ad09f814638ea67694a685bc3fc080a1f512473f47615ee2e392d3b31d7c7b03d6f9be3c9ff86c1ce462a3b772bfec18499b056ce81aef04968a74b3d4bdca820b1a20891889b5e46a7e20d6efa6c875f7240212f7b595e61abf989731e7b730f0a3d30b8c6d582cff13b4f0203010001"
	hexPriKey1024 = "3082025d02010002818100a751e464a258e5b55c3b3595a14c342d5f9f19e03ad09f814638ea67694a685bc3fc080a1f512473f47615ee2e392d3b31d7c7b03d6f9be3c9ff86c1ce462a3b772bfec18499b056ce81aef04968a74b3d4bdca820b1a20891889b5e46a7e20d6efa6c875f7240212f7b595e61abf989731e7b730f0a3d30b8c6d582cff13b4f020301000102818050cbf3cd40b44ae084143770f4fdd6685eb7768857fe6c37c1d0342911a813b2d475fcefde659183c8f5c8eb4638e805a0b10145b2b515832f050c6ec40c0fd1f56a83fdcca2182e738922cc07261dfe890a185e2f90f6739643b3213355de5e2e88309e211e09270620e2eb6c927948de04e4c92b6aa7397737b683336b4b59024100d49d78a609f3a88abcc61bf66cb592df8b0fa203900eccf64a7c3d417fa67dfd4afa86c18e5a8153e48136323d27147d77d8f96d3c8eaf56014a07c4c4bc02f5024100c9764d2815cd09ca70020b7ae2c5fbafc6637776a8bb91acf01a57b6f2420ceef9bf1c12bb39e97d0356edb96eeeccd53d3dbc5879f288923598e44585d842b3024100a224510cf6cbedbd9806d0ee55ab070e1963db9f31ee479a8fe53d65c4ee786881149b4de2bcdca1d8c23d4d84db57c1f372f18cbfc0e4b0071da8dd03578a3d02403798c43639bdf9e3ba017675953b99f7aa422ce7bc2cf748c8821c8eca505c0d5f32d4667ef0be74d78517d9c2b97821a8e2eea56412008a88ec06a3010aeb6d0241008955162a805c6275045e5865f7e6aa57a1523ae327596a2e2fbbf6b7025bff51339898962b1a14b3c8e5fd675163f7f3cae100d78cdf689f06987e09d2d1a241"
	hexPubKey2048 = "3082010a0282010100db8766d4dfc732b9a9b4ac1a243f9426cb0e65f75be04db5a7f0d50c799287eeac8216c8e3db510f974b7c150ec955260bbec8f89226e30f969e3505949cab1dbac6d333239332f82eeba33c64337b7704b29a118d1c19d15f84c810cf1ef3966c0584840ddcdbc04c361eafbb5bd5da67e93a39e6125eedd375f1ba28a95299cc2504d5a6073caeaf83b0e17b01eb9b4cddce80c34e97667cd7c2d31e88855759b454596ac83f3c3f5ea5e5ec1268d747595bf2c18790b9ee3622449b86c4c31bbf3ceacda8337741646e7e9415d9cbf26f468d125b7062f27f4fea7e63cb40e8104501efcb149fdfc9173c4720ed7594323d22c8d43213dadc5207c409e9e30203010001"
	hexPriKey2048 = "308204a30201000282010100db8766d4dfc732b9a9b4ac1a243f9426cb0e65f75be04db5a7f0d50c799287eeac8216c8e3db510f974b7c150ec955260bbec8f89226e30f969e3505949cab1dbac6d333239332f82eeba33c64337b7704b29a118d1c19d15f84c810cf1ef3966c0584840ddcdbc04c361eafbb5bd5da67e93a39e6125eedd375f1ba28a95299cc2504d5a6073caeaf83b0e17b01eb9b4cddce80c34e97667cd7c2d31e88855759b454596ac83f3c3f5ea5e5ec1268d747595bf2c18790b9ee3622449b86c4c31bbf3ceacda8337741646e7e9415d9cbf26f468d125b7062f27f4fea7e63cb40e8104501efcb149fdfc9173c4720ed7594323d22c8d43213dadc5207c409e9e302030100010282010041a76d099d2365f840d8d7dfb9978a274ff32e6b9bfea93efacafbec8f2f5397fddfaa10ca947cd9bcd5c67645c5d0c16021ded8f85cc8eb9090202b5b16bfd65455c234391f7ccedcb97c48436f622d662a44099bba1bbe926293b2f33ebe7aee33783e462717519b7954141a648cc094f31b86d558092bf761feb93e0fe5b3ab65b7d3bfdb855ffafd312662d78d4b6fc8c86d085ca2859dcea7c47455bf78ba1317a501bc3490b1463fca7e3ec5d8579139648d46696164803587ae8bba5f2f327d2a62a1b4faf3c3a530f3062af658cdd4bd87d04ecf1116c4e3350b060740d7217cf58d0dddf69ce034ff54dff0f9ac548f0d6ffc79507b7eb20c55f38102818100e0420eab79319069072f6d0df3bf6f94affdaf8d50caa1094579a2dd7750f9d9c8b54a5f981e2df99af607eaf09ffd69b74d3a5175f63fff6cb892132cd837a47c7dfe8843c90dfa77d0aa4f728a08f40d034f75c1d1baf9a2f7a96cd99babface9a162d287953d9297d6fd665633ff1f4db543982aaa2468445f2145fbc68f702818100fa99fc4f7b6ba6e5bb2c9bf80c3299a9723043074a43df58d2caee2e8bea973698fdf8bbd7a9fc31a37b694ecf05b2635b427419ff9099fa7b333e96867602a1f1fd29f21c355b07a5062b91a97fb8a5b11f4d4051d1edd81238fef7c45c5a62a3d3c67f36c89e2693411da7ece59a362ca5175d70ce86b1caed1cb1004e57750281804ce479713409d99119849a68e9459f75a4ee5fee1d608cdcc7f48ff24dc1f71944675ccbf03590dfffd1121fed477e356c434f96b4d2ad58e0275cf6b42ea2cd845e131317e2ed270f43fdd165dd8c7a59a7e3ebe57c0b172358b5bffbd113a3d8891ec777143abac02e2155aac7e01a0f31d0ec33305c99bf2ad87941e6313b02818100eb85370d182897a5872128c099ee205e90f3ecbaf8400bb3b6008493786a148d7a820e77b3fb8d0ab5e3b1982096f10dd1e205adbd73905349e0626d2397db678a3f6d619ec342774fd019b87f3d8b3325e10e4069e54b8c6babe76cc2be2d30515a224ec3150f15a0056db2b9c11c0ad8309c61f438157d190379989c7a04550281804a005d7aed10e75cf149a4645392fef8da4499904e947db0b0fd06faaa7eb3f39a7e4bdc997a654f009be62ca32893d7bde393fd0b2b81a06ea0f5504dea3438b23670765ba073dea1a669697c4d4f192cc68a9fe0a6cb35711535e859c36c8fa5e086cbd874e13b7cc0e8b018c21b72cff697e85a1ab7fad4a62af7458542cb"
)

func TestRsaEncryptBase64(t *testing.T) {
	base64Key1024, err := GenerateRsaKeyBase64(1024)
	assert.Nil(t, err)
	base64Key2048, err := GenerateRsaKeyBase64(2048)
	assert.Nil(t, err)
	_, err = GenerateRsaKeyBase64(204811)
	assert.NotNil(t, err)

	// good
	base64CipherText, err := RsaEncryptToBase64([]byte(msg), base64Key1024.PublicKey)
	assert.Nil(t, err)
	// bad
	_, err = RsaEncryptToBase64([]byte(msg), "badkey")
	assert.NotNil(t, err)
	_, err = RsaEncryptToBase64([]byte(msg), hexPubKey1024)
	assert.NotNil(t, err)
	// good
	plainText, err := RsaDecryptByBase64(base64CipherText, base64Key1024.PrivateKey)
	assert.Nil(t, err)
	assert.Equal(t, string(plainText), msg)
	// bad priKey
	_, err = RsaDecryptByBase64(base64CipherText, "badPriKey")
	assert.NotNil(t, err)
	_, err = RsaDecryptByBase64(base64CipherText, base64Key2048.PublicKey)
	assert.NotNil(t, err)
	_, err = RsaDecryptByBase64(base64CipherText, base64Key2048.PrivateKey)
	assert.NotNil(t, err)
	_, err = RsaDecryptByBase64(base64CipherText, hexPriKey1024)
	assert.NotNil(t, err)
	_, err = RsaDecryptByBase64(base64CipherText, hexPriKey2048)
	assert.NotNil(t, err)
	_, err = RsaDecryptByBase64(base64CipherText, hexPubKey1024)
	assert.NotNil(t, err)
	_, err = RsaDecryptByBase64("badtext", base64Key1024.PrivateKey)
	assert.NotNil(t, err)

	// good
	base64CipherText, err = RsaEncryptToBase64([]byte(msg), base64Key2048.PublicKey)
	assert.Nil(t, err)
	plainText, err = RsaDecryptByBase64(base64CipherText, base64Key2048.PrivateKey)
	assert.Nil(t, err)
	assert.Equal(t, string(plainText), msg)

	// good
	base64CipherText, err = RsaEncryptToBase64([]byte(msg), base64PubKey1024)
	assert.Nil(t, err)
	plainText, err = RsaDecryptByBase64(base64CipherText, base64PriKey1024)
	assert.Nil(t, err)
	assert.Equal(t, string(plainText), msg)

	// good
	base64CipherText, err = RsaEncryptToBase64([]byte(msg), base64PubKey2048)
	assert.Nil(t, err)
	plainText, err = RsaDecryptByBase64(base64CipherText, base64PriKey2048)
	assert.Nil(t, err)
	assert.Equal(t, string(plainText), msg)
}

func TestRsaEncryptHex(t *testing.T) {
	hexKey1024, err := GenerateRsaKeyHex(1024)
	assert.Nil(t, err)
	hexKey2048, err := GenerateRsaKeyHex(2048)
	assert.Nil(t, err)
	_, err = GenerateRsaKeyHex(2048111)
	assert.NotNil(t, err)

	// good
	hexCipherText, err := RsaEncryptToHex([]byte(msg), hexKey1024.PublicKey)
	assert.Nil(t, err)
	// bad
	_, err = RsaEncryptToHex([]byte(msg), "badkey")
	assert.NotNil(t, err)
	// good
	plainText, err := RsaDecryptByHex(hexCipherText, hexKey1024.PrivateKey)
	assert.Nil(t, err)
	assert.Equal(t, string(plainText), msg)
	// bad
	_, err = RsaDecryptByHex(hexCipherText, "badkey")
	assert.NotNil(t, err)
	// bad priKey
	_, err = RsaDecryptByHex(hexCipherText, hexPriKey2048)
	assert.NotNil(t, err)
	_, err = RsaDecryptByHex(hexCipherText, hexPriKey1024)
	assert.NotNil(t, err)
	_, err = RsaDecryptByHex(hexCipherText, base64PriKey2048)
	assert.NotNil(t, err)
	_, err = RsaDecryptByHex(hexCipherText, base64PriKey1024)
	assert.NotNil(t, err)
	_, err = RsaDecryptByHex("ssss", hexKey1024.PrivateKey)
	assert.NotNil(t, err)

	// good
	hexCipherText, err = RsaEncryptToHex([]byte(msg), hexKey2048.PublicKey)
	assert.Nil(t, err)
	plainText, err = RsaDecryptByHex(hexCipherText, hexKey2048.PrivateKey)
	assert.Nil(t, err)
	assert.Equal(t, string(plainText), msg)

	// good
	hexCipherText, err = RsaEncryptToHex([]byte(msg), hexPubKey1024)
	assert.Nil(t, err)
	plainText, err = RsaDecryptByHex(hexCipherText, hexPriKey1024)
	assert.Nil(t, err)
	assert.Equal(t, string(plainText), msg)

	// good
	hexCipherText, err = RsaEncryptToHex([]byte(msg), hexPubKey2048)
	assert.Nil(t, err)
	plainText, err = RsaDecryptByHex(hexCipherText, hexPriKey2048)
	assert.Nil(t, err)
	assert.Equal(t, string(plainText), msg)

}

func TestRsaSignBase64(t *testing.T) {
	base64Key1024, err := GenerateRsaKeyBase64(1024)
	assert.Nil(t, err)
	base64Key2048, err := GenerateRsaKeyBase64(2048)
	assert.Nil(t, err)
	_, err = GenerateRsaKeyBase64(204811)
	assert.NotNil(t, err)

	base64Sign1024, err := RsaSignBase64([]byte(msg), base64Key1024.PrivateKey)
	assert.Nil(t, err)
	_, err = RsaSignBase64([]byte(msg), hexPriKey2048)
	assert.NotNil(t, err)
	res := RsaVerifySignBase64([]byte(msg), base64Sign1024, base64Key1024.PublicKey)
	assert.Equal(t, res, true)
	res = RsaVerifySignBase64([]byte(msg), base64Sign1024, base64Key2048.PublicKey)
	assert.Equal(t, res, false)
	res = RsaVerifySignBase64([]byte(msg), "11111", "badpubkey")
	assert.Equal(t, res, false)
	res = RsaVerifySignBase64([]byte(msg), "11111", base64Key1024.PublicKey)
	assert.Equal(t, res, false)
	res = RsaVerifySignBase64([]byte(msg), base64Sign1024, base64Key2048.PublicKey)
	assert.Equal(t, res, false)

	base64Sign2048, err := RsaSignBase64([]byte(msg), base64Key2048.PrivateKey)
	assert.Nil(t, err)
	res = RsaVerifySignBase64([]byte(msg), base64Sign2048, base64Key2048.PublicKey)
	assert.Equal(t, res, true)
	res = RsaVerifySignBase64([]byte(msg), base64Sign2048, base64Key1024.PublicKey)
	assert.Equal(t, res, false)
	res = RsaVerifySignBase64([]byte(msg), "11111", "badpubkey")
	assert.Equal(t, res, false)
	res = RsaVerifySignBase64([]byte(msg), base64Sign2048, base64Key1024.PublicKey)
	assert.Equal(t, res, false)
	res = RsaVerifySignBase64([]byte(msg), base64Sign2048, base64Key1024.PrivateKey)
	assert.Equal(t, res, false)
	res = RsaVerifySignBase64([]byte(msg), base64Sign2048, base64Key2048.PrivateKey)
	assert.Equal(t, res, false)

}

func TestRsaSignHex(t *testing.T) {
	hexKey1024, err := GenerateRsaKeyHex(1024)
	assert.Nil(t, err)
	hexKey2048, err := GenerateRsaKeyHex(2048)
	assert.Nil(t, err)
	_, err = GenerateRsaKeyHex(2048111)
	assert.NotNil(t, err)

	hexSign1024, err := RsaSignHex([]byte(msg), hexKey1024.PrivateKey)
	assert.Nil(t, err)
	_, err = RsaSignHex([]byte(msg), hexKey1024.PublicKey)
	assert.NotNil(t, err)
	res := RsaVerifySignHex([]byte(msg), hexSign1024, hexKey1024.PublicKey)
	assert.Equal(t, res, true)
	res = RsaVerifySignHex([]byte(msg), hexSign1024, hexKey2048.PublicKey)
	assert.Equal(t, res, false)
	res = RsaVerifySignHex([]byte(msg), "11111", "badpubkey")
	assert.Equal(t, res, false)
	res = RsaVerifySignHex([]byte(msg), "282010100db", hexKey1024.PublicKey)
	assert.Equal(t, res, false)
	res = RsaVerifySignHex([]byte(msg), hexSign1024, hexKey2048.PublicKey)
	assert.Equal(t, res, false)

	hexSign2048, err := RsaSignHex([]byte(msg), hexKey2048.PrivateKey)
	assert.Nil(t, err)
	_, err = RsaSignHex([]byte(msg), hexPubKey2048)
	assert.NotNil(t, err)
	res = RsaVerifySignHex([]byte(msg), hexSign2048, hexKey2048.PublicKey)
	assert.Equal(t, res, true)
	res = RsaVerifySignHex([]byte(msg), hexSign2048, hexKey1024.PublicKey)
	assert.Equal(t, res, false)
	res = RsaVerifySignHex([]byte(msg), "0a0282010100d", "badpubkey")
	assert.Equal(t, res, false)
	res = RsaVerifySignHex([]byte(msg), "0a0282010100d", hexKey1024.PublicKey)
	assert.Equal(t, res, false)
	res = RsaVerifySignHex([]byte(msg), "xxxx", "badpubkey")
	assert.Equal(t, res, false)
	res = RsaVerifySignHex([]byte(msg), hexSign2048, hexKey1024.PublicKey)
	assert.Equal(t, res, false)
	res = RsaVerifySignHex([]byte(msg), hexSign2048, hexKey1024.PrivateKey)
	assert.Equal(t, res, false)
	res = RsaVerifySignHex([]byte(msg), hexSign2048, hexKey2048.PrivateKey)
	assert.Equal(t, res, false)

}
