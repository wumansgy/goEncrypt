package ecc

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	msg          = "床前明月光，疑是地上霜，举头望明月，低头思故乡"
	base64PubKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElJ+LbZBekYTu/Md4T/j3DJsmJFf/3wLLmfUR7sLXCzS1PsDpHIC0QXRdVVdzS9BmP5GdtpesR4Oeh7g0TBBoLA=="
	base64PriKey = "MHcCAQEEIKPH4RlH9IQYwalxykgwlZkV9JjxQW2mHM+oGp4dxkMGoAoGCCqGSM49AwEHoUQDQgAElJ+LbZBekYTu/Md4T/j3DJsmJFf/3wLLmfUR7sLXCzS1PsDpHIC0QXRdVVdzS9BmP5GdtpesR4Oeh7g0TBBoLA=="

	hexPubKey = "3059301306072a8648ce3d020106082a8648ce3d030107034200043d39b48322518e8c6053ff63ef0426537fb1d5e16d128802c4c54104d61f84605b6bfa3266cc7f38968c0174d672e3690e50a93c819589f6d0f6bb44a57bcee8"
	hexPriKey = "30770201010420af9497e1c61ffe6019592a25f22a12e079e87d935b01bd2dc6d817744053a849a00a06082a8648ce3d030107a144034200043d39b48322518e8c6053ff63ef0426537fb1d5e16d128802c4c54104d61f84605b6bfa3266cc7f38968c0174d672e3690e50a93c819589f6d0f6bb44a57bcee8"
)

func TestEccEncryptBase64(t *testing.T) {
	base64Key, err := GenerateEccKeyBase64()
	assert.Nil(t, err)

	cipherText, err := EccEncryptToBase64([]byte(msg), base64PubKey)
	assert.Nil(t, err)
	_, err = EccEncryptToBase64([]byte(msg), base64PriKey)
	assert.NotNil(t, err)
	plainText, err := EccDecryptByBase64(cipherText, base64PriKey)
	assert.Nil(t, err)
	assert.Equal(t, msg, string(plainText))

	cipherText, err = EccEncryptToBase64([]byte(msg), base64Key.PublicKey)
	assert.Nil(t, err)
	plainText, err = EccDecryptByBase64(cipherText, base64Key.PrivateKey)
	assert.Nil(t, err)
	assert.Equal(t, msg, string(plainText))
	_, err = EccDecryptByBase64(cipherText, base64Key.PublicKey)
	assert.NotNil(t, err)
	_, err = EccDecryptByBase64("badText", base64Key.PrivateKey)
	assert.NotNil(t, err)
	_, err = EccDecryptByBase64(cipherText, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElJ")
	assert.NotNil(t, err)

}

func TestEccEncryptHex(t *testing.T) {
	hexKey, err := GenerateEccKeyHex()
	assert.Nil(t, err)

	cipherText, err := EccEncryptToHex([]byte(msg), hexPubKey)
	assert.Nil(t, err)
	_, err = EccEncryptToHex([]byte(msg), hexPriKey)
	assert.NotNil(t, err)
	plainText, err := EccDecryptByHex(cipherText, hexPriKey)
	assert.Nil(t, err)
	assert.Equal(t, msg, string(plainText))

	cipherText, err = EccEncryptToHex([]byte(msg), hexKey.PublicKey)
	assert.Nil(t, err)
	plainText, err = EccDecryptByHex(cipherText, hexKey.PrivateKey)
	assert.Nil(t, err)
	assert.Equal(t, msg, string(plainText))
	_, err = EccDecryptByHex(cipherText, hexKey.PublicKey)
	assert.NotNil(t, err)
	_, err = EccDecryptByHex("badText", hexKey.PrivateKey)
	assert.NotNil(t, err)
	_, err = EccDecryptByHex(cipherText, "3059301306072a8648ce3d020106082a8648ce3d03")
	assert.NotNil(t, err)

}

func TestEccSignBase64(t *testing.T) {
	base64Key, err := GenerateEccKeyBase64()
	assert.Nil(t, err)

	rText, sText, err := EccSignBase64([]byte(msg), base64Key.PrivateKey)
	assert.Nil(t, err)
	_, _, err = EccSignBase64([]byte(msg), base64Key.PublicKey)
	assert.NotNil(t, err)
	_, _, err = EccSignBase64([]byte(msg), base64PubKey)
	assert.NotNil(t, err)

	res := EccVerifySignBase64([]byte(msg), rText, sText, base64Key.PublicKey)
	assert.Equal(t, res, true)

	res = EccVerifySignBase64([]byte(msg), rText, sText, base64Key.PrivateKey)
	assert.Equal(t, res, false)
	res = EccVerifySignBase64([]byte(msg), sText, rText, base64Key.PrivateKey)
	assert.Equal(t, res, false)
}

func TestEccSignHex(t *testing.T) {
	hexKey, err := GenerateEccKeyHex()
	assert.Nil(t, err)

	rText, sText, err := EccSignHex([]byte(msg), hexKey.PrivateKey)
	assert.Nil(t, err)
	_, _, err = EccSignHex([]byte(msg), hexKey.PublicKey)
	assert.NotNil(t, err)
	_, _, err = EccSignHex([]byte(msg), hexPubKey)
	assert.NotNil(t, err)

	res := EccVerifySignHex([]byte(msg), rText, sText, hexKey.PublicKey)
	assert.Equal(t, res, true)

	res = EccVerifySignHex([]byte(msg), rText, sText, hexKey.PrivateKey)
	assert.Equal(t, res, false)
	res = EccVerifySignHex([]byte(msg), sText, rText, hexKey.PrivateKey)
	assert.Equal(t, res, false)
}
