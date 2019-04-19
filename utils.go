package goEncrypt

import "errors"

var (
	ErrCipherKey=errors.New("The secret key is wrong and cannot be decrypted. Please check")
	ErrKeyLengthSixteen=errors.New("a sixteen-length secret key is required")
	ErrKeyLengtheEight=errors.New("a eight-length secret key is required")
	ErrKeyLengthTwentyFour=errors.New("a twenty-four-length secret key is required")
)

const (
	iv="wumansgy12345678"
	ivdes="wumansgy"

	privateFileName="private.pem"
	publicFileName="public.pem"

	eccPrivateFileName="eccprivate.pem"
	eccPublishFileName="eccpublic.pem"

	privateKeyPrefix=" WUMAN RSA PRIVATE KEY "
	publicKeyPrefix=" WUMAN  RSA PUBLIC KEY "

	eccPrivateKeyPrefix=" WUMAN ECC PRIVATE KEY "
	eccPublicKeyPrefix=" WUMAN ECC PUBLIC KEY "
)