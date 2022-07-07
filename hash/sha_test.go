package hash

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	shaData = "sha text"

	sha1Hex   = "d61babc269a1ccf83d8d08583fdf513eedeb55e6"
	sha256Hex = "65294d857d822c8b73af70c78cf6fc4325a0bf28c2efbbcd07c55b19eaf20d20"
	sha512Hex = "b4d5cda7b08feeca4ce2bf17e1ffab7d13e5234faca54ae46f4f87f66200a3bbc07b4b37b095eaf3bca2f8dba707bc259af3fe6e6e0b925a43915c9f351d92be"
)

func TestSha1Hex(t *testing.T) {
	actual := Sha1Hex([]byte(shaData))
	assert.Equal(t, sha1Hex, actual)
}

func TestSha256Hex(t *testing.T) {
	actual := Sha256Hex([]byte(shaData))
	assert.Equal(t, sha256Hex, actual)
}

func TestSha512Hex(t *testing.T) {
	actual := Sha512Hex([]byte(shaData))
	assert.Equal(t, sha512Hex, actual)
}

func BenchmarkSha256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Sha256Hex([]byte(shaData))
	}
}

func BenchmarkSha512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Sha512Hex([]byte(shaData))
	}
}
