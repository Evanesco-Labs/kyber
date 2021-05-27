package ecies

import (
	"crypto/sha512"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/util/random"
)

var SecretPreimage = []byte{71, 206, 249, 232, 106, 168, 50, 200, 72, 19, 2, 73, 219, 11, 4, 102, 154, 204, 162, 214, 90, 94, 255, 94, 101, 214, 15, 96, 166, 132, 127, 103}
var CipherText = []byte{45, 26, 138, 82, 189, 21, 152, 35, 38, 70, 154, 60, 116, 201, 41, 124, 74, 184, 49, 248, 78, 107, 171, 148, 176, 57, 181, 247, 110, 171, 6, 50, 180, 71, 253, 39, 51, 14, 219, 151, 137, 88, 202, 7, 227, 42, 71, 43, 146, 144, 120, 0, 58, 111, 217, 67, 176, 171, 252, 152, 87, 74, 179, 62, 15, 80, 145, 118, 59, 200, 238}

func TestECIES(t *testing.T) {
	message := []byte("Hello ECIES")
	suite := edwards25519.NewBlakeSHA256Ed25519()
	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)
	ciphertext, err := Encrypt(suite, public, message, suite.Hash)
	require.Nil(t, err)
	plaintext, err := Decrypt(suite, private, ciphertext, suite.Hash)
	require.Nil(t, err)
	require.Equal(t, message, plaintext)
}

func TestEncode(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	finial := sha512.Sum512(SecretPreimage)
	secretBytes := finial[:32]

	secretBytes[0] &= 248
	secretBytes[31] &= 63
	secretBytes[31] |= 64
	secretBytes[0] &= 248
	secretBytes[31] &= 127
	secretBytes[31] |= 64

	private := suite.Scalar()
	err := private.UnmarshalBinary(secretBytes)
	if err != nil {
		t.Fatal(err)
	}

	public := suite.Point().Mul(private, nil)

	_, err = public.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("Hello ECIES")
	ciphertext, err := Encrypt(suite, public, message, suite.Hash)
	plaintext, err := Decrypt(suite, private, ciphertext, suite.Hash)
	assert.Equal(t, plaintext, message)

	plaintextDe, err := Decrypt(suite, private, CipherText, suite.Hash)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, plaintext, plaintextDe)
}

func TestECIESFailPoint(t *testing.T) {
	message := []byte("Hello ECIES")
	suite := edwards25519.NewBlakeSHA256Ed25519()
	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)
	ciphertext, err := Encrypt(suite, public, message, nil)
	require.Nil(t, err)
	ciphertext[0] ^= 0xff
	_, err = Decrypt(suite, private, ciphertext, nil)
	require.NotNil(t, err)
}

func TestECIESFailCiphertext(t *testing.T) {
	message := []byte("Hello ECIES")
	suite := edwards25519.NewBlakeSHA256Ed25519()
	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)
	ciphertext, err := Encrypt(suite, public, message, nil)
	require.Nil(t, err)
	l := suite.PointLen()
	ciphertext[l] ^= 0xff
	_, err = Decrypt(suite, private, ciphertext, nil)
	require.NotNil(t, err)
}
