package shadowstream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"strconv"

	"github.com/aead/chacha20"
	"github.com/aead/chacha20/chacha"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/salsa20/salsa"
)

// Cipher generates a pair of stream ciphers for encryption and decryption.
type Cipher interface {
	IVSize() int
	Encrypter(iv []byte) cipher.Stream
	Decrypter(iv []byte) cipher.Stream
}

type KeySizeError int

func (e KeySizeError) Error() string {
	return "key size error: need " + strconv.Itoa(int(e)) + " bytes"
}

// CTR mode
type ctrStream struct{ cipher.Block }

func (b *ctrStream) IVSize() int                       { return b.BlockSize() }
func (b *ctrStream) Decrypter(iv []byte) cipher.Stream { return b.Encrypter(iv) }
func (b *ctrStream) Encrypter(iv []byte) cipher.Stream { return cipher.NewCTR(b, iv) }

func AESCTR(key []byte) (Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &ctrStream{blk}, nil
}

// CFB mode
type cfbStream struct{ cipher.Block }

func (b *cfbStream) IVSize() int                       { return b.BlockSize() }
func (b *cfbStream) Decrypter(iv []byte) cipher.Stream { return cipher.NewCFBDecrypter(b, iv) }
func (b *cfbStream) Encrypter(iv []byte) cipher.Stream { return cipher.NewCFBEncrypter(b, iv) }

func AESCFB(key []byte) (Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &cfbStream{blk}, nil
}

// IETF-variant of chacha20
type chacha20ietfkey []byte

func (k chacha20ietfkey) IVSize() int                       { return chacha.INonceSize }
func (k chacha20ietfkey) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k chacha20ietfkey) Encrypter(iv []byte) cipher.Stream {
	ciph, err := chacha20.NewCipher(iv, k)
	if err != nil {
		panic(err) // should never happen
	}
	return ciph
}

func Chacha20IETF(key []byte) (Cipher, error) {
	if len(key) != chacha.KeySize {
		return nil, KeySizeError(chacha.KeySize)
	}
	return chacha20ietfkey(key), nil
}

type xchacha20key []byte

func (k xchacha20key) IVSize() int                       { return chacha.XNonceSize }
func (k xchacha20key) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k xchacha20key) Encrypter(iv []byte) cipher.Stream {
	ciph, err := chacha20.NewCipher(iv, k)
	if err != nil {
		panic(err) // should never happen
	}
	return ciph
}

func Xchacha20(key []byte) (Cipher, error) {
	if len(key) != chacha.KeySize {
		return nil, KeySizeError(chacha.KeySize)
	}
	return xchacha20key(key), nil
}

type rc4Md5Key []byte

func (k rc4Md5Key) IVSize() int {
	return 16
}

func (k rc4Md5Key) Encrypter(iv []byte) cipher.Stream {
	h := md5.New()
	h.Write([]byte(k))
	h.Write(iv)
	rc4key := h.Sum(nil)
	c, _ := rc4.NewCipher(rc4key)
	return c
}

func (k rc4Md5Key) Decrypter(iv []byte) cipher.Stream {
	return k.Encrypter(iv)
}

func RC4MD5(key []byte) (Cipher, error) {
	return rc4Md5Key(key), nil
}

type chacha20key []byte

func (k chacha20key) IVSize() int {
	return chacha.NonceSize
}

func (k chacha20key) Encrypter(iv []byte) cipher.Stream {
	c, _ := chacha20.NewCipher(iv, k)
	return c
}

func (k chacha20key) Decrypter(iv []byte) cipher.Stream {
	return k.Encrypter(iv)
}

func ChaCha20(key []byte) (Cipher, error) {
	return chacha20key(key), nil
}

type blowfishCipher struct {
	c *blowfish.Cipher
}

func (k *blowfishCipher) IVSize() int {
	return blowfish.BlockSize
}

func (k *blowfishCipher) Encrypter(iv []byte) cipher.Stream {
	return cipher.NewCFBEncrypter(k.c, iv)
}

func (k *blowfishCipher) Decrypter(iv []byte) cipher.Stream {
	return cipher.NewCFBDecrypter(k.c, iv)
}

func BFCFB(key []byte) (Cipher, error) {
	c, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &blowfishCipher{c}, nil
}

type salsaStreamCipher struct {
	nonce   [8]byte
	key     [32]byte
	counter int
}

func (c *salsaStreamCipher) XORKeyStream(dst, src []byte) {
	padLen := c.counter % 64
	dataSize := len(src) + padLen
	buf := make([]byte, dataSize)
	var subNonce [16]byte
	copy(subNonce[:], c.nonce[:])
	binary.LittleEndian.PutUint64(subNonce[len(c.nonce):], uint64(c.counter/64))

	// It's difficult to avoid data copy here. src or dst maybe slice from
	// Conn.Read/Write, which can't have padding.
	copy(buf[padLen:], src[:])
	salsa.XORKeyStream(buf, buf, &subNonce, &c.key)
	copy(dst, buf[padLen:])

	c.counter += len(src)
}

type salsa20key []byte

func (k salsa20key) IVSize() int {
	return 8
}

func (k salsa20key) Encrypter(iv []byte) cipher.Stream {
	var c salsaStreamCipher
	copy(c.nonce[:], iv[:8])
	copy(c.key[:], k[:32])
	return &c
}

func (k salsa20key) Decrypter(iv []byte) cipher.Stream {
	return k.Encrypter(iv)
}

func SALSA20(key []byte) (Cipher, error) {
	return salsa20key(key), nil
}
