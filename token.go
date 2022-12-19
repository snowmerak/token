package token

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type Token struct {
	typ           string
	class         string
	publicClaims  map[string][]byte
	privateClaims map[string][]byte

	cryptoKey     []byte
	encryptMethod func([]byte, []byte) ([]byte, error)
	decryptMethod func([]byte, []byte) ([]byte, error)
	hashMethod    func(*Token) []byte
}

func New(typ string, class string) *Token {
	return &Token{
		typ:           typ,
		class:         class,
		publicClaims:  make(map[string][]byte),
		privateClaims: make(map[string][]byte),
	}
}

func (t *Token) SetCryptoMethod(key []byte, encrpyt func([]byte, []byte) ([]byte, error), decrypt func([]byte, []byte) ([]byte, error)) {
	t.encryptMethod = encrpyt
	t.decryptMethod = decrypt
	t.cryptoKey = key
}

func (t *Token) SetHashMethod(method func(*Token) []byte) {
	t.hashMethod = method
}

func (t *Token) SetPublicClaim(key string, value []byte) {
	t.publicClaims[key] = value
}

func (t *Token) SetPrivateClaim(key string, value []byte) error {
	if t.encryptMethod == nil {
		return errors.New("No crypto method set")
	}
	v, err := t.encryptMethod(value, t.cryptoKey)
	if err != nil {
		return fmt.Errorf("token.encryptMethod: %s", err)
	}
	t.privateClaims[key] = v
	return nil
}

func (t *Token) GetPublicClaim(key string) []byte {
	return t.publicClaims[key]
}

func (t *Token) GetPrivateClaim(key string) ([]byte, error) {
	if t.decryptMethod == nil {
		return nil, errors.New("No crypto method set")
	}
	v, err := t.decryptMethod(t.privateClaims[key], t.cryptoKey)
	if err != nil {
		return nil, fmt.Errorf("token.decryptMethod: %s", err)
	}
	return v, nil
}

func (t *Token) Hash() []byte {
	return t.hashMethod(t)
}

func (t *Token) Type() string {
	return t.typ
}

func (t *Token) Class() string {
	return t.class
}

func (t *Token) Bytes() []byte {
	buf := bytes.NewBuffer(nil)
	lenBuf := [4]byte{}

	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(t.typ)))
	buf.Write(lenBuf[:])
	buf.WriteString(t.typ)

	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(t.class)))
	buf.Write(lenBuf[:])
	buf.WriteString(t.class)

	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(t.publicClaims)))
	buf.Write(lenBuf[:])
	for k, v := range t.publicClaims {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(k)))
		buf.Write(lenBuf[:])
		buf.WriteString(k)

		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(v)))
		buf.Write(lenBuf[:])
		buf.Write(v)
	}

	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(t.privateClaims)))
	buf.Write(lenBuf[:])
	for k, v := range t.privateClaims {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(k)))
		buf.Write(lenBuf[:])
		buf.WriteString(k)

		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(v)))
		buf.Write(lenBuf[:])
		buf.Write(v)
	}

	buf.Write(t.Hash())

	return buf.Bytes()
}

func FromBytes(buf []byte, hashMethod func(*Token) []byte) (*Token, error) {
	t := &Token{
		publicClaims:  make(map[string][]byte),
		privateClaims: make(map[string][]byte),
	}

	typLength := binary.BigEndian.Uint32(buf[:4])
	t.typ = string(buf[4 : 4+typLength])
	buf = buf[4+typLength:]

	classLength := binary.BigEndian.Uint32(buf[:4])
	t.class = string(buf[4 : 4+classLength])
	buf = buf[4+classLength:]

	publicClaimsLength := binary.BigEndian.Uint32(buf[:4])
	buf = buf[4:]
	for i := uint32(0); i < publicClaimsLength; i++ {
		keyLength := binary.BigEndian.Uint32(buf[:4])
		key := string(buf[4 : 4+keyLength])
		buf = buf[4+keyLength:]

		valueLength := binary.BigEndian.Uint32(buf[:4])
		value := buf[4 : 4+valueLength]
		buf = buf[4+valueLength:]

		t.publicClaims[key] = value
	}

	privateClaimsLength := binary.BigEndian.Uint32(buf[:4])
	buf = buf[4:]
	for i := uint32(0); i < privateClaimsLength; i++ {
		keyLength := binary.BigEndian.Uint32(buf[:4])
		key := string(buf[4 : 4+keyLength])
		buf = buf[4+keyLength:]

		valueLength := binary.BigEndian.Uint32(buf[:4])
		value := buf[4 : 4+valueLength]
		buf = buf[4+valueLength:]

		t.privateClaims[key] = value
	}

	t.hashMethod = hashMethod
	if !bytes.Equal(t.Hash(), buf) {
		return nil, errors.New("Token hash mismatch")
	}

	return t, nil
}
