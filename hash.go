package token

import (
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

func SHA256(data *Token) []byte {
	h := sha256.New()
	h.Write([]byte(data.typ))
	h.Write([]byte(data.class))
	for k, v := range data.publicClaims {
		h.Write([]byte(k))
		h.Write(v)
	}
	for k, v := range data.privateClaims {
		h.Write([]byte(k))
		h.Write(v)
	}
	return h.Sum(nil)
}

func SHA512(data *Token) []byte {
	h := sha512.New()
	h.Write([]byte(data.typ))
	h.Write([]byte(data.class))
	for k, v := range data.publicClaims {
		h.Write([]byte(k))
		h.Write(v)
	}
	for k, v := range data.privateClaims {
		h.Write([]byte(k))
		h.Write(v)
	}
	return h.Sum(nil)
}

func Blake2b512(data *Token) []byte {
	h, _ := blake2b.New512(nil)
	h.Write([]byte(data.typ))
	h.Write([]byte(data.class))
	for k, v := range data.publicClaims {
		h.Write([]byte(k))
		h.Write(v)
	}
	for k, v := range data.privateClaims {
		h.Write([]byte(k))
		h.Write(v)
	}
	return h.Sum(nil)
}

func Blake2b384(data *Token) []byte {
	h, _ := blake2b.New384(nil)
	h.Write([]byte(data.typ))
	h.Write([]byte(data.class))
	for k, v := range data.publicClaims {
		h.Write([]byte(k))
		h.Write(v)
	}
	for k, v := range data.privateClaims {
		h.Write([]byte(k))
		h.Write(v)
	}
	return h.Sum(nil)
}

func Blake2b256(data *Token) []byte {
	h, _ := blake2b.New256(nil)
	h.Write([]byte(data.typ))
	h.Write([]byte(data.class))
	for k, v := range data.publicClaims {
		h.Write([]byte(k))
		h.Write(v)
	}
	for k, v := range data.privateClaims {
		h.Write([]byte(k))
		h.Write(v)
	}
	return h.Sum(nil)
}

func Blake2s(data *Token) []byte {
	h, _ := blake2s.New256(nil)
	h.Write([]byte(data.typ))
	h.Write([]byte(data.class))
	for k, v := range data.publicClaims {
		h.Write([]byte(k))
		h.Write(v)
	}
	for k, v := range data.privateClaims {
		h.Write([]byte(k))
		h.Write(v)
	}
	return h.Sum(nil)
}
