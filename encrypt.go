package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptAES256GCM(data []byte, key []byte) ([]byte, error) {
	k := sha256.Sum256(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}
	result := aead.Seal(nil, nonce, data, nil)
	return append(nonce, result...), nil
}

func DecryptAES256GCM(data []byte, key []byte) ([]byte, error) {
	k := sha256.Sum256(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	nonceSize := aead.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	result, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("aead.Open: %w", err)
	}
	return result, nil
}

func EncryptAES256CBC(data []byte, key []byte) ([]byte, error) {
	k := sha256.Sum256(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	result := make([]byte, len(data))
	mode.CryptBlocks(result, data)
	return append(iv, result...), nil
}

func DecryptAES256CBC(data []byte, key []byte) ([]byte, error) {
	k := sha256.Sum256(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	ivSize := block.BlockSize()
	iv, ciphertext := data[:ivSize], data[ivSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	result := make([]byte, len(ciphertext))
	mode.CryptBlocks(result, ciphertext)
	return result, nil
}

func EncryptAES256CTR(data []byte, key []byte) ([]byte, error) {
	k := sha256.Sum256(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}
	mode := cipher.NewCTR(block, iv)
	result := make([]byte, len(data))
	mode.XORKeyStream(result, data)
	return append(iv, result...), nil
}

func DecryptAES256CTR(data []byte, key []byte) ([]byte, error) {
	k := sha256.Sum256(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	ivSize := block.BlockSize()
	iv, ciphertext := data[:ivSize], data[ivSize:]
	mode := cipher.NewCTR(block, iv)
	result := make([]byte, len(ciphertext))
	mode.XORKeyStream(result, ciphertext)
	return result, nil
}

func EncryptChacha20Poly1305(data []byte, key []byte) ([]byte, error) {
	k := sha256.Sum256(key)
	block, err := chacha20poly1305.New(k[:])
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305.New: %w", err)
	}
	nonce := make([]byte, block.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("rand.Read: %w", err)
	}
	result := block.Seal(nil, nonce, data, nil)
	return append(nonce, result...), nil
}

func DecryptChacha20Poly1305(data []byte, key []byte) ([]byte, error) {
	k := sha256.Sum256(key)
	block, err := chacha20poly1305.New(k[:])
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305.New: %w", err)
	}
	nonceSize := block.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	result, err := block.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("block.Open: %w", err)
	}
	return result, nil
}
