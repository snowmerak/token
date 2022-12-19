package token_test

import (
	"crypto/rand"
	"testing"

	"github.com/snowmerak/token"
)

func TestAES256GCM(t *testing.T) {
	b := make([]byte, 1024)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	k := make([]byte, 256)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}

	r, err := token.EncryptAES256GCM(b, k)
	if err != nil {
		t.Fatal(err)
	}

	d, err := token.DecryptAES256GCM(r, k)
	if err != nil {
		t.Fatal(err)
	}

	if len(b) != len(d) {
		t.Fatal("length mismatch")
	}

	for i := range b {
		if b[i] != d[i] {
			t.Fatal("mismatch")
		}
	}
}

func TestAES256CBC(t *testing.T) {
	b := make([]byte, 1024)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	k := make([]byte, 256)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}

	r, err := token.EncryptAES256CBC(b, k)
	if err != nil {
		t.Fatal(err)
	}

	d, err := token.DecryptAES256CBC(r, k)
	if err != nil {
		t.Fatal(err)
	}

	if len(b) != len(d) {
		t.Fatal("length mismatch")
	}

	for i := range b {
		if b[i] != d[i] {
			t.Fatal("mismatch")
		}
	}
}

func TestAES256CTR(t *testing.T) {
	b := make([]byte, 1024)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	k := make([]byte, 256)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}

	r, err := token.EncryptAES256CTR(b, k)
	if err != nil {
		t.Fatal(err)
	}

	d, err := token.DecryptAES256CTR(r, k)
	if err != nil {
		t.Fatal(err)
	}

	if len(b) != len(d) {
		t.Fatal("length mismatch")
	}

	for i := range b {
		if b[i] != d[i] {
			t.Fatal("mismatch")
		}
	}
}

func TestChacha20Poloy1305(t *testing.T) {
	b := make([]byte, 1024)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	k := make([]byte, 256)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}

	r, err := token.EncryptChacha20Poly1305(b, k)
	if err != nil {
		t.Fatal(err)
	}

	d, err := token.DecryptChacha20Poly1305(r, k)
	if err != nil {
		t.Fatal(err)
	}

	if len(b) != len(d) {
		t.Fatal("length mismatch")
	}

	for i := range b {
		if b[i] != d[i] {
			t.Fatal("mismatch")
		}
	}
}
