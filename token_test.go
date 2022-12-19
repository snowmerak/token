package token_test

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/snowmerak/token"
)

func TestToken(t *testing.T) {
	privateKey := []byte("some private key")

	tk := token.New("some type", "some class")
	tk.SetHashMethod(token.Blake2b512)

	tk.SetCryptoMethod(privateKey, token.EncryptAES256GCM, token.DecryptAES256GCM)

	tk.SetPublicClaim("some public claim", []byte("some public claim value"))
	if err := tk.SetPrivateClaim("some private claim", []byte("some private claim value")); err != nil {
		t.Fatal(err)
	}

	tk.SetPublicClaim("some public claim2", []byte("some public claim value2"))
	if err := tk.SetPrivateClaim("some private claim2", []byte("some private claim value2")); err != nil {
		t.Fatal(err)
	}

	r := tk.Bytes()

	t.Log(hex.EncodeToString(r))
	t.Log(base64.RawURLEncoding.EncodeToString(r))

	tk2, err := token.FromBytes(r, token.Blake2b512)
	if err != nil {
		t.Fatal(err)
	}

	tk2.SetCryptoMethod(privateKey, token.EncryptAES256GCM, token.DecryptAES256GCM)

	t.Logf("%#v", tk2)

	if tk2.Type() != "some type" {
		t.Fatal("type mismatch")
	}

	if tk2.Class() != "some class" {
		t.Fatal("class mismatch")
	}

	v := tk2.GetPublicClaim("some public claim")
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "some public claim value" {
		t.Fatal("public claim mismatch")
	}

	v, err = tk2.GetPrivateClaim("some private claim")
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "some private claim value" {
		t.Fatal("private claim mismatch")
	}

	v = tk2.GetPublicClaim("some public claim2")
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "some public claim value2" {
		t.Fatal("public claim mismatch")
	}

	v, err = tk2.GetPrivateClaim("some private claim2")
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "some private claim value2" {
		t.Fatal("private claim mismatch")
	}

	if string(tk.Hash()) != string(tk2.Hash()) {
		t.Fatal("hash mismatch")
	}
}
