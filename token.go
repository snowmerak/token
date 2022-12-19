package token

type Token struct {
	typ           string
	class         string
	publicClaims  map[string][]byte
	privateClaims map[string][]byte
	hash          []byte

	cryptoKey     []byte
	encryptMethod func([]byte, []byte) []byte
	decryptMethod func([]byte, []byte) []byte
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

func (t *Token) SetCryptoMethod(key []byte, encrpyt func([]byte, []byte) []byte, decrypt func([]byte, []byte) []byte) {
	t.encryptMethod = encrpyt
	t.decryptMethod = decrypt
	t.cryptoKey = key
}

func (t *Token) SetHashMethod(method func(*Token) []byte) {
	t.hashMethod = method
}
