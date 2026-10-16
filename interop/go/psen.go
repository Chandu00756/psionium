// Package psen is a second, independent implementation of the .psen v2 format, written from
// docs/psen-v2.md alone. It exists to prove that the specification is complete and that files
// interoperate across implementations; use the psion command for real work.
package psen

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/argon2"
)

const (
	SuiteHybrid768 uint16 = 0x0001
	SuiteCNSA1024  uint16 = 0x0002

	prefixLen  = 26
	macLen     = 48
	wrappedLen = 48
	flagSigned = 0x01
)

type suiteParams struct {
	pkLen, skLen, ctLen, vkLen, sigLen int
	dkLen, ekLen, k                    int
	kem                                kem.Scheme
}

func params(suite uint16) (suiteParams, error) {
	switch suite {
	case SuiteHybrid768:
		return suiteParams{pkLen: 32 + 1184, skLen: 32 + 2400, ctLen: 32 + 1088, vkLen: 1952, sigLen: 3309,
			dkLen: 2400, ekLen: 1184, k: 3, kem: mlkem768.Scheme()}, nil
	case SuiteCNSA1024:
		return suiteParams{pkLen: 1568, skLen: 3168, ctLen: 1568, vkLen: 2592, sigLen: 4627,
			dkLen: 3168, ekLen: 1568, k: 4, kem: mlkem1024.Scheme()}, nil
	}
	return suiteParams{}, fmt.Errorf("unknown suite 0x%04x", suite)
}

// decodeKey parses "<prefix><base64url(suite ‖ body)>".
func decodeKey(text, prefix string) (uint16, []byte, error) {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, prefix) {
		return 0, nil, fmt.Errorf("expected %q", prefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(text[len(prefix):])
	if err != nil || len(raw) < 2 {
		return 0, nil, fmt.Errorf("bad %s key", prefix)
	}
	return binary.BigEndian.Uint16(raw), raw[2:], nil
}

func keyID(suite uint16, key []byte) []byte {
	h := sha512.New384()
	binary.Write(h, binary.BigEndian, suite)
	h.Write(key)
	return h.Sum(nil)[:16]
}

func hkdfKey(salt, ikm []byte, info string, n int) []byte {
	k, err := hkdf.Key(sha512.New384, ikm, salt, info, n)
	if err != nil {
		panic(err)
	}
	return k
}

func gcm(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

// Recipient is a parsed psionpk: public key.
type Recipient struct {
	Suite uint16
	PK    []byte
}

func ParseRecipient(text string) (Recipient, error) {
	suite, pk, err := decodeKey(text, "psionpk:")
	if err != nil {
		return Recipient{}, err
	}
	p, err := params(suite)
	if err != nil {
		return Recipient{}, err
	}
	if len(pk) != p.pkLen {
		return Recipient{}, errors.New("public key has the wrong length")
	}
	return Recipient{suite, pk}, nil
}

// Identity is a parsed identity file.
type Identity struct {
	Suite     uint16
	sk        []byte
	PK        []byte
	signSeed  []byte // nil when the identity has no signing key
	VerifyKey []byte
}

// ParseIdentity reads plain identity file contents: the first psionsk: and psionss: lines.
func ParseIdentity(contents string) (*Identity, error) {
	var skLine, ssLine string
	for _, l := range strings.Split(contents, "\n") {
		l = strings.TrimSpace(l)
		if skLine == "" && strings.HasPrefix(l, "psionsk:") {
			skLine = l
		}
		if ssLine == "" && strings.HasPrefix(l, "psionss:") {
			ssLine = l
		}
	}
	if skLine == "" {
		return nil, errors.New("no psionsk: line")
	}
	suite, sk, err := decodeKey(skLine, "psionsk:")
	if err != nil {
		return nil, err
	}
	p, err := params(suite)
	if err != nil {
		return nil, err
	}
	if len(sk) != p.skLen {
		return nil, errors.New("secret key has the wrong length")
	}
	// The FIPS 203 decapsulation key is dk_pke (384k) ‖ ek ‖ SHA3-256(ek) ‖ z.
	dk := sk[len(sk)-p.dkLen:]
	ek := dk[384*p.k : 384*p.k+p.ekLen]
	h := sha3.Sum256(ek)
	if !bytes.Equal(h[:], dk[384*p.k+p.ekLen:384*p.k+p.ekLen+32]) {
		return nil, errors.New("decapsulation key hash check failed")
	}
	id := &Identity{Suite: suite, sk: sk}
	if suite == SuiteHybrid768 {
		x, err := ecdh.X25519().NewPrivateKey(sk[:32])
		if err != nil {
			return nil, err
		}
		id.PK = append(x.PublicKey().Bytes(), ek...)
	} else {
		id.PK = append([]byte{}, ek...)
	}
	if ssLine != "" {
		ssSuite, seed, err := decodeKey(ssLine, "psionss:")
		if err != nil {
			return nil, err
		}
		if ssSuite != suite || len(seed) != 32 {
			return nil, errors.New("bad signing key")
		}
		id.signSeed = seed
		id.VerifyKey = verifyKeyFromSeed(suite, seed)
	}
	return id, nil
}

func verifyKeyFromSeed(suite uint16, seed []byte) []byte {
	var s [32]byte
	copy(s[:], seed)
	if suite == SuiteHybrid768 {
		pk, _ := mldsa65.NewKeyFromSeed(&s)
		return pk.Bytes()
	}
	pk, _ := mldsa87.NewKeyFromSeed(&s)
	return pk.Bytes()
}

func sign(suite uint16, seed, msg []byte) []byte {
	var s [32]byte
	copy(s[:], seed)
	if suite == SuiteHybrid768 {
		_, sk := mldsa65.NewKeyFromSeed(&s)
		sig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(sk, msg, nil, true, sig); err != nil {
			panic(err)
		}
		return sig
	}
	_, sk := mldsa87.NewKeyFromSeed(&s)
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(sk, msg, nil, true, sig); err != nil {
		panic(err)
	}
	return sig
}

func verify(suite uint16, vk, msg, sig []byte) bool {
	if suite == SuiteHybrid768 {
		var pk mldsa65.PublicKey
		if pk.UnmarshalBinary(vk) != nil {
			return false
		}
		return mldsa65.Verify(&pk, msg, nil, sig)
	}
	var pk mldsa87.PublicKey
	if pk.UnmarshalBinary(vk) != nil {
		return false
	}
	return mldsa87.Verify(&pk, msg, nil, sig)
}

func signedMessage(header, payload []byte) []byte {
	h := sha512.New384()
	h.Write(header)
	h.Write(payload)
	return append([]byte("psionium/v2/signature"), h.Sum(nil)...)
}

func nonce(i uint64, final bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[3:11], i)
	if final {
		n[11] = 1
	}
	return n
}

// Encrypt writes a .psen v2 file. signer may be nil.
func Encrypt(recipients []Recipient, plaintext []byte, chunkLog2 uint8, signer *Identity) ([]byte, error) {
	if len(recipients) == 0 || len(recipients) > 64 {
		return nil, errors.New("1 to 64 recipients")
	}
	suite := recipients[0].Suite
	p, err := params(suite)
	if err != nil {
		return nil, err
	}
	for _, r := range recipients {
		if r.Suite != suite {
			return nil, errors.New("mixed suites")
		}
	}
	if signer != nil && (signer.Suite != suite || signer.signSeed == nil) {
		return nil, errors.New("signer cannot sign for this suite")
	}
	fileKey := make([]byte, 32)
	salt := make([]byte, 16)
	rand.Read(fileKey)
	rand.Read(salt)

	var flags byte
	if signer != nil {
		flags = flagSigned
	}
	prefix := []byte("PSEN")
	prefix = append(prefix, 0x02)
	prefix = binary.BigEndian.AppendUint16(prefix, suite)
	prefix = append(prefix, chunkLog2, flags)
	prefix = append(prefix, salt...)
	prefix = append(prefix, byte(len(recipients)))

	header := append([]byte{}, prefix...)
	for _, r := range recipients {
		id := keyID(suite, r.PK)
		var kemCt, ikm []byte
		info := append([]byte("psionium/v2/kek"), byte(suite>>8), byte(suite))
		info = append(info, id...)
		if suite == SuiteHybrid768 {
			xpk, err := ecdh.X25519().NewPublicKey(r.PK[:32])
			if err != nil {
				return nil, err
			}
			esk, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}
			ssX, err := esk.ECDH(xpk)
			if err != nil {
				return nil, err
			}
			ek, err := mlkem.NewEncapsulationKey768(r.PK[32:])
			if err != nil {
				return nil, err
			}
			ssM, ctM := ek.Encapsulate()
			kemCt = append(esk.PublicKey().Bytes(), ctM...)
			ikm = append(ssM, ssX...)
			info = append(info, kemCt...)
			info = append(info, r.PK[:32]...)
		} else {
			ek, err := mlkem.NewEncapsulationKey1024(r.PK)
			if err != nil {
				return nil, err
			}
			ssM, ctM := ek.Encapsulate()
			kemCt, ikm = ctM, ssM
			info = append(info, kemCt...)
		}
		if len(kemCt) != p.ctLen {
			return nil, errors.New("internal: kem_ct length")
		}
		kek := hkdfKey(salt, ikm, string(info), 32)
		wrapped := gcm(kek).Seal(nil, make([]byte, 12), fileKey, append(append([]byte{}, prefix...), id...))
		header = append(header, id...)
		header = append(header, kemCt...)
		header = append(header, wrapped...)
	}
	if signer != nil {
		header = append(header, signer.VerifyKey...)
	}
	mac := hmac.New(sha512.New384, hkdfKey(salt, fileKey, "psionium/v2/header-mac", 48))
	mac.Write(header)
	header = mac.Sum(header)

	aead := gcm(hkdfKey(salt, fileKey, "psionium/v2/payload", 32))
	size := 1 << chunkLog2
	var payload []byte
	for i := uint64(0); ; i++ {
		start := int(i) * size
		end := min(start+size, len(plaintext))
		final := end == len(plaintext)
		payload = aead.Seal(payload, nonce(i, final), plaintext[start:end], nil)
		if final {
			break
		}
	}
	out := append(header, payload...)
	if signer != nil {
		out = append(out, sign(suite, signer.signSeed, signedMessage(header, payload))...)
	}
	return out, nil
}

// Result of a decryption.
type Result struct {
	Plaintext []byte
	Signer    []byte // the verified signer's verifying key, or nil for unsigned files
}

// Decrypt opens a whole .psen v2 file held in memory.
func Decrypt(id *Identity, file []byte) (*Result, error) {
	if len(file) < prefixLen || string(file[:4]) != "PSEN" || file[4] != 0x02 {
		return nil, errors.New("not a .psen v2 file")
	}
	suite := binary.BigEndian.Uint16(file[5:7])
	p, err := params(suite)
	if err != nil {
		return nil, err
	}
	chunkLog2, flags, salt, n := file[7], file[8], file[9:25], int(file[25])
	if chunkLog2 < 12 || chunkLog2 > 24 || flags&^flagSigned != 0 || n < 1 || n > 64 {
		return nil, errors.New("bad header")
	}
	if suite != id.Suite {
		return nil, errors.New("identity is for another suite")
	}
	signed := flags&flagSigned != 0
	prefix := file[:prefixLen]
	stanzaLen := 16 + p.ctLen + wrappedLen
	headerLen := prefixLen + n*stanzaLen + macLen
	if signed {
		headerLen += p.vkLen
	}
	trailer := 0
	if signed {
		trailer = p.sigLen
	}
	if len(file) < headerLen+trailer {
		return nil, errors.New("truncated")
	}

	myID := keyID(suite, id.PK)
	var fileKey []byte
	for s := 0; s < n && fileKey == nil; s++ {
		st := file[prefixLen+s*stanzaLen : prefixLen+(s+1)*stanzaLen]
		if !bytes.Equal(st[:16], myID) {
			continue
		}
		kemCt, wrapped := st[16:16+p.ctLen], st[16+p.ctLen:]
		dk, err := p.kem.UnmarshalBinaryPrivateKey(id.sk[len(id.sk)-p.dkLen:])
		if err != nil {
			return nil, err
		}
		info := append([]byte("psionium/v2/kek"), byte(suite>>8), byte(suite))
		info = append(info, myID...)
		info = append(info, kemCt...)
		var ikm []byte
		if suite == SuiteHybrid768 {
			xsk, _ := ecdh.X25519().NewPrivateKey(id.sk[:32])
			epk, err := ecdh.X25519().NewPublicKey(kemCt[:32])
			if err != nil {
				continue
			}
			ssX, err := xsk.ECDH(epk)
			if err != nil {
				continue
			}
			ssM, err := p.kem.Decapsulate(dk, kemCt[32:])
			if err != nil {
				continue
			}
			ikm = append(ssM, ssX...)
			info = append(info, id.PK[:32]...)
		} else {
			ssM, err := p.kem.Decapsulate(dk, kemCt)
			if err != nil {
				continue
			}
			ikm = ssM
		}
		kek := hkdfKey(salt, ikm, string(info), 32)
		fk, err := gcm(kek).Open(nil, make([]byte, 12), wrapped, append(append([]byte{}, prefix...), myID...))
		if err == nil {
			fileKey = fk
		}
	}
	if fileKey == nil {
		return nil, errors.New("not a recipient")
	}

	header := file[:headerLen]
	mac := hmac.New(sha512.New384, hkdfKey(salt, fileKey, "psionium/v2/header-mac", 48))
	mac.Write(header[:headerLen-macLen])
	if !hmac.Equal(mac.Sum(nil), header[headerLen-macLen:]) {
		return nil, errors.New("header authentication failed")
	}

	payload := file[headerLen : len(file)-trailer]
	aead := gcm(hkdfKey(salt, fileKey, "psionium/v2/payload", 32))
	block := (1 << chunkLog2) + 16
	var plaintext []byte
	off := 0
	for i := uint64(0); ; i++ {
		if off == len(payload) {
			return nil, errors.New("payload ends before the final chunk")
		}
		take := min(block, len(payload)-off)
		final := take < block || off+take == len(payload)
		plaintext, err = aead.Open(plaintext, nonce(i, final), payload[off:off+take], nil)
		if err != nil {
			return nil, fmt.Errorf("chunk %d does not open", i)
		}
		off += take
		if final {
			break
		}
	}

	res := &Result{Plaintext: plaintext}
	if signed {
		vk := header[headerLen-macLen-p.vkLen : headerLen-macLen]
		if !verify(suite, vk, signedMessage(header, payload), file[len(file)-trailer:]) {
			return nil, errors.New("signature does not verify")
		}
		res.Signer = vk
	}
	return res, nil
}

// Unprotect opens a psionpe: line and returns the secret lines it holds.
func Unprotect(contents string, passphrase []byte) (string, error) {
	var line string
	for _, l := range strings.Split(contents, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "psionpe:") {
			line = l
			break
		}
	}
	blob, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(line, "psionpe:"))
	if err != nil || len(blob) < 38+16 || blob[0] != 0x01 {
		return "", errors.New("bad protected identity")
	}
	m := binary.BigEndian.Uint32(blob[1:5])
	t := binary.BigEndian.Uint32(blob[5:9])
	lanes := blob[9]
	if m > 1<<20 || t > 16 || lanes > 16 {
		return "", errors.New("KDF parameters too large")
	}
	key := argon2.IDKey(passphrase, blob[10:26], t, m, lanes, 32)
	plain, err := gcm(key).Open(nil, blob[26:38], blob[38:], blob[:38])
	if err != nil {
		return "", errors.New("wrong passphrase")
	}
	return string(plain), nil
}
