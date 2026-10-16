package psen

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const vectorDir = "../../crates/psionium-core/tests/vectors"

// plaintext matches the committed vectors: byte i is (i*31 + 7) mod 251.
func plaintext(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*31 + 7) % 251)
	}
	return b
}

func loadIdentity(t *testing.T, path string) (*Identity, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ParseIdentity(string(data))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return id, string(data)
}

// comment returns the key text written in a "# <label>: " comment line.
func comment(contents, label string) string {
	for _, l := range strings.Split(contents, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "# "+label+": "); ok {
			return v
		}
	}
	return ""
}

func encodeKey(prefix string, suite uint16, body []byte) string {
	raw := binary.BigEndian.AppendUint16(nil, suite)
	return prefix + base64.RawURLEncoding.EncodeToString(append(raw, body...))
}

func TestIdentitiesMatchTheirPublicKeys(t *testing.T) {
	for _, name := range []string{"hybrid.identity", "cnsa.identity"} {
		id, contents := loadIdentity(t, filepath.Join(vectorDir, name))
		if got, want := encodeKey("psionpk:", id.Suite, id.PK), comment(contents, "public key"); got != want {
			t.Errorf("%s: public key derived here differs from the file's", name)
		}
		// ML-DSA key generation from the seed must agree across implementations.
		if got, want := encodeKey("psionvk:", id.Suite, id.VerifyKey), comment(contents, "verify key"); got != want {
			t.Errorf("%s: verifying key derived here differs from the file's", name)
		}
	}
}

func TestCommittedVectorsDecrypt(t *testing.T) {
	vectors := []struct {
		file, identity string
		len            int
		signed         bool
	}{
		{"hybrid-empty.psen", "hybrid.identity", 0, false},
		{"hybrid-small.psen", "hybrid.identity", 1000, false},
		{"hybrid-multichunk-3-recipients.psen", "hybrid.identity", 3*4096 + 17, false},
		{"hybrid-exact-chunks.psen", "hybrid.identity", 2 * 4096, false},
		{"hybrid-signed.psen", "hybrid.identity", 5000, true},
		{"cnsa-small.psen", "cnsa.identity", 777, false},
		{"cnsa-signed.psen", "cnsa.identity", 9000, true},
	}
	for _, v := range vectors {
		id, _ := loadIdentity(t, filepath.Join(vectorDir, v.identity))
		file, err := os.ReadFile(filepath.Join(vectorDir, v.file))
		if err != nil {
			t.Fatal(err)
		}
		res, err := Decrypt(id, file)
		if err != nil {
			t.Fatalf("%s: %v", v.file, err)
		}
		if !bytes.Equal(res.Plaintext, plaintext(v.len)) {
			t.Errorf("%s: wrong plaintext", v.file)
		}
		if v.signed != (res.Signer != nil) || (v.signed && !bytes.Equal(res.Signer, id.VerifyKey)) {
			t.Errorf("%s: wrong signer", v.file)
		}
		// Any flipped bit must make decryption fail.
		for _, pos := range []int{10, 30, len(file) / 2, len(file) - 1} {
			bad := bytes.Clone(file)
			bad[pos] ^= 0x01
			if _, err := Decrypt(id, bad); err == nil {
				t.Errorf("%s: corrupted byte %d still decrypts", v.file, pos)
			}
		}
	}
}

func TestProtectedIdentityUnlocks(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(vectorDir, "hybrid.identity.protected"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unprotect(string(data), []byte("wrong passphrase")); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	secret, err := Unprotect(string(data), []byte("pSIONIUM test vector passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	locked, err := ParseIdentity(secret)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := loadIdentity(t, filepath.Join(vectorDir, "hybrid.identity"))
	if !bytes.Equal(locked.PK, plain.PK) || !bytes.Equal(locked.VerifyKey, plain.VerifyKey) {
		t.Fatal("protected identity holds different keys")
	}
}

func TestGoRoundTrip(t *testing.T) {
	for _, name := range []string{"hybrid.identity", "cnsa.identity"} {
		id, _ := loadIdentity(t, filepath.Join(vectorDir, name))
		for _, n := range []int{0, 1, 4096, 4097, 3*4096 + 5} {
			msg := plaintext(n)
			file, err := Encrypt([]Recipient{{id.Suite, id.PK}}, msg, 12, id)
			if err != nil {
				t.Fatal(err)
			}
			res, err := Decrypt(id, file)
			if err != nil || !bytes.Equal(res.Plaintext, msg) || !bytes.Equal(res.Signer, id.VerifyKey) {
				t.Fatalf("%s %d bytes: round trip failed: %v", name, n, err)
			}
		}
	}
}

// psion returns the psion binary to test against, from $PSION.
func psion(t *testing.T) string {
	bin := os.Getenv("PSION")
	if bin == "" {
		t.Skip("set PSION to a psion binary to run cross-implementation tests")
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func run(t *testing.T, bin string, stdin []byte, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("psion %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return out, nil
}

func keygen(t *testing.T, bin, dir, suite, name string) (string, *Identity) {
	t.Helper()
	path := filepath.Join(dir, name+".identity")
	if _, err := run(t, bin, nil, "keygen", "--no-passphrase", "--suite", suite, "-o", path); err != nil {
		t.Fatal(err)
	}
	id, _ := loadIdentity(t, path)
	return path, id
}

// Files written here must decrypt with psion, and the reverse.
func TestCrossImplementation(t *testing.T) {
	bin := psion(t)
	dir := t.TempDir()
	for _, suite := range []string{"pq-hybrid-768", "cnsa-1024"} {
		aPath, a := keygen(t, bin, dir, suite, suite+"-a")
		bPath, b := keygen(t, bin, dir, suite, suite+"-b")
		aVK := encodeKey("psionvk:", a.Suite, a.VerifyKey)
		bVK := encodeKey("psionvk:", b.Suite, b.VerifyKey)
		for _, n := range []int{0, 1, 4095, 4096, 4097, 3*4096 + 5, 70000} {
			for _, chunkLog2 := range []uint8{12, 16} {
				for _, signed := range []bool{false, true} {
					msg := make([]byte, n)
					rand.Read(msg)
					label := fmt.Sprintf("%s/%d bytes/chunk 2^%d/signed=%v", suite, n, chunkLog2, signed)

					// Go encrypts to two recipients; psion decrypts as each of them.
					var signer *Identity
					if signed {
						signer = a
					}
					file, err := Encrypt([]Recipient{{b.Suite, b.PK}, {a.Suite, a.PK}}, msg, chunkLog2, signer)
					if err != nil {
						t.Fatal(err)
					}
					in := filepath.Join(dir, "go.psen")
					if err := os.WriteFile(in, file, 0o600); err != nil {
						t.Fatal(err)
					}
					for _, idPath := range []string{aPath, bPath} {
						args := []string{"decrypt", "-i", idPath, "-o", "-"}
						if signed {
							args = append(args, "--signed-by", aVK)
						}
						out, err := run(t, bin, nil, append(args, in)...)
						if err != nil {
							t.Fatalf("%s: %v", label, err)
						}
						if !bytes.Equal(out, msg) {
							t.Fatalf("%s: psion decrypted different data", label)
						}
					}
					if signed {
						if _, err := run(t, bin, nil, "decrypt", "-i", aPath, "-o", "-", "--signed-by", bVK, in); err == nil {
							t.Fatalf("%s: psion accepted the wrong signer", label)
						}
					}

					// psion encrypts; Go decrypts.
					args := []string{"encrypt", "-r", encodeKey("psionpk:", a.Suite, a.PK), "--chunk-size-log2", fmt.Sprint(chunkLog2)}
					if signed {
						args = append(args, "--sign-with", bPath)
					}
					enc, err := run(t, bin, msg, args...)
					if err != nil {
						t.Fatalf("%s: %v", label, err)
					}
					res, err := Decrypt(a, enc)
					if err != nil {
						t.Fatalf("%s: Go could not decrypt psion's file: %v", label, err)
					}
					if !bytes.Equal(res.Plaintext, msg) {
						t.Fatalf("%s: Go decrypted different data", label)
					}
					if signed != (res.Signer != nil) || (signed && !bytes.Equal(res.Signer, b.VerifyKey)) {
						t.Fatalf("%s: wrong signer", label)
					}
				}
			}
		}
	}
}
