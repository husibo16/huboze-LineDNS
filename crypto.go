package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/fernet/fernet-go"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

var fernetKeys []*fernet.Key
var sessionSecret []byte

func loadKeys() error {
	b, err := os.ReadFile(FernetKeyFile)
	if err != nil {
		return fmt.Errorf("读取 %s 失败：%w", FernetKeyFile, err)
	}
	k, err := fernet.DecodeKey(strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("fernet.key 格式无效：%w", err)
	}
	fernetKeys = []*fernet.Key{k}
	s, err := os.ReadFile(SecretKeyFile)
	if err != nil {
		return fmt.Errorf("读取 %s 失败：%w", SecretKeyFile, err)
	}
	sessionSecret = []byte(strings.TrimSpace(string(s)))
	if len(sessionSecret) == 0 {
		return errors.New("flask_secret.key 为空")
	}
	return nil
}

// ensureKeyFiles creates the Fernet key and session secret when missing
// (same formats as the original installer, so upgrades keep working).
func ensureKeyFiles() error {
	if err := os.MkdirAll(ConfigDir, 0o750); err != nil {
		return err
	}
	if st, err := os.Stat(FernetKeyFile); err != nil || st.Size() == 0 {
		var k fernet.Key
		if err := k.Generate(); err != nil {
			return err
		}
		if err := os.WriteFile(FernetKeyFile, []byte(k.Encode()+"\n"), 0o600); err != nil {
			return err
		}
	}
	if st, err := os.Stat(SecretKeyFile); err != nil || st.Size() == 0 {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		if err := os.WriteFile(SecretKeyFile, []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func encryptSecret(v string) string {
	if v == "" {
		return ""
	}
	tok, err := fernet.EncryptAndSign([]byte(v), fernetKeys[0])
	if err != nil {
		return ""
	}
	return string(tok)
}

func decryptSecret(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	msg := fernet.VerifyAndDecrypt([]byte(v), 0, fernetKeys)
	if msg == nil {
		return "", errors.New("密钥解密失败，请检查 config/fernet.key 是否被更换")
	}
	return string(msg), nil
}

// ---------------- Werkzeug-compatible password hashes ----------------

const saltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(n int, chars string) string {
	var b strings.Builder
	max := big.NewInt(int64(len(chars)))
	for i := 0; i < n; i++ {
		x, _ := rand.Int(rand.Reader, max)
		b.WriteByte(chars[x.Int64()])
	}
	return b.String()
}

func randomURLSafe(nbytes int) string {
	b := make([]byte, nbytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// generatePasswordHash produces werkzeug's default "scrypt:32768:8:1$salt$hex".
func generatePasswordHash(password string) (string, error) {
	salt := randomString(16, saltChars)
	dk, err := scrypt.Key([]byte(password), []byte(salt), 32768, 8, 1, 64)
	if err != nil {
		return "", err
	}
	return "scrypt:32768:8:1$" + salt + "$" + hex.EncodeToString(dk), nil
}

func checkPasswordHash(pwhash, password string) bool {
	parts := strings.SplitN(pwhash, "$", 3)
	if len(parts) != 3 {
		return false
	}
	method, salt, want := parts[0], parts[1], parts[2]
	var got string
	mp := strings.Split(method, ":")
	switch mp[0] {
	case "scrypt":
		n, r, p := 32768, 8, 1
		if len(mp) == 4 {
			n, _ = strconv.Atoi(mp[1])
			r, _ = strconv.Atoi(mp[2])
			p, _ = strconv.Atoi(mp[3])
		}
		dk, err := scrypt.Key([]byte(password), []byte(salt), n, r, p, 64)
		if err != nil {
			return false
		}
		got = hex.EncodeToString(dk)
	case "pbkdf2":
		hname, iter := "sha256", 600000
		if len(mp) >= 2 {
			hname = mp[1]
		}
		if len(mp) >= 3 {
			iter, _ = strconv.Atoi(mp[2])
		}
		var h func() hash.Hash
		switch hname {
		case "sha256":
			h = sha256.New
		case "sha512":
			h = sha512.New
		case "sha1":
			h = sha1.New
		default:
			return false
		}
		dk := pbkdf2.Key([]byte(password), []byte(salt), iter, h().Size(), h)
		got = hex.EncodeToString(dk)
	default:
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// ---------------- signed cookie helper ----------------

func signValue(data []byte) string {
	m := hmac.New(sha256.New, sessionSecret)
	m.Write(data)
	return base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func unsignValue(v string) ([]byte, bool) {
	i := strings.LastIndexByte(v, '.')
	if i < 0 {
		return nil, false
	}
	data, err1 := base64.RawURLEncoding.DecodeString(v[:i])
	sig, err2 := base64.RawURLEncoding.DecodeString(v[i+1:])
	if err1 != nil || err2 != nil {
		return nil, false
	}
	m := hmac.New(sha256.New, sessionSecret)
	m.Write(data)
	if !hmac.Equal(sig, m.Sum(nil)) {
		return nil, false
	}
	return data, true
}
