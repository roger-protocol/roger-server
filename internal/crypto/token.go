package crypto

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateSafeToken(prefix string) (string, error) {
	randomBytes := make([]byte, 32) // 32 bytes -> 256 bits
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
