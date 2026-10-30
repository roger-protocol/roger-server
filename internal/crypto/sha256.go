package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

func Hash256(data []byte, encoder func([]byte) string) string {
	hash := sha256.Sum256(data)
	if encoder == nil {
		encoder = hex.EncodeToString
	}
	return encoder(hash[:])
}
