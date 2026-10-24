package crypto

import (
	"encoding/base64"
	"uuid"
)

func GenerateID(prefix string) string {
	id := uuid.NewV7()
	encoded := base64.RawURLEncoding.EncodeToString(id[:])
	return prefix + "_" + encoded
}
