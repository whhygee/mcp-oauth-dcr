package mcpoauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// TokenStore persists proxy tokens for DCR client validation.
// Implement with your preferred backend (Datastore, Redis, SQL, in-memory, etc.).
type TokenStore interface {
	Put(ctx context.Context, token string) error
	Exists(ctx context.Context, token string) bool
}

// GenToken generates a cryptographically random 32-byte proxy token.
func GenToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
