// Package peer is the second peer binding of the access sidecar's sockets
// (DEC-045 B2, DD-03 §5): the launcher issues a per-launch secret to the
// sidecar and the trusted container; from it each side derives one token
// per socket role, every request carries its token and a fresh nonce, and
// every answer carries the sidecar's proof over that nonce, so a client
// knows it talked to the holder of the secret whatever the runtime reports
// as peer credentials. The candidate receives only its own token, never
// the secret.
package peer

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// RoleTrusted and RoleCandidate name the two sockets' token roles.
	RoleTrusted   = "trusted"
	RoleCandidate = "candidate"

	// HeaderToken, HeaderNonce and HeaderProof are the protocol's headers.
	HeaderToken = "Anvilkit-Peer-Token"
	HeaderNonce = "Anvilkit-Peer-Nonce"
	HeaderProof = "Anvilkit-Sidecar-Proof"

	// EnvToken is how a child process receives the token of its socket.
	EnvToken = "ANVILKIT_PEER_TOKEN"

	tokenPrefix = "anvilkit/peer-token/v1/"
	proofPrefix = "anvilkit/sidecar-proof/v1/"
	secretBytes = 32
	nonceBytes  = 16
)

// ErrSecret marks a launch secret that is not 64 lowercase hex characters.
var ErrSecret = errors.New("the launch secret must be 64 lowercase hex characters")

// ParseSecret decodes the launch secret as the launcher issues it.
func ParseSecret(s string) ([]byte, error) {
	if !isLowerHex(s, 2*secretBytes) {
		return nil, ErrSecret
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, ErrSecret
	}
	return b, nil
}

// Token derives the token of a socket role from the launch secret:
// hex(HMAC-SHA256(secret, "anvilkit/peer-token/v1/" + role)).
func Token(secret []byte, role string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(tokenPrefix + role))
	return hex.EncodeToString(m.Sum(nil))
}

// Nonce draws 16 fresh random bytes as 32 lowercase hex characters.
func Nonce() (string, error) {
	var b [nonceBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ValidNonce reports whether s is a well-formed nonce.
func ValidNonce(s string) bool { return isLowerHex(s, 2*nonceBytes) }

// ValidToken reports whether s is a well-formed token.
func ValidToken(s string) bool { return isLowerHex(s, 2*sha256.Size) }

// Proof is the sidecar's answer over a request's nonce:
// hex(HMAC-SHA256(decoded token, "anvilkit/sidecar-proof/v1/" + nonce)).
func Proof(token, nonce string) (string, error) {
	if !ValidToken(token) {
		return "", errors.New("peer token is not 64 lowercase hex characters")
	}
	key, err := hex.DecodeString(token)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(proofPrefix + nonce))
	return hex.EncodeToString(m.Sum(nil)), nil
}

// TokenMatches compares a presented token with the expected one in
// constant time.
func TokenMatches(expected, presented string) bool {
	return len(presented) == len(expected) && hmac.Equal([]byte(expected), []byte(presented))
}

// ProofMatches checks a presented proof against the token and nonce in
// constant time.
func ProofMatches(token, nonce, presented string) bool {
	want, err := Proof(token, nonce)
	if err != nil {
		return false
	}
	return len(presented) == len(want) && hmac.Equal([]byte(want), []byte(presented))
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
