package peer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokensAndProofs(t *testing.T) {
	secretHex := strings.Repeat("0a", 32)
	secret, err := ParseSecret(secretHex)
	require.NoError(t, err)
	trusted, candidate := Token(secret, RoleTrusted), Token(secret, RoleCandidate)
	require.True(t, ValidToken(trusted) && ValidToken(candidate))
	require.NotEqual(t, trusted, candidate)
	// The exact byte layout of §9.
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("anvilkit/peer-token/v1/trusted"))
	require.Equal(t, hex.EncodeToString(m.Sum(nil)), trusted)

	nonce, err := Nonce()
	require.NoError(t, err)
	require.True(t, ValidNonce(nonce))
	proof, err := Proof(trusted, nonce)
	require.NoError(t, err)
	key, _ := hex.DecodeString(trusted)
	p := hmac.New(sha256.New, key)
	p.Write([]byte("anvilkit/sidecar-proof/v1/" + nonce))
	require.Equal(t, hex.EncodeToString(p.Sum(nil)), proof)
	require.True(t, ProofMatches(trusted, nonce, proof))
	require.False(t, ProofMatches(candidate, nonce, proof), "a proof is bound to the socket's token")
	require.False(t, ProofMatches(trusted, strings.Repeat("00", 16), proof), "and to the nonce")
	require.True(t, TokenMatches(trusted, trusted))
	require.False(t, TokenMatches(trusted, candidate))
}

func TestSecretShape(t *testing.T) {
	for _, bad := range []string{"", strings.Repeat("0A", 32), strings.Repeat("0", 63), strings.Repeat("0", 65), strings.Repeat("g", 64)} {
		_, err := ParseSecret(bad)
		require.ErrorIs(t, err, ErrSecret, bad)
	}
	require.False(t, ValidNonce("abc"))
	_, err := Proof("short", strings.Repeat("0", 32))
	require.Error(t, err)
}
