package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/peer"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// testServer serves the DEC-045 guard order of the sidecar on a unique
// abstract name: the peer UID is implicit (the caller is the server's own
// UID), then nonce, then token, then the proof on every answer. The
// behaviour is switched per test: a wrong proof, no proof, a refusal.
type testServer struct {
	name       string
	token      string
	noProof    bool
	wrongProof bool
	refuse     int
}

func serve(t *testing.T, s *testServer) {
	t.Helper()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.name, Net: "unix"})
	require.NoError(t, err)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := r.Header.Get(peer.HeaderNonce)
		if !peer.ValidNonce(nonce) {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"code":"PEER_NONCE_INVALID"}`)
			return
		}
		if !peer.TokenMatches(s.token, r.Header.Get(peer.HeaderToken)) {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"code":"PEER_TOKEN_MISMATCH"}`)
			return
		}
		proof, _ := peer.Proof(s.token, nonce)
		switch {
		case s.wrongProof:
			w.Header().Set(peer.HeaderProof, strings.Repeat("0", 64))
		case !s.noProof:
			w.Header().Set(peer.HeaderProof, proof)
		}
		w.Header().Set("Content-Type", "application/json")
		if s.refuse != 0 {
			w.WriteHeader(s.refuse)
			fmt.Fprint(w, `{"code":"SCOPE_UNAVAILABLE","reason":"not yet"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"scope": map[string]any{"attemptId": "att_1"}, "launchId": "lch_1", "inputs": []string{"a"}})
	})
	srv := &http.Server{Handler: h}
	srv.SetKeepAlivesEnabled(false)
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
}

func client(name string, token string) *Client {
	return &Client{Socket: name, Token: token, SidecarUID: uint32(os.Getuid()), Timeout: 5 * time.Second}
}

func uniqueName(t *testing.T) string {
	return fmt.Sprintf("@anvilkit-client-test-%d-%s/trusted", os.Getpid(), strings.ReplaceAll(t.Name(), "/", "_"))
}

func TestRequestCarriesTokenAndNonceAndChecksProof(t *testing.T) {
	secret, _ := peer.ParseSecret(testSecret)
	token := peer.Token(secret, peer.RoleTrusted)
	name := uniqueName(t)
	serve(t, &testServer{name: name, token: token})
	c := client(name, token)
	require.NoError(t, c.WaitFor(context.Background(), 5*time.Second))
	scope, inputs, err := c.Scope(context.Background())
	require.NoError(t, err)
	require.Equal(t, "att_1", scope.AttemptID)
	require.Equal(t, []string{"a"}, inputs)

	// The wrong token is refused by the server; the refusal carries no
	// proof, so the client reports the missing proof, not the code.
	wrong := client(name, peer.Token(secret, peer.RoleCandidate))
	_, _, err = wrong.Scope(context.Background())
	require.ErrorIs(t, err, ErrSidecarProof)
}

func TestWrongOrMissingProofIsRefused(t *testing.T) {
	secret, _ := peer.ParseSecret(testSecret)
	token := peer.Token(secret, peer.RoleTrusted)
	for label, s := range map[string]*testServer{"wrong proof": {wrongProof: true}, "no proof": {noProof: true}, "refusal without proof check bypass": {noProof: true, refuse: 503}} {
		name := uniqueName(t) + "-" + strings.ReplaceAll(label, " ", "-")
		s.name, s.token = name, token
		serve(t, s)
		c := client(name, token)
		_, _, err := c.Scope(context.Background())
		require.ErrorIs(t, err, ErrSidecarProof, label)
		// AwaitScope treats it as definitive: it does not poll.
		_, _, err = c.AwaitScope(context.Background(), time.Hour, nil)
		require.ErrorIs(t, err, ErrSidecarProof, label)
	}
}

func TestRefusalWithProofIsTheSidecarsCode(t *testing.T) {
	secret, _ := peer.ParseSecret(testSecret)
	token := peer.Token(secret, peer.RoleTrusted)
	name := uniqueName(t)
	serve(t, &testServer{name: name, token: token, refuse: 503})
	c := client(name, token)
	_, _, err := c.Scope(context.Background())
	var e *Error
	require.ErrorAs(t, err, &e)
	require.Equal(t, 503, e.Status)
	require.Equal(t, "SCOPE_UNAVAILABLE", e.Code)
}

func TestWaitForPollsByConnecting(t *testing.T) {
	secret, _ := peer.ParseSecret(testSecret)
	token := peer.Token(secret, peer.RoleTrusted)
	name := uniqueName(t)
	c := client(name, token)
	require.Error(t, c.WaitFor(context.Background(), 400*time.Millisecond), "nothing listens yet")
	go func() {
		time.Sleep(300 * time.Millisecond)
		serve(t, &testServer{name: name, token: token})
	}()
	require.NoError(t, c.WaitFor(context.Background(), 5*time.Second))
}

func TestServerIdentityIsChecked(t *testing.T) {
	secret, _ := peer.ParseSecret(testSecret)
	token := peer.Token(secret, peer.RoleTrusted)
	name := uniqueName(t)
	serve(t, &testServer{name: name, token: token})
	c := &Client{Socket: name, Token: token, SidecarUID: uint32(os.Getuid()) + 1, Timeout: 5 * time.Second}
	require.ErrorIs(t, c.WaitFor(context.Background(), 5*time.Second), ErrServerIdentity)
	_, _, err := c.Scope(context.Background())
	require.ErrorIs(t, err, ErrServerIdentity)
}
