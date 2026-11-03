// Package sidecar is the trusted harness's client of the access sidecar's
// trusted socket (DD-03 §5, DEC-045): an abstract-namespace Unix socket
// inside the Pod (no file, no directory, no shared volume). Every request
// opens its own connection, verifies the server's kernel-reported identity
// (SO_PEERCRED, the sidecar's UID) before sending, sends one request
// carrying the peer token and a fresh nonce, requires the sidecar's proof
// over that nonce on the answer, and closes, so no descriptor is ever
// delegated and a connection never outlives its request.
package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ancyloce/anvilkit-job-codegen-supervisor/internal/peer"
)

// Error is a sidecar refusal with its public code.
type Error struct {
	Status int
	Code   string
	Reason string
}

func (e *Error) Error() string {
	return fmt.Sprintf("sidecar answered %d %s %s", e.Status, e.Code, e.Reason)
}

// ErrSidecarProof marks an answer whose proof is missing or wrong: whoever
// answered does not hold this launch's secret, and the answer is discarded.
var ErrSidecarProof = errors.New("sidecar proof missing or wrong: the answer is not the sidecar's")

// ErrServerIdentity marks a connection whose server is not the sidecar's
// UID; nothing is sent on it.
var ErrServerIdentity = errors.New("the socket's server is not the sidecar's UID")

// Client talks to the trusted socket. Socket is the abstract name ('@'
// prefixed; Go's net package binds a leading '@' to the abstract
// namespace), Token the trusted peer token, SidecarUID the server identity
// every connection must carry.
type Client struct {
	Socket     string
	Token      string
	SidecarUID uint32
	Timeout    time.Duration
}

// dial opens one connection and verifies the server's credentials before
// anything is written on it.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, err
	}
	uid, err := ServerUID(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if uid != c.SidecarUID {
		conn.Close()
		return nil, fmt.Errorf("%w: uid %d, expected %d", ErrServerIdentity, uid, c.SidecarUID)
	}
	return conn, nil
}

// ServerUID reads the kernel-reported UID of the process on the other end
// of a Unix connection (SO_PEERCRED).
func ServerUID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return cred.Uid, nil
}

// send makes one request on its own connection to the socket and returns
// the response once its proof is verified; a non-2xx answer is an *Error
// with the sidecar's code.
func (c *Client) send(ctx context.Context, method, path string, headers map[string]string, body []byte) (*http.Response, error) {
	nonce, err := peer.Nonce()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext:       func(ctx context.Context, _, _ string) (net.Conn, error) { return c.dial(ctx) },
		DisableKeepAlives: true, MaxConnsPerHost: 1,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: c.Timeout}
	req, err := http.NewRequestWithContext(ctx, method, "http://sidecar"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Close = true
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set(peer.HeaderToken, c.Token)
	req.Header.Set(peer.HeaderNonce, nonce)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sidecar %s %s: %w", method, path, err)
	}
	if !peer.ProofMatches(c.Token, nonce, resp.Header.Get(peer.HeaderProof)) {
		resp.Body.Close()
		return nil, fmt.Errorf("sidecar %s %s (status %d): %w", method, path, resp.StatusCode, ErrSidecarProof)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		e := &Error{Status: resp.StatusCode}
		var f struct {
			Code   string `json:"code"`
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(raw, &f)
		e.Code, e.Reason = f.Code, f.Reason
		return nil, e
	}
	return resp, nil
}

func (c *Client) do(ctx context.Context, method, path string, headers map[string]string, body []byte, out any) error {
	resp, err := c.send(ctx, method, path, headers, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Scope is the resolved execution scope.
type Scope struct {
	TenantID       string    `json:"tenantId"`
	OperationID    string    `json:"operationId"`
	AttemptID      string    `json:"attemptId"`
	InstanceID     string    `json:"instanceId"`
	Current        bool      `json:"current"`
	ProfileID      string    `json:"profileId"`
	ExecutionEpoch string    `json:"executionEpoch"`
	LaunchKey      string    `json:"launchKey"`
	Deadline       time.Time `json:"deadline"`
}

type scopeAnswer struct {
	Scope    Scope    `json:"scope"`
	LaunchID string   `json:"launchId"`
	Inputs   []string `json:"inputs"`
}

// Scope reads the scope once; a *Error with code SCOPE_UNAVAILABLE means
// the launcher has not registered the instance yet.
func (c *Client) Scope(ctx context.Context) (Scope, []string, error) {
	var a scopeAnswer
	if err := c.do(ctx, http.MethodGet, "/v1/scope", nil, nil, &a); err != nil {
		return Scope{}, nil, err
	}
	return a.Scope, a.Inputs, nil
}

// AwaitScope polls Scope until it resolves, a definitive refusal is
// answered or ctx ends. A proof or server-identity failure is definitive.
func (c *Client) AwaitScope(ctx context.Context, every time.Duration, log func(string)) (Scope, []string, error) {
	for {
		s, inputs, err := c.Scope(ctx)
		if err == nil {
			return s, inputs, nil
		}
		if errors.Is(err, ErrSidecarProof) || errors.Is(err, ErrServerIdentity) {
			return Scope{}, nil, err
		}
		var e *Error
		if errors.As(err, &e) && e.Code != "SCOPE_UNAVAILABLE" && e.Code != "DEPENDENCY_UNAVAILABLE" {
			return Scope{}, nil, err
		}
		if log != nil {
			log(err.Error())
		}
		select {
		case <-ctx.Done():
			return Scope{}, nil, fmt.Errorf("scope not resolved: %w (last: %v)", ctx.Err(), err)
		case <-time.After(every):
		}
	}
}

// StageInput hands a permitted input's bytes to the sidecar for the
// candidate route.
func (c *Client) StageInput(ctx context.Context, name string, body []byte) error {
	return c.do(ctx, http.MethodPut, "/v1/inputs/"+name, map[string]string{"Content-Type": "application/octet-stream"}, body, nil)
}

// LoadedInput is what the sidecar loaded for a handle-bound input.
type LoadedInput struct {
	Name      string `json:"name"`
	Class     string `json:"class"`
	Digest    string `json:"digest"`
	SizeBytes int64  `json:"sizeBytes"`
}

// LoadInput asks the sidecar to load the input the envelope binds to an
// artifact handle through Control (P13-04) and stage it; the bytes are
// then read back with ReadInput. This process never sees a capability.
func (c *Client) LoadInput(ctx context.Context, name string) (LoadedInput, error) {
	var out LoadedInput
	err := c.do(ctx, http.MethodPost, "/v1/inputs/"+name+"/loads", nil, nil, &out)
	return out, err
}

// ReadInput reads the staged bytes of an input from the trusted socket,
// bounded by maxBytes.
func (c *Client) ReadInput(ctx context.Context, name string, maxBytes int64) ([]byte, error) {
	resp, err := c.send(ctx, http.MethodGet, "/v1/inputs/"+name, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("input %s exceeds %d bytes", name, maxBytes)
	}
	return body, nil
}

// Transfer is a finalized scoped upload.
type Transfer struct {
	Handle        string `json:"handle"`
	TransferID    string `json:"transferId"`
	Class         string `json:"class"`
	Digest        string `json:"digest"`
	SizeBytes     string `json:"sizeBytes"`
	ObjectVersion string `json:"objectVersion"`
	State         string `json:"state"`
	Existing      bool   `json:"existing"`
}

// Upload runs the scoped transfer of bytes the trusted observer produced.
func (c *Client) Upload(ctx context.Context, class, mediaType string, body []byte) (Transfer, error) {
	var t Transfer
	err := c.do(ctx, http.MethodPost, "/v1/transfers", map[string]string{"X-Anvilkit-Class": class, "Content-Type": mediaType}, body, &t)
	return t, err
}

// Stage is an accepted result.
type Stage struct {
	StageID      string `json:"stageId"`
	ResultDigest string `json:"resultDigest"`
	Existing     bool   `json:"existing"`
}

// Submit submits the result manifest for acceptance.
func (c *Client) Submit(ctx context.Context, verdict, failureCode, observer string, manifest json.RawMessage) (Stage, error) {
	body, err := json.Marshal(map[string]any{"verdict": verdict, "failureCode": failureCode, "observerIdentity": observer, "manifest": manifest})
	if err != nil {
		return Stage{}, err
	}
	var s Stage
	err = c.do(ctx, http.MethodPost, "/v1/results", map[string]string{"Content-Type": "application/json"}, body, &s)
	return s, err
}

// WaitFor waits until the trusted name accepts a connection from the
// sidecar's UID (the sidecar container started and bound its sockets) or
// the deadline passes. A connection refused or a missing name is "not
// yet"; a name held by another identity is refused at once.
func (c *Client) WaitFor(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := c.dial(ctx)
		if err == nil {
			conn.Close()
			return nil
		}
		if errors.Is(err, ErrServerIdentity) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("trusted socket %s did not appear within %s (last: %v)", c.Socket, timeout, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
