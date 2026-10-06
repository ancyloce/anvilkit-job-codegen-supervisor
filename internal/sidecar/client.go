// Package sidecar is the trusted harness's client of the access sidecar's
// trusted socket (DD-03 §5): every request opens its own connection, sends
// one request and closes, so no descriptor is ever delegated and a
// connection never outlives its request.
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
	"os"
	"path/filepath"
	"syscall"
	"time"
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

// Client talks to trusted.sock.
type Client struct {
	Socket  string
	Timeout time.Duration
}

// VerifyLayout checks the socket directory and trusted socket carry the
// DD-03 ownership and modes before anything is sent: the directory
// owner:0 0711, trusted.sock owner:0 0660, both owned by the sidecar UID.
func (c *Client) VerifyLayout(sidecarUID uint32) error {
	check := func(path string, group uint32, mode os.FileMode, dir bool) error {
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		sys := st.Sys().(*syscall.Stat_t)
		if st.IsDir() != dir || (!dir && st.Mode()&os.ModeSocket == 0) {
			return fmt.Errorf("%s: unexpected file type", path)
		}
		if sys.Uid != sidecarUID || sys.Gid != group || st.Mode().Perm() != mode {
			return fmt.Errorf("%s is %d:%d %o, expected %d:%d %o", path, sys.Uid, sys.Gid, st.Mode().Perm(), sidecarUID, group, mode)
		}
		return nil
	}
	if err := check(filepath.Dir(c.Socket), 0, 0o711, true); err != nil {
		return err
	}
	return check(c.Socket, 0, 0o660, false)
}

// send makes one request on its own connection to the socket and returns
// the response; a non-2xx answer is an *Error with the sidecar's code.
func (c *Client) send(ctx context.Context, method, path string, headers map[string]string, body []byte) (*http.Response, error) {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
		},
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
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sidecar %s %s: %w", method, path, err)
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
// answered or ctx ends.
func (c *Client) AwaitScope(ctx context.Context, every time.Duration, log func(string)) (Scope, []string, error) {
	for {
		s, inputs, err := c.Scope(ctx)
		if err == nil {
			return s, inputs, nil
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

// WaitFor waits until the trusted socket exists (the sidecar container
// started) or the deadline passes.
func (c *Client) WaitFor(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if st, err := os.Lstat(c.Socket); err == nil && st.Mode()&os.ModeSocket != 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("trusted socket %s did not appear within %s", c.Socket, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
