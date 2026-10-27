// Package client is a typed HTTPS client for the sc-server API.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/adee42/mcp-server-control/internal/api"
	"github.com/adee42/mcp-server-control/internal/tlsutil"
)

type Options struct {
	Host string
	Port int
	Key  string
	// Fingerprint pins the server certificate ("SHA256:AB:..."); empty uses normal CA verification.
	Fingerprint string
	// Insecure skips verification entirely. Only for testing.
	Insecure bool
}

type Client struct {
	base string
	key  string
	http *http.Client
}

// APIError is a non-2xx response from the server.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("server returned %d %s: %s", e.Status, http.StatusText(e.Status), e.Message)
}

func New(o Options) (*Client, error) {
	if o.Host == "" {
		return nil, errors.New("host is required")
	}
	if o.Port == 0 {
		o.Port = 8443
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: o.Host}
	switch {
	case o.Fingerprint != "":
		want, err := tlsutil.NormalizeFingerprint(o.Fingerprint)
		if err != nil {
			return nil, err
		}
		// Chain and hostname checks are replaced by an exact match on the leaf certificate.
		tc.InsecureSkipVerify = true
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server sent no certificate")
			}
			if got := tlsutil.Fingerprint(cs.PeerCertificates[0].Raw); got != want {
				return fmt.Errorf("certificate fingerprint mismatch: server presented %s, expected %s", got, want)
			}
			return nil
		}
	case o.Insecure:
		tc.InsecureSkipVerify = true
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tc
	tr.Proxy = nil
	return &Client{
		base: "https://" + net.JoinHostPort(o.Host, strconv.Itoa(o.Port)),
		key:  o.Key,
		http: &http.Client{Transport: tr},
	}, nil
}

// do sends a request and decodes a JSON response into out. timeout bounds the whole call.
func (c *Client) do(ctx context.Context, timeout time.Duration, method, path string, query url.Values, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e api.Error
		if json.Unmarshal(data, &e) != nil || e.Error == "" {
			e.Error = string(bytes.TrimSpace(data))
		}
		return &APIError{Status: resp.StatusCode, Message: e.Error}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

const (
	shortTimeout = 30 * time.Second
	// slack is added to command timeouts to cover connection setup and transfer.
	slack = 30 * time.Second
)

func (c *Client) Health(ctx context.Context) (api.Health, error) {
	var h api.Health
	return h, c.do(ctx, shortTimeout, "GET", "/v1/health", nil, nil, &h)
}

func (c *Client) Info(ctx context.Context) (api.Info, error) {
	var i api.Info
	return i, c.do(ctx, shortTimeout, "GET", "/v1/info", nil, nil, &i)
}

func (c *Client) Exec(ctx context.Context, req api.ExecRequest) (api.ExecResult, error) {
	var r api.ExecResult
	// The server applies its default timeout when none is given and clamps to its maximum.
	t := 10 * time.Minute
	if req.TimeoutSeconds > 0 {
		t = time.Duration(req.TimeoutSeconds) * time.Second
	}
	return r, c.do(ctx, t+slack, "POST", "/v1/exec", nil, req, &r)
}

func (c *Client) StartJob(ctx context.Context, req api.JobRequest) (api.Job, error) {
	var j api.Job
	return j, c.do(ctx, shortTimeout, "POST", "/v1/jobs", nil, req, &j)
}

func (c *Client) Jobs(ctx context.Context) ([]api.Job, error) {
	var j []api.Job
	return j, c.do(ctx, shortTimeout, "GET", "/v1/jobs", nil, nil, &j)
}

// Job fetches status and output from offset, waiting up to waitSeconds for completion.
func (c *Client) Job(ctx context.Context, id string, offset int64, waitSeconds int) (api.JobOutput, error) {
	var o api.JobOutput
	q := url.Values{"offset": {strconv.FormatInt(offset, 10)}}
	if waitSeconds > 0 {
		q.Set("wait", strconv.Itoa(waitSeconds))
	}
	return o, c.do(ctx, time.Duration(waitSeconds)*time.Second+slack, "GET", "/v1/jobs/"+url.PathEscape(id), q, nil, &o)
}

func (c *Client) KillJob(ctx context.Context, id string) (api.Job, error) {
	var j api.Job
	return j, c.do(ctx, shortTimeout, "DELETE", "/v1/jobs/"+url.PathEscape(id), nil, nil, &j)
}

func (c *Client) ReadFile(ctx context.Context, path string) (api.FileContent, error) {
	var f api.FileContent
	return f, c.do(ctx, 5*time.Minute, "GET", "/v1/files", url.Values{"path": {path}}, nil, &f)
}

func (c *Client) WriteFile(ctx context.Context, path string, w api.FileWrite) (api.FileWriteResult, error) {
	var r api.FileWriteResult
	return r, c.do(ctx, 5*time.Minute, "PUT", "/v1/files", url.Values{"path": {path}}, w, &r)
}

func (c *Client) ListDir(ctx context.Context, path string) (api.DirListing, error) {
	var d api.DirListing
	return d, c.do(ctx, shortTimeout, "GET", "/v1/files/list", url.Values{"path": {path}}, nil, &d)
}

func (c *Client) Services(ctx context.Context, pattern string) ([]api.Service, error) {
	var s []api.Service
	var q url.Values
	if pattern != "" {
		q = url.Values{"pattern": {pattern}}
	}
	return s, c.do(ctx, shortTimeout+slack, "GET", "/v1/services", q, nil, &s)
}

func (c *Client) ServiceStatus(ctx context.Context, unit string, journalLines int) (api.ServiceStatus, error) {
	var s api.ServiceStatus
	q := url.Values{"journal_lines": {strconv.Itoa(journalLines)}}
	return s, c.do(ctx, shortTimeout+slack, "GET", "/v1/services/"+url.PathEscape(unit), q, nil, &s)
}

func (c *Client) ServiceAction(ctx context.Context, unit, action string) (api.ServiceActionResult, error) {
	var r api.ServiceActionResult
	return r, c.do(ctx, 2*time.Minute+slack, "POST", "/v1/services/"+url.PathEscape(unit)+"/"+url.PathEscape(action), nil, nil, &r)
}

func (c *Client) Cron(ctx context.Context) ([]api.CronJob, error) {
	var j []api.CronJob
	return j, c.do(ctx, shortTimeout, "GET", "/v1/cron", nil, nil, &j)
}

func (c *Client) PutCron(ctx context.Context, j api.CronJob) (api.CronJob, error) {
	var out api.CronJob
	return out, c.do(ctx, shortTimeout, "PUT", "/v1/cron/"+url.PathEscape(j.Name), nil, j, &out)
}

func (c *Client) DeleteCron(ctx context.Context, name string) error {
	return c.do(ctx, shortTimeout, "DELETE", "/v1/cron/"+url.PathEscape(name), nil, nil, nil)
}
