// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"golang.org/x/sync/semaphore"
)

func TestResolveOCITransportConfig_FillsDefaults(t *testing.T) {
	t.Parallel()
	defaults := ociTransportConfig{
		pullTimeoutSeconds: defaultOCIPullTimeoutSeconds,
		retryAttempts:      defaultOCIRetryMaxAttempts,
		retryWindow:        defaultOCIRetryMaxWindowSeconds,
		perHostSlots:       defaultOCIPerHostSlots,
	}
	withKeepalive := func(policy malcontent.KeepalivePolicy, seconds int) ociTransportConfig {
		c := defaults
		c.keepalivePolicy = policy
		c.keepaliveSeconds = seconds
		return c
	}
	cases := []struct {
		name string
		in   malcontent.Config
		want ociTransportConfig
	}{
		{
			name: "zero values take the hardened defaults",
			in:   malcontent.Config{},
			want: withKeepalive(malcontent.KeepalivePolicyExplicitlyEnabled, defaultOCIKeepaliveSeconds),
		},
		{
			name: "negative values take the hardened defaults",
			in: malcontent.Config{
				OCIPullTimeoutSeconds:    -1,
				OCIRetryMaxAttempts:      -1,
				OCIRetryMaxWindowSeconds: -1,
				OCIPerHostSlots:          -1,
				OCIKeepalivePolicy:       malcontent.KeepalivePolicyGoDefault,
			},
			want: withKeepalive(malcontent.KeepalivePolicyGoDefault, 0),
		},
		{
			name: "minimum positive values are kept",
			in: malcontent.Config{
				OCIPullTimeoutSeconds:    1,
				OCIRetryMaxAttempts:      1,
				OCIRetryMaxWindowSeconds: 1,
				OCIPerHostSlots:          1,
				OCIKeepalivePolicy:       malcontent.KeepalivePolicyGoDefault,
			},
			want: ociTransportConfig{
				pullTimeoutSeconds: 1,
				retryAttempts:      1,
				retryWindow:        1,
				perHostSlots:       1,
				keepalivePolicy:    malcontent.KeepalivePolicyGoDefault,
			},
		},
		{
			name: "positive values are kept",
			in: malcontent.Config{
				OCIPullTimeoutSeconds:    5,
				OCIRetryMaxAttempts:      1,
				OCIRetryMaxWindowSeconds: 7,
				OCIPerHostSlots:          2,
				OCIKeepalivePolicy:       malcontent.KeepalivePolicyExplicitlyDisabled,
				OCIKeepaliveSeconds:      9,
				OCIProxyOptIn:            true,
				OCICABundlePath:          "/etc/ssl/ca.pem",
			},
			want: ociTransportConfig{
				pullTimeoutSeconds: 5,
				retryAttempts:      1,
				retryWindow:        7,
				perHostSlots:       2,
				keepalivePolicy:    malcontent.KeepalivePolicyExplicitlyDisabled,
				keepaliveSeconds:   9,
				proxyOptIn:         true,
				caBundlePath:       "/etc/ssl/ca.pem",
			},
		},
		{
			name: "keepalive seconds without a policy are kept as given",
			in:   malcontent.Config{OCIKeepaliveSeconds: 5},
			want: withKeepalive("", 5),
		},
		{
			name: "explicit policy with zero seconds is kept as given",
			in:   malcontent.Config{OCIKeepalivePolicy: malcontent.KeepalivePolicyGoDefault},
			want: withKeepalive(malcontent.KeepalivePolicyGoDefault, 0),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := tc.in
			if got := resolveOCITransportConfig(t.Context(), &in); got != tc.want {
				t.Errorf("config: got = %+v, want = %+v", got, tc.want)
			}
		})
	}
}

// Not parallel: rearms the package-level one-shot warning.
func TestResolveOCITransportConfig_UnsetKeepaliveWarnsOnce(t *testing.T) {
	const warning = "OCIKeepalivePolicy is unset"
	cases := []struct {
		name  string
		calls []malcontent.Config
		want  int
	}{
		{
			name:  "unset policy and seconds warn once across calls",
			calls: []malcontent.Config{{}, {}},
			want:  1,
		},
		{
			name:  "go default policy does not warn",
			calls: []malcontent.Config{{OCIKeepalivePolicy: malcontent.KeepalivePolicyGoDefault}},
			want:  0,
		},
		{
			name:  "keepalive seconds without a policy do not warn",
			calls: []malcontent.Config{{OCIKeepaliveSeconds: 5}},
			want:  0,
		},
		{
			name:  "disabled policy with zero seconds does not warn",
			calls: []malcontent.Config{{OCIKeepalivePolicy: malcontent.KeepalivePolicyExplicitlyDisabled}},
			want:  0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ociResetOnce(t, &keepaliveUnsetWarnOnce)
			rec := &ociWarnRecorder{}
			ctx := clog.WithLogger(t.Context(), clog.New(rec))
			for i := range tc.calls {
				_ = resolveOCITransportConfig(ctx, &tc.calls[i])
			}
			if got := rec.count(warning); got != tc.want {
				t.Errorf("unset-keepalive warnings: got = %d, want = %d", got, tc.want)
			}
		})
	}
}

// Not parallel: sets process environment and rearms a one-shot warning.
func TestBuildScopedKeychain_MissingCredentialsWarnOnce(t *testing.T) {
	const warning = "OCI auth requested but"
	cases := []struct {
		name    string
		useAuth bool
		user    string
		pass    string
		calls   int
		want    int
	}{
		{name: "auth with user and pass does not warn", useAuth: true, user: "user", pass: "pass", calls: 1, want: 0},
		{name: "auth with only a user warns", useAuth: true, user: "user", calls: 1, want: 1},
		{name: "auth with only a pass warns", useAuth: true, pass: "pass", calls: 1, want: 1},
		{name: "auth with a whitespace-only user warns", useAuth: true, user: " \t", pass: "pass", calls: 1, want: 1},
		{name: "auth without credentials warns once across calls", useAuth: true, calls: 2, want: 1},
		{name: "anonymous pulls do not warn", useAuth: false, calls: 1, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(registryUserEnv, tc.user)
			t.Setenv(registryPassEnv, tc.pass)
			ociResetOnce(t, &authMissingWarnOnce)
			rec := &ociWarnRecorder{}
			ctx := clog.WithLogger(t.Context(), clog.New(rec))
			for range tc.calls {
				_ = buildScopedKeychain(ctx, tc.useAuth)
			}
			if got := rec.count(warning); got != tc.want {
				t.Errorf("missing-credential warnings: got = %d, want = %d", got, tc.want)
			}
		})
	}
}

func TestBuildTransport_TimeoutsAndProxy(t *testing.T) {
	t.Parallel()
	const pullTimeout = 7
	cases := []struct {
		name       string
		policy     malcontent.KeepalivePolicy
		proxyOptIn bool
	}{
		{name: "go default policy leaves keepalive at the stdlib default", policy: malcontent.KeepalivePolicyGoDefault},
		{name: "unrecognized policy falls back to the stdlib default", policy: "sometimes"},
		{name: "proxy opt-in reads the proxy from the environment", policy: malcontent.KeepalivePolicyGoDefault, proxyOptIn: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rt, err := buildTransport(ociTransportConfig{
				pullTimeoutSeconds: pullTimeout,
				keepalivePolicy:    tc.policy,
				proxyOptIn:         tc.proxyOptIn,
			})
			if err != nil {
				t.Fatalf("buildTransport: %v", err)
			}
			tr, ok := rt.(*http.Transport)
			if !ok {
				t.Fatalf("transport type: got = %T, want = *http.Transport", rt)
			}
			if got, want := tr.TLSHandshakeTimeout, 10*time.Second; got != want {
				t.Errorf("TLSHandshakeTimeout: got = %s, want = %s", got, want)
			}
			if got, want := tr.ResponseHeaderTimeout, pullTimeout*time.Second; got != want {
				t.Errorf("ResponseHeaderTimeout: got = %s, want = %s", got, want)
			}
			if got := tr.TLSClientConfig.MinVersion; got != tls.VersionTLS12 {
				t.Errorf("TLS MinVersion: got = %#x, want = %#x", got, tls.VersionTLS12)
			}
			if tr.IdleConnTimeout != 0 {
				t.Errorf("IdleConnTimeout: got = %s, want = 0", tr.IdleConnTimeout)
			}
			if tr.DisableKeepAlives {
				t.Errorf("DisableKeepAlives: got = true, want = false")
			}
			if got := tr.Proxy != nil; got != tc.proxyOptIn {
				t.Errorf("proxy configured: got = %v, want = %v", got, tc.proxyOptIn)
			}
		})
	}
}

func TestBuildTransport_CABundle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	root := openTestRoot(t, dir)
	bundlePEM, wantPool := ociTestCA(t)
	valid := filepath.Join(dir, "ca.pem")
	if err := root.WriteFile("ca.pem", bundlePEM, 0o600); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}
	garbage := filepath.Join(dir, "garbage.pem")
	if err := root.WriteFile("garbage.pem", []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write garbage bundle: %v", err)
	}

	cases := []struct {
		name      string
		path      string
		wantErr   string
		wantErrIs error
	}{
		{name: "relative path is rejected", path: "ca.pem", wantErr: "must be absolute"},
		{name: "missing file is rejected", path: filepath.Join(dir, "missing.pem"), wantErr: "read CA bundle", wantErrIs: fs.ErrNotExist},
		{name: "file without certificates is rejected", path: garbage, wantErr: "no certificates parsed"},
		{name: "valid bundle becomes the only trusted root", path: valid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rt, err := buildTransport(ociTransportConfig{
				pullTimeoutSeconds: 1,
				keepalivePolicy:    malcontent.KeepalivePolicyGoDefault,
				caBundlePath:       tc.path,
			})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error: got = %v, want containing %q", err, tc.wantErr)
				}
				if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
					t.Errorf("error chain: got = %v, want wrapping %v", err, tc.wantErrIs)
				}
				if rt != nil {
					t.Errorf("transport: got = %T, want = nil", rt)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildTransport: %v", err)
			}
			tr, ok := rt.(*http.Transport)
			if !ok {
				t.Fatalf("transport type: got = %T, want = *http.Transport", rt)
			}
			if !tr.TLSClientConfig.RootCAs.Equal(wantPool) {
				t.Errorf("root CAs: got = a pool other than the bundle, want = only the bundled certificate")
			}
		})
	}
}

// ociTestCA returns a PEM-encoded self-signed CA certificate and a pool that
// holds only that certificate.
func ociTestCA(t *testing.T) ([]byte, *x509.CertPool) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "malcontent test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pool
}

func TestSanitizeRefName_MapsRunesOutsideAllowlistToDash(t *testing.T) {
	t.Parallel()
	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
	for r := range rune(0x300) {
		want := "-"
		if strings.ContainsRune(allowed, r) {
			want = string(r)
		}
		if got := sanitizeRefName(string(r)); got != want {
			t.Errorf("sanitizeRefName(%q): got = %q, want = %q", string(r), got, want)
		}
	}
}

func TestSanitizeRefName_References(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "tagged reference", in: "cgr.dev/chainguard/static:latest", want: "cgr.dev-chainguard-static-latest"},
		{name: "digest reference with a port", in: "localhost:5000/a_b-c@sha256:0f", want: "localhost-5000-a_b-c-sha256-0f"},
		{name: "each non-ASCII rune becomes one dash", in: "imäge:✓", want: "im-ge--"},
		{name: "invalid UTF-8 byte becomes a dash", in: "a\xffb", want: "a-b"},
		{name: "empty input stays empty", in: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := sanitizeRefName(tc.in); got != tc.want {
				t.Errorf("sanitizeRefName(%q): got = %q, want = %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestGetOrCreateHostSemaphore_Capacity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		slots int
		want  int
	}{
		{name: "zero slots fall back to the default capacity", slots: 0, want: defaultOCIPerHostSlots},
		{name: "negative slots fall back to the default capacity", slots: -1, want: defaultOCIPerHostSlots},
		{name: "positive slots set the capacity", slots: 2, want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			host := "semaphore.invalid/" + t.Name()
			t.Cleanup(func() { hostSemaphores.Delete(host) })
			if got := ociSemaphoreCapacity(getOrCreateHostSemaphore(host, tc.slots)); got != tc.want {
				t.Errorf("capacity: got = %d, want = %d", got, tc.want)
			}
		})
	}
}

// TestGetOrCreateHostSemaphore_ConcurrentFirstUseSharesOneSemaphore checks
// that callers racing to create a host's semaphore all receive the stored one,
// so the per-host cap holds even for the first pulls from a registry. The
// callers spin until released so that several of them miss the initial lookup
// together.
func TestGetOrCreateHostSemaphore_ConcurrentFirstUseSharesOneSemaphore(t *testing.T) {
	t.Parallel()
	const rounds, callers = 50, 32
	for round := range rounds {
		host := fmt.Sprintf("concurrent.invalid/%s/%d", t.Name(), round)
		t.Cleanup(func() { hostSemaphores.Delete(host) })

		got := make([]*semaphore.Weighted, callers)
		var ready atomic.Int32
		var release atomic.Bool
		var wg sync.WaitGroup
		for i := range callers {
			wg.Go(func() {
				ready.Add(1)
				for !release.Load() {
					runtime.Gosched()
				}
				got[i] = getOrCreateHostSemaphore(host, 1)
			})
		}
		for ready.Load() < callers {
			runtime.Gosched()
		}
		release.Store(true)
		wg.Wait()

		distinct := make(map[*semaphore.Weighted]struct{}, callers)
		for _, s := range got {
			distinct[s] = struct{}{}
		}
		if len(distinct) != 1 {
			t.Fatalf("round %d distinct semaphores for one host: got = %d, want = 1", round, len(distinct))
		}
		if c := ociSemaphoreCapacity(got[0]); c != 1 {
			t.Fatalf("round %d capacity: got = %d, want = 1", round, c)
		}
	}
}

// ociSemaphoreCapacity counts how many single slots sem grants without
// blocking, up to a ceiling, then hands them back.
func ociSemaphoreCapacity(sem *semaphore.Weighted) int {
	const ceiling = 64
	n := 0
	for n < ceiling && sem.TryAcquire(1) {
		n++
	}
	if n > 0 {
		sem.Release(int64(n))
	}
	return n
}
