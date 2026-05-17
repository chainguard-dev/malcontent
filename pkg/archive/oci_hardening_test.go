// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// hostileRegistry implements a minimal subset of the OCI distribution v2 protocol with
// configurable hostile behaviors per test.
type hostileRegistry struct {
	t *testing.T

	// behavior hooks
	manifestDelay time.Duration
	always503     bool
	transient408  int32
	declaredSize  int64

	// observability
	manifestHits int32
	blobHits     int32
	inFlight     int32
	peakInFlight int32

	authHeaderSeen atomic.Pointer[string]

	// payloads
	configBlob   []byte
	configDigest string
	layerBlob    []byte
	layerDigest  string
	manifestJSON []byte
}

// newHostileRegistry assembles a layer + config + manifest. The optional declaredSize
// overrides the manifest's layer.Size field so size-preflight tests can advertise an
// oversized payload without actually serving one.
func newHostileRegistry(t *testing.T, declaredSize int64) *hostileRegistry {
	t.Helper()

	// Build a single-entry tar.gz layer.
	var layerRaw bytes.Buffer
	gz := gzip.NewWriter(&layerRaw)
	tw := tar.NewWriter(gz)
	body := []byte("hello-malcontent")
	hdr := &tar.Header{Name: "hello.txt", Mode: 0o644, Size: int64(len(body))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	_ = tw.Close()
	_ = gz.Close()
	layer := layerRaw.Bytes()
	layerDigest := digestOf(layer)

	// Minimal Docker v2 config blob.
	configBlob := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:` + digestOf(body)[7:] + `"]}}`)
	configDigest := digestOf(configBlob)

	advertisedLayerSize := int64(len(layer))
	if declaredSize > 0 {
		advertisedLayerSize = declaredSize
	}

	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.docker.distribution.manifest.v2+json",
		"config": map[string]any{
			"mediaType": "application/vnd.docker.container.image.v1+json",
			"size":      len(configBlob),
			"digest":    configDigest,
		},
		"layers": []map[string]any{
			{
				"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
				"size":      advertisedLayerSize,
				"digest":    layerDigest,
			},
		},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	return &hostileRegistry{
		t:            t,
		declaredSize: advertisedLayerSize,
		configBlob:   configBlob,
		configDigest: configDigest,
		layerBlob:    layer,
		layerDigest:  layerDigest,
		manifestJSON: manifestJSON,
	}
}

func digestOf(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func (h *hostileRegistry) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&h.inFlight, 1)
		for {
			peak := atomic.LoadInt32(&h.peakInFlight)
			if current <= peak || atomic.CompareAndSwapInt32(&h.peakInFlight, peak, current) {
				break
			}
		}
		defer atomic.AddInt32(&h.inFlight, -1)

		if auth := r.Header.Get("Authorization"); auth != "" {
			a := auth
			h.authHeaderSeen.Store(&a)
		}

		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
			return
		case strings.HasPrefix(r.URL.Path, "/v2/") && strings.Contains(r.URL.Path, "/manifests/"):
			hit := atomic.AddInt32(&h.manifestHits, 1)
			if h.always503 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if h.transient408 > 0 && hit <= h.transient408 {
				w.WriteHeader(http.StatusRequestTimeout)
				return
			}
			if h.manifestDelay > 0 {
				select {
				case <-time.After(h.manifestDelay):
				case <-r.Context().Done():
					return
				}
			}
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Header().Set("Docker-Content-Digest", digestOf(h.manifestJSON))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(h.manifestJSON)
		case strings.HasPrefix(r.URL.Path, "/v2/") && strings.Contains(r.URL.Path, "/blobs/"):
			atomic.AddInt32(&h.blobHits, 1)
			if strings.HasSuffix(r.URL.Path, h.configDigest) {
				_, _ = w.Write(h.configBlob)
				return
			}
			if strings.HasSuffix(r.URL.Path, h.layerDigest) {
				_, _ = w.Write(h.layerBlob)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// hostPort strips the scheme from an httptest.Server URL so it can be used as the
// host portion of an OCI reference.
func hostPort(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	return u.Host
}

// withCleanHostSemaphores resets the package-level host semaphore map between tests so
// per-host caps are recomputed from the current Config.
func withCleanHostSemaphores(t *testing.T) {
	t.Helper()
	hostSemaphores.Range(func(k, _ any) bool {
		hostSemaphores.Delete(k)
		return true
	})
}

func TestOCIHardening_PullTimeout_HangAborted(t *testing.T) {
	withCleanHostSemaphores(t)
	reg := newHostileRegistry(t, 0)
	reg.manifestDelay = 30 * time.Second
	srv := httptest.NewServer(reg.handler())
	defer srv.Close()

	c := &malcontent.Config{
		OCIPullTimeoutSeconds:    2,
		OCIRetryMaxAttempts:      1,
		OCIRetryMaxWindowSeconds: 1,
		OCIPerHostSlots:          2,
	}

	start := time.Now()
	_, err := OCIWithConfig(context.Background(), hostPort(t, srv.URL)+"/foo:bar", c)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if elapsed > 7*time.Second {
		t.Fatalf("timeout did not abort within slack: elapsed=%s", elapsed)
	}
}

func TestOCIHardening_Retry_Infinite503Aborted(t *testing.T) {
	withCleanHostSemaphores(t)
	reg := newHostileRegistry(t, 0)
	reg.always503 = true
	srv := httptest.NewServer(reg.handler())
	defer srv.Close()

	c := &malcontent.Config{
		OCIPullTimeoutSeconds:    30,
		OCIRetryMaxAttempts:      3,
		OCIRetryMaxWindowSeconds: 3,
		OCIPerHostSlots:          2,
	}

	start := time.Now()
	_, err := OCIWithConfig(context.Background(), hostPort(t, srv.URL)+"/foo:bar", c)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected retry-exhausted error, got nil")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("retry budget did not bound: elapsed=%s", elapsed)
	}
	if atomic.LoadInt32(&reg.manifestHits) == 0 {
		t.Fatalf("expected at least one manifest hit, got 0")
	}
}

func TestOCIHardening_Retry_408RequestTimeout_Retried(t *testing.T) {
	withCleanHostSemaphores(t)
	reg := newHostileRegistry(t, 0)
	reg.transient408 = 2
	srv := httptest.NewServer(reg.handler())
	defer srv.Close()

	c := &malcontent.Config{
		OCIPullTimeoutSeconds:    30,
		OCIRetryMaxAttempts:      5,
		OCIRetryMaxWindowSeconds: 10,
		OCIPerHostSlots:          2,
	}

	_, err := OCIWithConfig(context.Background(), hostPort(t, srv.URL)+"/foo:bar", c)
	if err != nil && strings.Contains(err.Error(), "408") {
		t.Fatalf("408 was not retried: %v", err)
	}
	hits := atomic.LoadInt32(&reg.manifestHits)
	if hits <= reg.transient408 {
		t.Fatalf("expected more than %d manifest hits after 408 retries, got %d", reg.transient408, hits)
	}
}

func TestOCIHardening_PerHostConcurrency_CapEnforced(t *testing.T) {
	withCleanHostSemaphores(t)
	reg := newHostileRegistry(t, 0)
	reg.manifestDelay = 200 * time.Millisecond
	srv := httptest.NewServer(reg.handler())
	defer srv.Close()

	c := &malcontent.Config{
		OCIPullTimeoutSeconds:    30,
		OCIRetryMaxAttempts:      1,
		OCIRetryMaxWindowSeconds: 5,
		OCIPerHostSlots:          2,
	}

	host := hostPort(t, srv.URL)
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ref := fmt.Sprintf("%s/foo:bar%d", host, i)
			_, _ = OCIWithConfig(context.Background(), ref, c)
		}(i)
	}
	wg.Wait()

	peak := atomic.LoadInt32(&reg.peakInFlight)
	if peak > int32(c.OCIPerHostSlots) {
		t.Fatalf("peak in-flight %d exceeded per-host slots %d", peak, c.OCIPerHostSlots)
	}
}

func TestOCIHardening_Keepalive_Explicit(t *testing.T) {
	// Predicate KeepalivePolicy.explicitlyEnabled: policy=enabled with positive seconds yields IdleConnTimeout > 0.
	cfg := ociTransportConfig{
		pullTimeoutSeconds: 5,
		keepalivePolicy:    malcontent.KeepalivePolicyExplicitlyEnabled,
		keepaliveSeconds:   30,
		perHostSlots:       1,
	}
	rt, err := buildTransport(cfg)
	if err != nil {
		t.Fatalf("buildTransport (enabled): %v", err)
	}
	tr, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected RoundTripper type %T", rt)
	}
	if tr.IdleConnTimeout <= 0 {
		t.Fatalf("expected IdleConnTimeout > 0 with keepalive enabled, got %s", tr.IdleConnTimeout)
	}
	if tr.DisableKeepAlives {
		t.Fatalf("expected DisableKeepAlives=false with keepalive enabled")
	}

	cfg.keepalivePolicy = malcontent.KeepalivePolicyExplicitlyDisabled
	cfg.keepaliveSeconds = 0
	rt2, err := buildTransport(cfg)
	if err != nil {
		t.Fatalf("buildTransport (disabled): %v", err)
	}
	tr2 := rt2.(*http.Transport)
	if !tr2.DisableKeepAlives {
		t.Fatalf("expected DisableKeepAlives=true with policy=disabled")
	}
}

func TestOCIHardening_ProxyPolicy_HTTPSProxyBypassedByDefault(t *testing.T) {
	withCleanHostSemaphores(t)
	t.Setenv("HTTPS_PROXY", "http://untrusted.invalid:9999")
	t.Setenv("HTTP_PROXY", "http://untrusted.invalid:9999")

	reg := newHostileRegistry(t, 0)
	srv := httptest.NewServer(reg.handler())
	defer srv.Close()

	c := &malcontent.Config{
		OCIPullTimeoutSeconds:    5,
		OCIRetryMaxAttempts:      1,
		OCIRetryMaxWindowSeconds: 1,
		OCIPerHostSlots:          2,
		OCIProxyOptIn:            false,
	}

	_, err := OCIWithConfig(context.Background(), hostPort(t, srv.URL)+"/foo:bar", c)
	if err != nil {
		// The extraction may fail downstream, but the pull itself must reach the test server.
		if atomic.LoadInt32(&reg.manifestHits) == 0 {
			t.Fatalf("proxy bypass failed: no manifest hits, err=%v", err)
		}
	}
	if atomic.LoadInt32(&reg.manifestHits) == 0 {
		t.Fatalf("expected manifest hits with proxy bypass")
	}
}

func TestOCIHardening_SizePreflight_OversizedAbortedBeforeBodyFetch(t *testing.T) {
	withCleanHostSemaphores(t)
	const oversized = int64(1 << 30) // 1 GiB advertised
	reg := newHostileRegistry(t, oversized)
	srv := httptest.NewServer(reg.handler())
	defer srv.Close()

	c := &malcontent.Config{
		OCIPullTimeoutSeconds:    30,
		OCIRetryMaxAttempts:      1,
		OCIRetryMaxWindowSeconds: 5,
		OCIPerHostSlots:          2,
		MaxImageSize:             1 << 16, // 64 KiB
	}

	_, err := OCIWithConfig(context.Background(), hostPort(t, srv.URL)+"/foo:bar", c)
	if err == nil {
		t.Fatalf("expected size-preflight rejection, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum allowed size") {
		t.Fatalf("expected size error, got %v", err)
	}
	if got := atomic.LoadInt32(&reg.blobHits); got != 0 {
		t.Fatalf("size preflight should have aborted before blob fetch, got %d blob hits", got)
	}
}

func TestOCIHardening_Keychain_AmbientDefaultRejected(t *testing.T) {
	withCleanHostSemaphores(t)

	// Stand up a docker-config file pointing at the test server.
	dockerCfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dockerCfgDir, "config.json"),
		[]byte(`{"auths":{"127.0.0.1":{"auth":"dXNlcjpwYXNz"}}}`), 0o644); err != nil {
		t.Fatalf("write docker config: %v", err)
	}
	t.Setenv("DOCKER_CONFIG", dockerCfgDir)

	// Auth disabled → Anonymous; no Authorization header should be observed.
	t.Run("auth_disabled_anonymous", func(t *testing.T) {
		reg := newHostileRegistry(t, 0)
		srv := httptest.NewServer(reg.handler())
		defer srv.Close()

		c := &malcontent.Config{
			OCIAuth:                  false,
			OCIPullTimeoutSeconds:    5,
			OCIRetryMaxAttempts:      1,
			OCIRetryMaxWindowSeconds: 5,
			OCIPerHostSlots:          2,
		}
		_, _ = OCIWithConfig(context.Background(), hostPort(t, srv.URL)+"/foo:bar", c)
		if seen := reg.authHeaderSeen.Load(); seen != nil {
			t.Fatalf("unexpected Authorization header when OCIAuth=false: %q", *seen)
		}
	})

	// Auth enabled but no MALCONTENT_REGISTRY_* env → still no docker-config auth.
	t.Run("auth_enabled_no_env_no_auth", func(t *testing.T) {
		t.Setenv(registryUserEnv, "")
		t.Setenv(registryPassEnv, "")
		reg := newHostileRegistry(t, 0)
		srv := httptest.NewServer(reg.handler())
		defer srv.Close()

		c := &malcontent.Config{
			OCIAuth:                  true,
			OCIPullTimeoutSeconds:    5,
			OCIRetryMaxAttempts:      1,
			OCIRetryMaxWindowSeconds: 5,
			OCIPerHostSlots:          2,
		}
		_, _ = OCIWithConfig(context.Background(), hostPort(t, srv.URL)+"/foo:bar", c)
		if seen := reg.authHeaderSeen.Load(); seen != nil {
			t.Fatalf("docker-config ambient auth should be rejected, but saw header %q", *seen)
		}
	})

	// Auth enabled with MALCONTENT_REGISTRY_* env set → Basic auth observed.
	t.Run("auth_enabled_env_basic_auth", func(t *testing.T) {
		t.Setenv(registryUserEnv, "scoped-user")
		t.Setenv(registryPassEnv, "scoped-pass")
		reg := newHostileRegistry(t, 0)
		srv := httptest.NewServer(reg.handler())
		defer srv.Close()

		c := &malcontent.Config{
			OCIAuth:                  true,
			OCIPullTimeoutSeconds:    5,
			OCIRetryMaxAttempts:      1,
			OCIRetryMaxWindowSeconds: 5,
			OCIPerHostSlots:          2,
		}
		_, _ = OCIWithConfig(context.Background(), hostPort(t, srv.URL)+"/foo:bar", c)
		seen := reg.authHeaderSeen.Load()
		if seen == nil {
			t.Fatalf("expected Authorization header when env creds set, saw none")
		}
		if !strings.HasPrefix(*seen, "Basic ") {
			t.Fatalf("expected Basic auth, got %q", *seen)
		}
	})
}
