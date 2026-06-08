// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"golang.org/x/sync/semaphore"
)

// limitedWriter wraps a writer and returns an error if the total bytes written exceeds a limit.
type limitedWriter struct {
	w         io.Writer
	remaining int64
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > lw.remaining {
		return 0, fmt.Errorf("export size exceeds maximum allowed size")
	}
	lw.remaining -= int64(len(p))
	return lw.w.Write(p)
}

// Default values applied when the corresponding Config field is zero-valued. These keep the OCI transport hardened (bounded timeouts, retries, and keepalive) by default.
const (
	defaultOCIPullTimeoutSeconds    = 600
	defaultOCIRetryMaxAttempts      = 3
	defaultOCIRetryMaxWindowSeconds = 60
	defaultOCIPerHostSlots          = 4
	defaultOCIKeepaliveSeconds      = 30
)

// Environment variables consulted for the request-scoped keychain. The DefaultKeychain (ambient ~/.docker/config.json) is intentionally avoided.
const (
	registryUserEnv = "MALCONTENT_REGISTRY_USER"
	registryPassEnv = "MALCONTENT_REGISTRY_PASS"
	registryHostEnv = "MALCONTENT_REGISTRY_HOST"
)

// ociTransportConfig captures the resolved transport-hardening values used by prepareImage.
//
// keepalivePolicy: the zero value (empty string) is treated as an unset policy
// and is silently promoted to malcontent.KeepalivePolicyExplicitlyEnabled with
// keepaliveSeconds = defaultOCIKeepaliveSeconds when keepaliveSeconds is also
// zero. Callers that want the Go stdlib's default transport keepalive behavior
// must set malcontent.Config.OCIKeepalivePolicy to
// malcontent.KeepalivePolicyGoDefault explicitly (constructible via
// malcontent.WithOCIKeepalivePolicy). A one-shot WARN is emitted from
// resolveOCITransportConfig on the first promotion in a process.
type ociTransportConfig struct {
	pullTimeoutSeconds int
	retryAttempts      int
	retryWindow        int
	perHostSlots       int
	keepalivePolicy    malcontent.KeepalivePolicy
	keepaliveSeconds   int
	proxyOptIn         bool
	caBundlePath       string
}

// keepaliveUnsetWarnOnce gates a single WARN per process when callers leave
// OCIKeepalivePolicy at its zero value and trigger the silent promotion to
// KeepalivePolicyExplicitlyEnabled with the 30s default.
var keepaliveUnsetWarnOnce sync.Once

// resolveOCITransportConfig folds zero-valued Config fields into safe defaults.
//
// Note on keepalive: when both OCIKeepalivePolicy and OCIKeepaliveSeconds are
// zero, the policy is silently promoted to KeepalivePolicyExplicitlyEnabled
// with defaultOCIKeepaliveSeconds. Pass malcontent.KeepalivePolicyGoDefault
// via malcontent.WithOCIKeepalivePolicy to opt into Go's stdlib default
// transport keepalive behavior and suppress the one-shot WARN.
func resolveOCITransportConfig(ctx context.Context, c *malcontent.Config) ociTransportConfig {
	cfg := ociTransportConfig{
		pullTimeoutSeconds: c.OCIPullTimeoutSeconds,
		retryAttempts:      c.OCIRetryMaxAttempts,
		retryWindow:        c.OCIRetryMaxWindowSeconds,
		perHostSlots:       c.OCIPerHostSlots,
		keepalivePolicy:    c.OCIKeepalivePolicy,
		keepaliveSeconds:   c.OCIKeepaliveSeconds,
		proxyOptIn:         c.OCIProxyOptIn,
		caBundlePath:       c.OCICABundlePath,
	}
	if cfg.pullTimeoutSeconds <= 0 {
		cfg.pullTimeoutSeconds = defaultOCIPullTimeoutSeconds
	}
	if cfg.retryAttempts <= 0 {
		cfg.retryAttempts = defaultOCIRetryMaxAttempts
	}
	if cfg.retryWindow <= 0 {
		cfg.retryWindow = defaultOCIRetryMaxWindowSeconds
	}
	if cfg.perHostSlots <= 0 {
		cfg.perHostSlots = defaultOCIPerHostSlots
	}
	// Callers that leave both fields zero fall through to a bounded idle-conn
	// timeout so the transport never has unbounded keepalive defaults. Emit a
	// one-shot WARN so the implicit promotion is observable; pass
	// malcontent.KeepalivePolicyGoDefault explicitly to suppress this.
	if cfg.keepalivePolicy == "" && cfg.keepaliveSeconds == 0 {
		keepaliveUnsetWarnOnce.Do(func() {
			clog.FromContext(ctx).Warn(
				"OCIKeepalivePolicy is unset; defaulting to ExplicitlyEnabled+30s — pass malcontent.KeepalivePolicyGoDefault to suppress this warning",
				"default_seconds", defaultOCIKeepaliveSeconds,
			)
		})
		cfg.keepalivePolicy = malcontent.KeepalivePolicyExplicitlyEnabled
		cfg.keepaliveSeconds = defaultOCIKeepaliveSeconds
	}
	return cfg
}

// envKeychain resolves Basic auth from MALCONTENT_REGISTRY_USER / MALCONTENT_REGISTRY_PASS,
// scoped to the host in MALCONTENT_REGISTRY_HOST. If the requested resource's
// registry does not match the expected host, Anonymous is returned so that
// private credentials are never leaked to an attacker-controlled registry.
// The match is against authn.Resource.RegistryStr(), which go-containerregistry
// normalizes (e.g. Docker Hub resolves to "index.docker.io"), so
// MALCONTENT_REGISTRY_HOST must be set to that normalized host.
type envKeychain struct{}

func (envKeychain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	user := strings.TrimSpace(os.Getenv(registryUserEnv))
	pass := strings.TrimSpace(os.Getenv(registryPassEnv))
	if user == "" || pass == "" {
		return authn.Anonymous, nil
	}
	expectedHost := strings.TrimSpace(os.Getenv(registryHostEnv))
	if expectedHost == "" {
		return authn.Anonymous, nil
	}
	if resource.RegistryStr() != expectedHost {
		return authn.Anonymous, nil
	}
	return &authn.Basic{Username: user, Password: pass}, nil
}

// buildScopedKeychain returns a request-scoped keychain. authn.DefaultKeychain is intentionally never returned, so credentials are never resolved from the ambient Docker keychain.
func buildScopedKeychain(useAuth bool) authn.Keychain {
	if !useAuth {
		return authn.NewMultiKeychain(authn.Keychain(staticAnonKeychain{}))
	}
	return authn.NewMultiKeychain(envKeychain{})
}

// staticAnonKeychain returns Anonymous for every Resource, never reading ambient state.
type staticAnonKeychain struct{}

func (staticAnonKeychain) Resolve(_ authn.Resource) (authn.Authenticator, error) {
	return authn.Anonymous, nil
}

// buildTransport assembles the hardened OCI transport settings into a single *http.Transport.
func buildTransport(cfg ociTransportConfig) (http.RoundTripper, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch cfg.caBundlePath {
	case "", "system":
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system CA pool: %w", err)
		}
		tlsCfg.RootCAs = pool
	default:
		if !filepath.IsAbs(cfg.caBundlePath) {
			return nil, fmt.Errorf("--ca-bundle path must be absolute, got %q", cfg.caBundlePath)
		}
		pem, err := os.ReadFile(cfg.caBundlePath)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle %s: %w", cfg.caBundlePath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates parsed from %s", cfg.caBundlePath)
		}
		tlsCfg.RootCAs = pool
	}
	t := &http.Transport{
		TLSClientConfig:       tlsCfg,
		MaxIdleConns:          100,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(cfg.pullTimeoutSeconds) * time.Second,
	}
	switch cfg.keepalivePolicy {
	case malcontent.KeepalivePolicyExplicitlyDisabled:
		t.DisableKeepAlives = true
	case malcontent.KeepalivePolicyExplicitlyEnabled:
		secs := cfg.keepaliveSeconds
		if secs <= 0 {
			secs = defaultOCIKeepaliveSeconds
		}
		t.IdleConnTimeout = time.Duration(secs) * time.Second
	case malcontent.KeepalivePolicyGoDefault, "":
		// Leave transport keepalive at the Go default.
	}
	if cfg.proxyOptIn {
		t.Proxy = http.ProxyFromEnvironment
	}
	return t, nil
}

// hostSemaphores tracks per-registry-hostname concurrency caps, keyed by RegistryStr().
var hostSemaphores sync.Map

// getOrCreateHostSemaphore lazily creates a per-hostname weighted semaphore.
func getOrCreateHostSemaphore(host string, slots int) *semaphore.Weighted {
	if slots <= 0 {
		slots = defaultOCIPerHostSlots
	}
	if v, ok := hostSemaphores.Load(host); ok {
		if s, ok := v.(*semaphore.Weighted); ok {
			return s
		}
	}
	sem := semaphore.NewWeighted(int64(slots))
	actual, _ := hostSemaphores.LoadOrStore(host, sem)
	if s, ok := actual.(*semaphore.Weighted); ok {
		return s
	}
	return sem
}

// pullWithRetry performs a bounded retry around remote.Image.
func pullWithRetry(ctx context.Context, ref name.Reference, rt http.RoundTripper, keychain authn.Keychain, attempts, windowSeconds int) (v1.Image, error) {
	deadline := time.Now().Add(time.Duration(windowSeconds) * time.Second)
	var lastErr error
	for i := range attempts {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Now().After(deadline) {
			break
		}
		img, err := remote.Image(
			ref,
			remote.WithContext(ctx),
			remote.WithTransport(rt),
			remote.WithAuthFromKeychain(keychain),
		)
		if err == nil {
			_, err = img.Manifest()
			if err == nil {
				return img, nil
			}
		}
		lastErr = err
		var terr *transport.Error
		if errors.As(err, &terr) && terr.StatusCode >= 400 && terr.StatusCode < 500 &&
			terr.StatusCode != http.StatusTooManyRequests &&
			terr.StatusCode != http.StatusRequestTimeout {
			return nil, err
		}
		// Exponential backoff with jitter, capped at remaining window.
		backoff := time.Duration(1<<i) * 100 * time.Millisecond
		jitter := time.Duration(rand.Int64N(int64(50 * time.Millisecond))) // #nosec G404 -- non-cryptographic jitter for retry backoff; weak RNG is intentional and adequate
		sleep := backoff + jitter
		if remaining := time.Until(deadline); sleep > remaining {
			sleep = remaining
		}
		if sleep <= 0 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("retry budget exhausted")
	}
	return nil, fmt.Errorf("pull retry exhausted (attempts=%d, window=%ds): %w", attempts, windowSeconds, lastErr)
}

func prepareImage(ctx context.Context, c *malcontent.Config, d string) (string, *os.File, error) {
	if ctx.Err() != nil {
		return "", nil, ctx.Err()
	}

	logger := clog.FromContext(ctx).With("image", d)
	logger.Debug("preparing image")
	tmpDir, err := os.MkdirTemp("", filepath.Base(d))
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	tmpFile, err := os.CreateTemp(tmpDir, fmt.Sprintf("%s.tar", filepath.Base(d)))
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	// On any error return the caller never receives tmpFile, so its descriptor
	// must be closed here. The success-path caller owns the close otherwise; the
	// success guard prevents a double-close.
	defer func() {
		if !success {
			_ = tmpFile.Close()
		}
	}()

	useAuth := c.OCIAuth
	maxImageSize := c.MaxImageSize

	cfg := resolveOCITransportConfig(ctx, c)

	keychain := buildScopedKeychain(useAuth)
	rt, err := buildTransport(cfg)
	if err != nil {
		return "", nil, fmt.Errorf("build OCI transport: %w", err)
	}

	ref, err := name.ParseReference(d)
	if err != nil {
		return "", nil, fmt.Errorf("parse reference: %w", err)
	}

	sem := getOrCreateHostSemaphore(ref.Context().RegistryStr(), cfg.perHostSlots)
	if err := sem.Acquire(ctx, 1); err != nil {
		return "", nil, fmt.Errorf("acquire per-host slot: %w", err)
	}
	defer sem.Release(1)

	// Bound the entire pull in a derived context so it always has a deadline.
	pullCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.pullTimeoutSeconds)*time.Second)
	defer cancel()

	image, err := pullWithRetry(pullCtx, ref, rt, keychain, cfg.retryAttempts, cfg.retryWindow)
	if err != nil {
		return "", nil, fmt.Errorf("failed to pull image: %w", err)
	}

	// Preflight manifest size check before any layer is exported.
	if maxImageSize > 0 {
		manifest, err := image.Manifest()
		if err != nil {
			return "", nil, fmt.Errorf("failed to read image manifest: %w", err)
		}
		var totalSize int64
		for _, layer := range manifest.Layers {
			if layer.Size < 0 || totalSize > maxImageSize-layer.Size {
				return "", nil, fmt.Errorf("image size exceeds maximum allowed size (%d bytes)", maxImageSize)
			}
			totalSize += layer.Size
		}
		if manifest.Config.Size < 0 || totalSize > maxImageSize-manifest.Config.Size {
			return "", nil, fmt.Errorf("image size exceeds maximum allowed size (%d bytes)", maxImageSize)
		}
		totalSize += manifest.Config.Size
		if totalSize > maxImageSize {
			return "", nil, fmt.Errorf("image size (%d bytes) exceeds maximum allowed size (%d bytes)", totalSize, maxImageSize)
		}
	}

	// Counting-writer abort as a secondary defense if the manifest understated the image size.
	var exportWriter io.Writer = tmpFile
	if maxImageSize > 0 {
		exportWriter = &limitedWriter{w: tmpFile, remaining: maxImageSize}
	}
	if err := crane.Export(image, exportWriter); err != nil {
		return "", nil, fmt.Errorf("failed to export image: %w", err)
	}
	_, err = tmpFile.Seek(0, io.SeekStart)
	if err != nil {
		return "", nil, fmt.Errorf("failed to seek to start of temp file: %w", err)
	}

	success = true
	return tmpDir, tmpFile, nil
}

// OCI returns a directory with the extracted image directories/files in it.
func OCI(ctx context.Context, path string, useAuth bool, maxImageSize int64) (string, error) {
	c := &malcontent.Config{
		OCIAuth:      useAuth,
		MaxImageSize: maxImageSize,
	}
	return OCIWithConfig(ctx, path, c)
}

// OCIWithConfig accepts a fully-populated Config for OCI transport-hardening knobs.
func OCIWithConfig(ctx context.Context, path string, c *malcontent.Config) (string, error) {
	if c == nil {
		c = &malcontent.Config{}
	}
	tmpDir, tmpFile, err := prepareImage(ctx, c, path)
	if err != nil {
		return "", fmt.Errorf("failed to prepare image: %w", err)
	}
	defer tmpFile.Close()

	if err := ExtractTar(ctx, tmpDir, tmpFile.Name()); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("extract image: %w", err)
	}
	// remove the temporary tarball after we extract it
	// otherwise we scan the tarball
	// in addition to its contents which produces odd results
	defer os.Remove(tmpFile.Name())

	return tmpDir, nil
}
