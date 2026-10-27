// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"cmp"
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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"golang.org/x/sync/semaphore"
)

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

// ociTempPattern names the temporary directories of an image pull.
const ociTempPattern = "malcontent-oci-*"

// maxOCIIndexDepth bounds how deeply image indexes may nest.
const maxOCIIndexDepth = 4

// ErrInsecureRegistryAuth reports a pull that would have sent registry
// credentials over plain HTTP without Config.OCIAllowInsecureAuth.
var ErrInsecureRegistryAuth = errors.New("refusing to send registry credentials over plain HTTP")

// errImageTooLarge reports an image whose layers decompress to more than
// Config.MaxImageSize bytes.
var errImageTooLarge = errors.New("export size exceeds maximum allowed size")

// ociTransportConfig captures the resolved transport-hardening values used by
// pullImage. pullTimeoutSeconds bounds the wait for each response's headers;
// Config.OCIPullDeadlineSeconds bounds the whole pull.
//
// keepalivePolicy: the zero value (empty string) is treated as an unset policy
// and is silently promoted to malcontent.KeepalivePolicyExplicitlyEnabled with
// keepaliveSeconds = defaultOCIKeepaliveSeconds when keepaliveSeconds is also
// zero. Callers that want the Go stdlib's default transport keepalive behavior
// must set malcontent.Config.OCIKeepalivePolicy to
// malcontent.KeepalivePolicyGoDefault explicitly. A one-shot WARN is emitted
// from resolveOCITransportConfig on the first promotion in a process.
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
// with defaultOCIKeepaliveSeconds. Set malcontent.Config.OCIKeepalivePolicy to
// malcontent.KeepalivePolicyGoDefault to opt into Go's stdlib default transport
// keepalive behavior and suppress the one-shot WARN.
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
			clog.WarnContext(ctx,
				"OCIKeepalivePolicy is unset; defaulting to ExplicitlyEnabled+30s — pass malcontent.KeepalivePolicyGoDefault to suppress this warning",
				"default_seconds", defaultOCIKeepaliveSeconds,
			)
		})
		cfg.keepalivePolicy = malcontent.KeepalivePolicyExplicitlyEnabled
		cfg.keepaliveSeconds = defaultOCIKeepaliveSeconds
	}
	return cfg
}

// registryCredentials returns the trimmed MALCONTENT_REGISTRY_* values.
func registryCredentials() (user, pass, host string) {
	return strings.TrimSpace(os.Getenv(registryUserEnv)),
		strings.TrimSpace(os.Getenv(registryPassEnv)),
		strings.TrimSpace(os.Getenv(registryHostEnv))
}

// normalizeRegistryHost folds the spellings of one registry host together:
// letter case, the default HTTPS port, and Docker Hub's aliases.
func normalizeRegistryHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ":443")
	switch host {
	case "docker.io", name.DefaultRegistry, "registry-1.docker.io":
		return name.DefaultRegistry
	}
	return host
}

// envKeychain resolves Basic auth from MALCONTENT_REGISTRY_USER / MALCONTENT_REGISTRY_PASS,
// scoped to the host in MALCONTENT_REGISTRY_HOST. If the requested resource's
// registry does not match the expected host, Anonymous is returned so that
// private credentials are never leaked to an attacker-controlled registry.
// Both hosts are normalized first, so case, a ":443" suffix, and the Docker
// Hub aliases docker.io, index.docker.io, and registry-1.docker.io do not
// matter.
type envKeychain struct{}

func (envKeychain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	user, pass, host := registryCredentials()
	if user == "" || pass == "" || host == "" {
		return authn.Anonymous, nil
	}
	if normalizeRegistryHost(resource.RegistryStr()) != normalizeRegistryHost(host) {
		return authn.Anonymous, nil
	}
	return &authn.Basic{Username: user, Password: pass}, nil
}

// authMissingWarnOnce gates a single WARN per process when OCI auth is
// requested but the MALCONTENT_REGISTRY_* environment credentials are
// absent or incomplete.
var authMissingWarnOnce sync.Once

// authHostMismatchWarnOnce gates a single WARN per process when OCI auth is
// requested with credentials whose MALCONTENT_REGISTRY_HOST does not match the
// image's registry.
var authHostMismatchWarnOnce sync.Once

// buildScopedKeychain returns a request-scoped keychain. authn.DefaultKeychain is intentionally never returned, so credentials are never resolved from the ambient Docker keychain.
func buildScopedKeychain(ctx context.Context, useAuth bool) authn.Keychain {
	if !useAuth {
		return authn.NewMultiKeychain(authn.Keychain(staticAnonKeychain{}))
	}
	user, pass, _ := registryCredentials()
	if user == "" || pass == "" {
		authMissingWarnOnce.Do(func() {
			clog.WarnContext(ctx,
				"OCI auth requested but MALCONTENT_REGISTRY_USER/MALCONTENT_REGISTRY_PASS are not set; ambient docker credentials are no longer used — proceeding anonymously",
			)
		})
	}
	return authn.NewMultiKeychain(envKeychain{})
}

// warnAuthHostMismatch warns once when OCI auth is requested with credentials
// scoped to a host other than registry, which is then pulled anonymously.
func warnAuthHostMismatch(ctx context.Context, useAuth bool, registry string) {
	user, pass, host := registryCredentials()
	if !useAuth || user == "" || pass == "" || normalizeRegistryHost(host) == normalizeRegistryHost(registry) {
		return
	}
	authHostMismatchWarnOnce.Do(func() {
		clog.WarnContextf(ctx, "MALCONTENT_REGISTRY_HOST %q does not match registry %q; pulling anonymously", host, registry)
	})
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
		pem, err := file.ReadFile(cfg.caBundlePath)
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
	default:
		clog.WarnContextf(context.Background(), "unrecognized OCI keepalive policy %q; using Go default keepalive behavior", cfg.keepalivePolicy)
	}
	if cfg.proxyOptIn {
		t.Proxy = http.ProxyFromEnvironment
	}
	return t, nil
}

// plainHTTPAuthGuard fails every request that would carry credentials over
// plain HTTP. go-containerregistry sets the Authorization header in the
// transports it wraps around this one, so the guard sees each request as sent,
// token requests included.
type plainHTTPAuthGuard struct{ inner http.RoundTripper }

func (g plainHTTPAuthGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" && req.Header.Get("Authorization") != "" {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, fmt.Errorf("%w to %s; serve the registry over HTTPS or pass --oci-allow-insecure-auth", ErrInsecureRegistryAuth, req.URL.Host)
	}
	return g.inner.RoundTrip(req)
}

// sanitizeRefName maps any rune outside [A-Za-z0-9._-] to '-', so that the
// result is safe as one path segment on all platforms.
func sanitizeRefName(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '-'
	}, s)
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

// retryable reports whether a failed registry request may succeed if repeated.
func retryable(err error) bool {
	if errors.Is(err, ErrInsecureRegistryAuth) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var terr *transport.Error
	return !errors.As(err, &terr) || terr.StatusCode < 400 || terr.StatusCode >= 500 ||
		terr.StatusCode == http.StatusTooManyRequests || terr.StatusCode == http.StatusRequestTimeout
}

// withRetry calls fn at most attempts times within windowSeconds, backing off
// exponentially with jitter between transient failures.
func withRetry(ctx context.Context, attempts, windowSeconds int, fn func() error) error {
	deadline := time.Now().Add(time.Duration(windowSeconds) * time.Second)
	var lastErr error
	for i := range attempts {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			break
		}
		err := fn()
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryable(err) {
			return err
		}
		// Exponential backoff with jitter, capped at remaining window.
		backoff := time.Duration(1<<i) * 100 * time.Millisecond
		jitter := time.Duration(rand.Int64N(int64(50 * time.Millisecond))) // #nosec G404 -- non-cryptographic jitter for retry backoff; weak RNG is intentional and adequate
		sleep := min(backoff+jitter, time.Until(deadline))
		if sleep <= 0 {
			break
		}
		timer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	if lastErr == nil {
		lastErr = errors.New("retry budget exhausted")
	}
	return fmt.Errorf("pull retry exhausted (attempts=%d, window=%ds): %w", attempts, windowSeconds, lastErr)
}

// pullWithRetry fetches the manifest or index that ref names, making at most
// attempts requests within windowSeconds. Each attempt authenticates through
// rt itself and hands go-containerregistry the result as a *transport.Wrapper,
// so no retry layer of its own multiplies the attempts.
func pullWithRetry(ctx context.Context, ref name.Reference, rt http.RoundTripper, keychain authn.Keychain, attempts, windowSeconds int) (*remote.Descriptor, error) {
	var desc *remote.Descriptor
	err := withRetry(ctx, attempts, windowSeconds, func() error {
		auth, err := keychain.Resolve(ref.Context())
		if err != nil {
			return err
		}
		tr, err := transport.NewWithContext(ctx, ref.Context().Registry, auth, rt, []string{ref.Scope(transport.PullScope)})
		if err != nil {
			return err
		}
		desc, err = remote.Get(ref, remote.WithContext(ctx), remote.WithTransport(tr))
		return err
	})
	if err != nil {
		return nil, err
	}
	return desc, nil
}

// ociTarget is one image to extract: the image itself, or one platform of an
// index.
type ociTarget struct {
	img      v1.Image
	platform *v1.Platform // nil for a single-manifest image
	segment  string       // subdirectory of the extraction root; empty for the root itself
}

// parsePlatforms parses os/arch[/variant] platform filters.
func parsePlatforms(specs []string) ([]v1.Platform, error) {
	var out []v1.Platform
	for _, s := range specs {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		p, err := v1.ParsePlatform(s)
		if err != nil || p.OS == "" || p.Architecture == "" {
			return nil, fmt.Errorf("invalid platform %q: want os/arch[/variant]", s)
		}
		out = append(out, *p)
	}
	return out, nil
}

// platformSelected reports whether p passes filters. A filter without a
// variant matches every variant.
func platformSelected(p v1.Platform, filters []v1.Platform) bool {
	return len(filters) == 0 || slices.ContainsFunc(filters, func(f v1.Platform) bool {
		return f.OS == p.OS && f.Architecture == p.Architecture && (f.Variant == "" || f.Variant == p.Variant)
	})
}

// platformSegment names the subdirectory a platform is extracted into.
func platformSegment(p v1.Platform) string {
	parts := []string{cmp.Or(p.OS, "unknown"), cmp.Or(p.Architecture, "unknown")}
	if p.Variant != "" {
		parts = append(parts, p.Variant)
	}
	return sanitizeRefName(strings.Join(parts, "-"))
}

// selectImages returns the images to extract from desc: the image itself, or
// the platforms of an index that pass filters. When an index yields more than
// one, each is given its own subdirectory.
func selectImages(desc *remote.Descriptor, filters []v1.Platform, retry func(func() error) error, logger *clog.Logger) ([]ociTarget, error) {
	if !desc.MediaType.IsIndex() {
		img, err := desc.Image()
		if err != nil {
			return nil, fmt.Errorf("read image: %w", err)
		}
		return []ociTarget{{img: img}}, nil
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("read image index: %w", err)
	}
	var targets []ociTarget
	if err := collectIndex(idx, filters, retry, logger, 0, &targets); err != nil {
		return nil, err
	}
	switch len(targets) {
	case 0:
		want := "any known platform"
		if len(filters) > 0 {
			names := make([]string, 0, len(filters))
			for _, f := range filters {
				names = append(names, f.String())
			}
			want = "platforms " + strings.Join(names, ", ")
		}
		return nil, fmt.Errorf("no image in the index matches %s", want)
	case 1:
		return targets, nil
	}
	used := make(map[string]struct{}, len(targets))
	for i := range targets {
		base := platformSegment(*targets[i].platform)
		seg := base
		for n := 2; ; n++ {
			if _, taken := used[seg]; !taken {
				break
			}
			seg = fmt.Sprintf("%s-%d", base, n)
		}
		used[seg] = struct{}{}
		targets[i].segment = seg
	}
	return targets, nil
}

// collectIndex appends to targets the images of idx, and of the indexes it
// nests, that pass filters. Attestations and manifests without a known
// platform are skipped.
func collectIndex(idx v1.ImageIndex, filters []v1.Platform, retry func(func() error) error, logger *clog.Logger, depth int, targets *[]ociTarget) error {
	var im *v1.IndexManifest
	if err := retry(func() (err error) { im, err = idx.IndexManifest(); return err }); err != nil {
		return fmt.Errorf("read image index: %w", err)
	}
	for _, m := range im.Manifests {
		p := m.Platform
		switch {
		case m.MediaType.IsIndex():
			if depth >= maxOCIIndexDepth {
				logger.Warnf("skipping index %s: nested more than %d levels deep", m.Digest, maxOCIIndexDepth)
				continue
			}
			var child v1.ImageIndex
			if err := retry(func() (err error) { child, err = idx.ImageIndex(m.Digest); return err }); err != nil {
				return fmt.Errorf("read image index %s: %w", m.Digest, err)
			}
			if err := collectIndex(child, filters, retry, logger, depth+1, targets); err != nil {
				return err
			}
		case !m.MediaType.IsImage():
			logger.Infof("skipping index manifest %s: %s is not an image", m.Digest, m.MediaType)
		case m.Annotations["vnd.docker.reference.type"] == "attestation-manifest":
			logger.Debugf("skipping attestation manifest %s", m.Digest)
		case p == nil || p.OS == "" || p.OS == "unknown" || p.Architecture == "" || p.Architecture == "unknown":
			logger.Infof("skipping index manifest %s: unknown platform", m.Digest)
		case !platformSelected(*p, filters):
			logger.Debugf("skipping index manifest %s: platform %s is not selected", m.Digest, p)
		default:
			var img v1.Image
			if err := retry(func() (err error) { img, err = idx.Image(m.Digest); return err }); err != nil {
				return fmt.Errorf("read image %s: %w", m.Digest, err)
			}
			*targets = append(*targets, ociTarget{img: img, platform: p})
		}
	}
	return nil
}

// checkImageSize rejects targets whose manifests declare more than
// maxImageSize bytes of layers and configs in total, before any blob is read.
func checkImageSize(targets []ociTarget, maxImageSize int64) error {
	if maxImageSize <= 0 {
		return nil
	}
	tooLarge := fmt.Errorf("image size exceeds maximum allowed size (%d bytes)", maxImageSize)
	var total int64
	for _, tgt := range targets {
		m, err := tgt.img.Manifest()
		if err != nil {
			return fmt.Errorf("failed to read image manifest: %w", err)
		}
		for _, d := range slices.Concat(m.Layers, []v1.Descriptor{m.Config}) {
			if d.Size < 0 || total > maxImageSize-d.Size {
				return tooLarge
			}
			total += d.Size
		}
	}
	return nil
}

// ociBudget counts every byte decompressed from an image's layers, including
// bytes an upper layer deletes and so are never written, against the image
// size limit and the archive byte cap.
type ociBudget struct {
	maxImageSize int64 // <= 0 is unlimited
	total        int64
	archive      *file.ArchiveCounter
}

func newOCIBudget(ctx context.Context, c *malcontent.Config) *ociBudget {
	maxBytes, _ := resolveArchiveCaps(ctx)
	if c.MaxArchiveBytes > 0 {
		maxBytes = c.MaxArchiveBytes
	}
	return &ociBudget{maxImageSize: c.MaxImageSize, archive: &file.ArchiveCounter{MaxBytes: maxBytes}}
}

func (b *ociBudget) add(n int) error {
	b.total += int64(n)
	if b.maxImageSize > 0 && b.total > b.maxImageSize {
		return errImageTooLarge
	}
	return b.archive.Add(n)
}

// ociBudgetReader charges every byte read from r to budget.
type ociBudgetReader struct {
	r      io.Reader
	budget *ociBudget
}

func (br *ociBudgetReader) Read(p []byte) (int, error) {
	n, err := br.r.Read(p)
	if n > 0 {
		if berr := br.budget.add(n); berr != nil {
			return n, berr
		}
	}
	return n, err
}

// OCI returns a directory with the extracted image directories/files in it.
func OCI(ctx context.Context, path string, useAuth bool, maxImageSize int64) (string, error) {
	c := &malcontent.Config{
		OCIAuth:      useAuth,
		MaxImageSize: maxImageSize,
	}
	return OCIWithConfig(ctx, path, c)
}

// OCIWithConfig pulls the image that path names and extracts the filesystem a
// container runtime would assemble from its layers into a new temporary
// directory, which it returns. Each platform of an index that
// Config.OCIPlatforms selects (every known platform by default) is extracted
// into its own subdirectory, named like linux-arm64-v8, unless only one is
// selected. The image config's Env, Entrypoint, and Cmd are written beside
// each image's files as a shell script named malcontent-image-config.sh.
func OCIWithConfig(ctx context.Context, path string, c *malcontent.Config) (string, error) {
	if c == nil {
		c = &malcontent.Config{}
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	filters, err := parsePlatforms(c.OCIPlatforms)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", ociTempPattern)
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	if err := pullImage(ctx, c, path, filters, dir); err != nil {
		_ = file.RemoveAllIn(filepath.Dir(dir), filepath.Base(dir))
		return "", fmt.Errorf("failed to prepare image: %w", err)
	}
	return dir, nil
}

// pullImage pulls the image d and extracts it into dir.
func pullImage(ctx context.Context, c *malcontent.Config, d string, filters []v1.Platform, dir string) error {
	logger := clog.FromContext(ctx).With("image", d)
	logger.Debug("preparing image")
	cfg := resolveOCITransportConfig(ctx, c)
	rt, err := buildTransport(cfg)
	if err != nil {
		return fmt.Errorf("build OCI transport: %w", err)
	}
	ref, err := name.ParseReference(d)
	if err != nil {
		return fmt.Errorf("parse reference: %w", err)
	}
	keychain := buildScopedKeychain(ctx, c.OCIAuth)
	warnAuthHostMismatch(ctx, c.OCIAuth, ref.Context().RegistryStr())
	auth, err := keychain.Resolve(ref.Context())
	if err != nil {
		return fmt.Errorf("resolve registry credentials: %w", err)
	}
	if auth != authn.Anonymous && !c.OCIAllowInsecureAuth {
		rt = plainHTTPAuthGuard{inner: rt}
	}

	sem := getOrCreateHostSemaphore(ref.Context().RegistryStr(), cfg.perHostSlots)
	if err := sem.Acquire(ctx, 1); err != nil {
		return fmt.Errorf("acquire per-host slot: %w", err)
	}
	defer sem.Release(1)

	if c.OCIPullDeadlineSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(c.OCIPullDeadlineSeconds)*time.Second)
		defer cancel()
	}

	desc, err := pullWithRetry(ctx, ref, rt, keychain, cfg.retryAttempts, cfg.retryWindow)
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}
	retry := func(fn func() error) error { return withRetry(ctx, cfg.retryAttempts, cfg.retryWindow, fn) }
	targets, err := selectImages(desc, filters, retry, logger)
	if err != nil {
		return err
	}
	if err := checkImageSize(targets, c.MaxImageSize); err != nil {
		return err
	}

	budget := newOCIBudget(ctx, c)
	buf := extractPool.Get()
	defer extractPool.Put(buf)
	for _, tgt := range targets {
		dest := dir
		tlog := logger
		if tgt.segment != "" {
			dest = filepath.Join(dir, tgt.segment)
			if err := os.Mkdir(dest, 0o700); err != nil {
				return fmt.Errorf("create platform directory: %w", err)
			}
		}
		if tgt.platform != nil {
			tlog = logger.With("platform", tgt.platform.String())
		}
		if err := extractImage(ctx, tgt.img, dest, budget, buf, tlog); err != nil {
			return err
		}
	}
	return nil
}

// extractImage extracts img into dest and writes its config script there.
func extractImage(ctx context.Context, img v1.Image, dest string, budget *ociBudget, buf []byte, logger *clog.Logger) error {
	root, err := os.OpenRoot(dest)
	if err != nil {
		return fmt.Errorf("open extraction directory: %w", err)
	}
	defer root.Close()
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("read image layers: %w", err)
	}
	artifact := false
	if len(layers) == 1 {
		mt, err := layers[0].MediaType()
		if err != nil {
			return fmt.Errorf("read layer media type: %w", err)
		}
		artifact = !mt.IsLayer()
	}
	if artifact {
		if err := extractArtifact(ctx, layers[0], dest, budget, buf); err != nil {
			return err
		}
	} else {
		tree := newOCITree(root, buf, logger)
		for i, layer := range layers {
			if err := applyLayerBlob(ctx, tree, i+1, layer, budget); err != nil {
				return fmt.Errorf("failed to export image: %w", err)
			}
		}
		if err := tree.finish(); err != nil {
			return fmt.Errorf("failed to export image: %w", err)
		}
	}
	return writeConfigScript(img, root, logger)
}

// applyLayerBlob streams layer n from the registry into tree.
func applyLayerBlob(ctx context.Context, tree *ociTree, n int, layer v1.Layer, budget *ociBudget) error {
	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("read layer %d: %w", n, err)
	}
	defer rc.Close()
	return tree.applyLayer(ctx, n, &ociBudgetReader{r: rc, budget: budget})
}

// ociArtifactName names the copy of an artifact blob that extractArtifact
// reads. Its fixed name keeps the image reference from choosing a
// decompressor.
const ociArtifactName = "artifact.tar"

// extractArtifact extracts an image whose only layer is not a filesystem
// layer, such as an artifact. Its blob is read verbatim as a tar, so bytes
// hidden past the end-of-archive marker still reach the trailer audit.
func extractArtifact(ctx context.Context, layer v1.Layer, dest string, budget *ociBudget, buf []byte) error {
	tmp, err := os.MkdirTemp("", ociTempPattern)
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer func() { _ = file.RemoveAllIn(filepath.Dir(tmp), filepath.Base(tmp)) }()
	if err := copyArtifact(layer, tmp, budget, buf); err != nil {
		return fmt.Errorf("failed to export image: %w", err)
	}
	if err := ExtractTar(ctx, dest, filepath.Join(tmp, ociArtifactName)); err != nil {
		return fmt.Errorf("extract image: %w", err)
	}
	return nil
}

// copyArtifact writes the uncompressed blob of layer to ociArtifactName in dir.
func copyArtifact(layer v1.Layer, dir string, budget *ociBudget, buf []byte) error {
	rc, err := layer.Uncompressed()
	if err != nil {
		return err
	}
	defer rc.Close()
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(ociArtifactName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.CopyBuffer(struct{ io.Writer }{f}, &ociBudgetReader{r: rc, budget: budget}, buf)
	return errors.Join(err, f.Close())
}
