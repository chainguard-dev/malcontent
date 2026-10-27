// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/google/go-containerregistry/pkg/registry"
)

func TestNormalizeRegistryHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "docker.io is Docker Hub", in: "docker.io", want: "index.docker.io"},
		{name: "index.docker.io is Docker Hub", in: "index.docker.io", want: "index.docker.io"},
		{name: "registry-1.docker.io is Docker Hub", in: "registry-1.docker.io", want: "index.docker.io"},
		{name: "case is folded", in: "Registry.Example.COM", want: "registry.example.com"},
		{name: "the default HTTPS port is dropped", in: "registry.example.com:443", want: "registry.example.com"},
		{name: "Docker Hub with the default port", in: "Docker.IO:443", want: "index.docker.io"},
		{name: "surrounding whitespace is trimmed", in: " registry.example.com\n", want: "registry.example.com"},
		{name: "other ports are kept", in: "registry.example.com:5000", want: "registry.example.com:5000"},
		{name: "a Docker Hub look-alike is not Docker Hub", in: "docker.io.example.com", want: "docker.io.example.com"},
		{name: "an IPv6 literal keeps its brackets", in: "[::1]:443", want: "[::1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeRegistryHost(tc.in); got != tc.want {
				t.Errorf("normalizeRegistryHost(%q): got = %q, want = %q", tc.in, got, tc.want)
			}
		})
	}
}

// ociAuthRegistry serves an in-process registry and counts the requests that
// carry an Authorization header.
func ociAuthRegistry(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	inner := registry.New(registry.Logger(slog.NewLogLogger(slog.DiscardHandler, slog.LevelInfo)))
	var authed atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.Header.Get("Authorization") != "" {
			authed.Add(1)
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return hostPort(t, srv.URL), &authed
}

// Not parallel: sets process environment and rearms a one-shot warning.
func TestOCIWithConfig_PlainHTTPCredentials(t *testing.T) {
	cases := []struct {
		name          string
		useAuth       bool
		allowInsecure bool
		hostMatches   bool
		wantErr       error
		wantAuthed    bool
	}{
		{name: "credentials over plain HTTP are refused", useAuth: true, hostMatches: true, wantErr: ErrInsecureRegistryAuth},
		{name: "the insecure-auth opt-in sends credentials over plain HTTP", useAuth: true, allowInsecure: true, hostMatches: true, wantAuthed: true},
		{name: "anonymous pulls over plain HTTP are unaffected", useAuth: false, hostMatches: true},
		{name: "credentials scoped to another registry neither block nor leak", useAuth: true, hostMatches: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ociResetOnce(t, &authHostMismatchWarnOnce)
			host, authed := ociAuthRegistry(t)
			ref := host + "/auth:1"
			ociPushImage(t, ref, ociTestImage(t, []ociTestEntry{{name: "ok.txt", body: "ok"}}))
			t.Setenv(registryUserEnv, "user")
			t.Setenv(registryPassEnv, "secret")
			t.Setenv(registryHostEnv, map[bool]string{true: host, false: "registry.example.com"}[tc.hostMatches])
			authed.Store(0)

			c := ociTestConfig(0)
			c.OCIAuth = tc.useAuth
			c.OCIAllowInsecureAuth = tc.allowInsecure
			dir, err := OCIWithConfig(t.Context(), ref, c)
			removeOCIDir(t, dir)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error: got = %v, want wrapping %v", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("OCIWithConfig: %v", err)
			}
			if got := authed.Load() > 0; got != tc.wantAuthed {
				t.Errorf("credentials reached the registry: got = %v, want = %v", got, tc.wantAuthed)
			}
		})
	}
}

// Not parallel: sets process environment and rearms a one-shot warning.
func TestOCIWithConfig_AuthHostMismatchWarnsOnce(t *testing.T) {
	const warning = "does not match registry"
	cases := []struct {
		name    string
		useAuth bool
		host    func(registryHost string) string
		pulls   int
		want    int
	}{
		{name: "a mismatched host warns once across pulls", useAuth: true, host: func(string) string { return "registry.example.com" }, pulls: 2, want: 1},
		{name: "an unset host warns", useAuth: true, host: func(string) string { return "" }, pulls: 1, want: 1},
		{name: "a matching host does not warn", useAuth: true, host: strings.TrimSpace, pulls: 1, want: 0},
		{name: "anonymous pulls do not warn", useAuth: false, host: func(string) string { return "registry.example.com" }, pulls: 1, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ociResetOnce(t, &authHostMismatchWarnOnce)
			host, _ := ociAuthRegistry(t)
			ref := host + "/warn:1"
			ociPushImage(t, ref, ociTestImage(t, []ociTestEntry{{name: "ok.txt", body: "ok"}}))
			t.Setenv(registryUserEnv, "user")
			t.Setenv(registryPassEnv, "secret")
			t.Setenv(registryHostEnv, tc.host(host))
			rec := &ociWarnRecorder{}
			ctx := clog.WithLogger(t.Context(), clog.New(rec))
			c := ociTestConfig(0)
			c.OCIAuth = tc.useAuth
			c.OCIAllowInsecureAuth = true
			for range tc.pulls {
				dir, err := OCIWithConfig(ctx, ref, c)
				removeOCIDir(t, dir)
				if err != nil {
					t.Fatalf("OCIWithConfig: %v", err)
				}
			}
			if got := rec.count(warning); got != tc.want {
				t.Errorf("host-mismatch warnings: got = %d, want = %d", got, tc.want)
			}
		})
	}
}
