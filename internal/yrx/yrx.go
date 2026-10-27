// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package yrx builds, loads, and destroys YARA-X rules without letting those
// calls run at once where the platform cannot take it.
//
// YARA-X compiles rules to WebAssembly with wasmtime, which registers the
// unwind information of every module it compiles or loads with the system
// unwinder and deregisters it when the rules are destroyed. On macOS, those
// calls write-lock the global cache of libunwind, and under many concurrent
// registrations and deregistrations every caller can end up waiting for a
// lock that no thread holds, so the process stops making progress. Every
// call that registers or deregisters rules goes through this package, which
// runs them one at a time there.
package yrx

import (
	"io"
	"runtime"

	yarax "github.com/VirusTotal/yara-x/go"
)

// The YARA-X calls that register or deregister compiled code. They are
// variables so that tests can see the order calls run in.
var (
	build    = (*yarax.Compiler).Build
	readFrom = yarax.ReadFrom
	destroy  = (*yarax.Rules).Destroy
)

// Build builds the rules c holds, as c.Build does. The rules are destroyed
// through Destroy when the garbage collector frees them.
func Build(c *yarax.Compiler) *yarax.Rules {
	lock()
	r := build(c)
	unlock()
	// The binding destroys rules it frees directly; destroy them here instead.
	runtime.SetFinalizer(r, nil)
	runtime.SetFinalizer(r, Destroy)
	return r
}

// Compile compiles src, as yarax.Compile does.
func Compile(src string, opts ...yarax.CompileOption) (*yarax.Rules, error) {
	c, err := yarax.NewCompiler(opts...)
	if err != nil {
		return nil, err
	}
	defer c.Destroy()
	if err := c.AddSource(src); err != nil {
		return nil, err
	}
	return Build(c), nil
}

// ReadFrom reads compiled rules from rd, as yarax.ReadFrom does.
func ReadFrom(rd io.Reader) (*yarax.Rules, error) {
	lock()
	defer unlock()
	return readFrom(rd)
}

// Destroy destroys r, as r.Destroy does. It is safe to call on nil.
func Destroy(r *yarax.Rules) {
	if r == nil {
		return
	}
	lock()
	defer unlock()
	destroy(r)
}
