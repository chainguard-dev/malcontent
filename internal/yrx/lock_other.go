// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package yrx

// Other platforms register and deregister rules concurrently without
// trouble, so the calls run at once. lock and unlock are variables, as on
// darwin, so that tests can see the order calls run in.
var lock, unlock = func() {}, func() {}
