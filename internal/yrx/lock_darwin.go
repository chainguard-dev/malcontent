// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package yrx

import "sync"

// mu runs the calls that register or deregister rules one at a time.
var mu sync.Mutex

// lock and unlock take and release mu. They are variables so that tests can
// see the order calls run in.
var lock, unlock = mu.Lock, mu.Unlock
