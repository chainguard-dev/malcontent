// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import "github.com/chainguard-dev/bincapz/pkg/bincapz"

type KV struct {
	key   string
	value *bincapz.FileReport
}
type byKey []KV

func (a byKey) Len() int {
	return len(a)
}
func (a byKey) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a byKey) Less(i, j int) bool {
	return a[i].key < a[j].key
}
