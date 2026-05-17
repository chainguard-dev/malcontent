// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package thirdparty

import "embed"

// SHA256SUMS manifests are excluded: their filename column lists
// upstream-rule paths like `Macos_Infostealer_Atomic.yar` which XProtect
// signature-matches on macOS, killing any process whose binary embeds them.
// The manifests participate in the on-disk integrity workflow run by
// third_party/yara/update.sh and are not consumed at runtime.
//
//go:embed yara/*/*.yar yara/*/*.yara yara/*/*/*.yar yara/*/*/*.yara yara/*/RELEASE yara/*/LICENSE* yara/*/README*
var FS embed.FS
