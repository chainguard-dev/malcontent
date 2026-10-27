// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package thirdparty embeds the third-party YARA rule feeds under yara/, with
// their licenses and notices, as FS. The feeds are refreshed by
// yara/update.sh, and malcontent compiles them only when third-party rules
// are requested.
package thirdparty
