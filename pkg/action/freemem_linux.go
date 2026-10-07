// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux && cgo

package action

/*
#include <features.h>
#ifdef __GLIBC__
#include <malloc.h>
static void mal_release_free_memory(void) { malloc_trim(0); }
#else
static void mal_release_free_memory(void) {}
#endif
*/
import "C"

// releaseFreeMemory returns memory that the C allocator holds free to the
// operating system. glibc keeps memory freed in small blocks for reuse, so
// the gigabytes a large scan frees would otherwise stay resident.
func releaseFreeMemory() { C.mal_release_free_memory() }
