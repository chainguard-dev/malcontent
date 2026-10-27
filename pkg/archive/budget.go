// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// entryCost is what each entry an extraction writes costs against the byte
// cap besides its content: about the filesystem block and inode an entry
// occupies even when empty. Charging it bounds an archive of empty entries,
// whose content alone would never reach the cap, to MaxArchiveBytes/4096
// entries, about eight million at the default cap, while the 100,000 files of
// a large source tree cost 400 MB of a 32 GiB cap.
const entryCost = 4 << 10

// treeBudgetKey keys the byte counter a nested tree shares in a context.
type treeBudgetKey struct{}

// withTreeBudget returns ctx carrying tree, the counter every extraction in
// one nested tree charges.
func withTreeBudget(ctx context.Context, tree *file.ArchiveCounter) context.Context {
	return context.WithValue(ctx, treeBudgetKey{}, tree)
}

// newTreeCounter returns the counter of a nested tree, capped at the
// configured MaxArchiveBytes. It applies no ratio cap; each archive in the
// tree applies its own.
func newTreeCounter(ctx context.Context, c *malcontent.Config) *file.ArchiveCounter {
	maxBytes, _ := resolveArchiveCaps(ctx)
	if c != nil && c.MaxArchiveBytes > 0 {
		maxBytes = c.MaxArchiveBytes
	}
	return &file.ArchiveCounter{MaxBytes: maxBytes}
}

// budget charges what one extraction writes against two caps: the expansion
// ratio of the archive being extracted, measured against its own size, and
// the byte cap shared by every archive in its nested tree, so that archives
// nested inside archives cannot multiply what one scanned file writes. A nil
// budget charges nothing.
type budget struct {
	archive *file.ArchiveCounter
	tree    *file.ArchiveCounter
}

// newArchiveCounter returns the budget of an archive of inputBytes bytes,
// charging the tree counter ctx carries, or a counter of its own when ctx
// carries none, as when an extractor is called directly. Caps prefer the
// ctx-attached Config; absent or zero values fall back to the package
// defaults, so zero-config callers still receive finite caps.
func newArchiveCounter(ctx context.Context, inputBytes int64) *budget {
	_, maxRatio := resolveArchiveCaps(ctx)
	tree, ok := ctx.Value(treeBudgetKey{}).(*file.ArchiveCounter)
	if !ok || tree == nil {
		tree = newTreeCounter(ctx, nil)
	}
	return &budget{
		archive: &file.ArchiveCounter{MaxRatio: maxRatio, InputBytes: inputBytes},
		tree:    tree,
	}
}

// Add charges n bytes of content.
func (b *budget) Add(n int) error {
	if b == nil {
		return nil
	}
	if err := b.tree.Add(n); err != nil {
		return err
	}
	return b.archive.Add(n)
}

// Entry charges the fixed cost of one entry.
func (b *budget) Entry() error {
	if b == nil {
		return nil
	}
	return b.tree.Add(entryCost)
}

// Remaining returns how many more bytes the byte cap accepts.
func (b *budget) Remaining() int64 {
	if b == nil {
		return (*file.ArchiveCounter)(nil).Remaining()
	}
	return b.tree.Remaining()
}

// Available returns how many more bytes Add accepts before either cap fails
// it.
func (b *budget) Available() int64 {
	if b == nil {
		return (*file.ArchiveCounter)(nil).Available()
	}
	return min(b.tree.Available(), b.archive.Available())
}
