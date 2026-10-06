// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"io"
	"runtime"
	"slices"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/puzpuzpuz/xsync/v4"
)

const (
	// jsonIndent is one level of indentation in JSON output.
	jsonIndent = "    "
	// jsonFileIndent starts each member of the "Files" object, two levels deep.
	jsonFileIndent = jsonIndent + jsonIndent
	// jsonFilesPerChunk is how many file reports one goroutine encodes before
	// they are written.
	jsonFilesPerChunk = 32
)

// JSON writes the report as one indented JSON document: the bytes of
// json.MarshalIndent(Report, "", "    ") and a newline. It encodes file
// reports in parallel and streams them in key order instead of building the
// whole document in memory first.
type JSON struct {
	w io.Writer
}

func NewJSON(w io.Writer) JSON {
	return JSON{w: w}
}

func (r JSON) Name() string { return "JSON" }

func (r JSON) Scanning(_ context.Context, _ string) {}

func (r JSON) File(_ context.Context, _ *malcontent.FileReport) error {
	return nil
}

func (r JSON) Full(ctx context.Context, c *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// guard against nil reports
	if rep == nil {
		return nil
	}

	files := sanitizedFiles(ctx, rep.Files)

	var stats *Stats
	if c != nil && c.Stats && rep.Diff == nil {
		stats = serializedStats(c, rep)
	}

	// The document is a Report: its Diff, Files, and Stats members in field
	// order, each omitted when empty; Filter is always empty. Everything but
	// the file reports is encoded before anything is written, so a failure
	// there writes nothing.
	head, tail := getBuffer(), getBuffer()
	defer putBuffer(head)
	defer putBuffer(tail)

	var doc jsonObject
	head.WriteByte('{')
	if rep.Diff != nil {
		if err := doc.member(head, "Diff", rep.Diff); err != nil {
			return err
		}
	}
	if len(files) > 0 {
		doc.key(head, "Files")
		head.WriteByte('{')
		tail.WriteString("\n" + jsonIndent + "}")
	}
	if stats != nil {
		if err := doc.member(tail, "Stats", stats); err != nil {
			return err
		}
	}
	doc.end(tail)

	if _, err := r.w.Write(head.Bytes()); err != nil {
		return err
	}
	if err := writeJSONFiles(r.w, files); err != nil {
		return err
	}
	_, err := r.w.Write(tail.Bytes())
	return err
}

// fileEntry is one member of the "Files" object.
type fileEntry struct {
	key string
	fr  *malcontent.FileReport
	// order is the position of the report in Range order.
	order int
}

// sanitizedFiles returns the reports in files that the "Files" object holds,
// sanitized in place and sorted by key, which is the order json.Marshal gives
// map keys. Reports whose keys are equal once sanitized keep only the one
// ranged over last, as storing them in a map would.
func sanitizedFiles(ctx context.Context, files *xsync.Map[string, *malcontent.FileReport]) []fileEntry {
	if files == nil {
		return nil
	}

	entries := make([]fileEntry, 0, files.Size())
	files.Range(func(key string, fr *malcontent.FileReport) bool {
		if ctx.Err() != nil {
			return false
		}
		if fr == nil || fr.Skipped != "" {
			return true
		}
		sanitizeReport(fr)
		entries = append(entries, fileEntry{key: sanitizeUTF8(key), fr: fr, order: len(entries)})
		return true
	})

	slices.SortFunc(entries, func(a, b fileEntry) int {
		return cmp.Or(strings.Compare(a.key, b.key), cmp.Compare(a.order, b.order))
	})
	kept := entries[:0]
	for i, e := range entries {
		if i+1 < len(entries) && entries[i+1].key == e.key {
			continue
		}
		kept = append(kept, e)
	}
	clear(entries[len(kept):])
	return kept
}

// jsonChunk holds consecutive members of the "Files" object, encoded.
type jsonChunk struct {
	buf *bytes.Buffer
	err error
}

// writeJSONFiles writes the members of the "Files" object in key order.
// Chunks of reports are encoded in parallel, and each chunk is written as
// soon as it and every chunk before it are done, so memory holds a few
// chunks per CPU rather than the whole document.
func writeJSONFiles(w io.Writer, files []fileEntry) error {
	if len(files) == 0 {
		return nil
	}

	if len(files) <= jsonFilesPerChunk {
		b := getBuffer()
		defer putBuffer(b)
		if err := encodeJSONFiles(b, files, true); err != nil {
			return err
		}
		_, err := w.Write(b.Bytes())
		return err
	}

	// pending carries each chunk's result channel in chunk order. Its capacity
	// bounds how far encoding runs ahead of writing.
	pending := make(chan chan jsonChunk, 2*runtime.GOMAXPROCS(0))
	go func() {
		defer close(pending)
		for start := 0; start < len(files); start += jsonFilesPerChunk {
			done := make(chan jsonChunk, 1)
			pending <- done
			go func() {
				b := getBuffer()
				part := files[start:min(start+jsonFilesPerChunk, len(files))]
				done <- jsonChunk{buf: b, err: encodeJSONFiles(b, part, start == 0)}
			}()
		}
	}()

	// Receive every chunk, even after a failure, so no goroutine is left
	// blocked.
	var err error
	for done := range pending {
		c := <-done
		if err == nil {
			err = c.err
		}
		if err == nil {
			_, err = w.Write(c.buf.Bytes())
		}
		putBuffer(c.buf)
	}
	return err
}

// encodeJSONFiles appends files to b as members of the "Files" object, with
// the separators and indentation json.MarshalIndent gives them inside the
// whole report. first reports whether files starts the object.
func encodeJSONFiles(b *bytes.Buffer, files []fileEntry, first bool) error {
	enc := json.NewEncoder(b)
	enc.SetIndent(jsonFileIndent, jsonIndent)
	for i, f := range files {
		if i > 0 || !first {
			b.WriteByte(',')
		}
		b.WriteString("\n" + jsonFileIndent)
		if err := encodeJSON(enc, b, f.key); err != nil {
			return err
		}
		b.WriteString(": ")
		if err := encodeJSON(enc, b, f.fr); err != nil {
			return err
		}
	}
	return nil
}

// encodeJSON appends v to b, encoded by enc, without the newline Encode ends
// it with. enc must write to b.
func encodeJSON(enc *json.Encoder, b *bytes.Buffer, v any) error {
	if err := enc.Encode(v); err != nil {
		return err
	}
	b.Truncate(b.Len() - 1)
	return nil
}

// jsonObject writes members of the top-level object with the separators and
// indentation json.MarshalIndent(report, "", jsonIndent) gives them.
type jsonObject struct {
	members int
}

// key starts a member named name.
func (o *jsonObject) key(b *bytes.Buffer, name string) {
	if o.members > 0 {
		b.WriteByte(',')
	}
	o.members++
	b.WriteString("\n" + jsonIndent + `"`)
	b.WriteString(name)
	b.WriteString(`": `)
}

// member writes a member named name whose value is v.
func (o *jsonObject) member(b *bytes.Buffer, name string, v any) error {
	o.key(b, name)
	enc := json.NewEncoder(b)
	enc.SetIndent(jsonIndent, jsonIndent)
	return encodeJSON(enc, b, v)
}

// end closes the object and ends the document with a newline.
func (o *jsonObject) end(b *bytes.Buffer) {
	if o.members > 0 {
		b.WriteByte('\n')
	}
	b.WriteString("}\n")
}
