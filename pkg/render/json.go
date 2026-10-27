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

	files, err := sanitizedFiles(ctx, rep.Files)
	if err != nil {
		return err
	}
	diff, err := sanitizedDiff(ctx, rep.Diff)
	if err != nil {
		return err
	}

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
	if diff != nil {
		if err := doc.member(head, "Diff", diff); err != nil {
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
	_, err = r.w.Write(tail.Bytes())
	return err
}

// fileEntry is one member of the "Files" object.
type fileEntry struct {
	key string
	// raw is the key before sanitizing.
	raw string
	fr  *malcontent.FileReport
}

// sanitizedFiles returns the reports in files that the "Files" object holds,
// sanitized in place and sorted by key, which is the order json.Marshal gives
// map keys. Keys that are equal once sanitized are made distinct by
// uniqueKeys over the raw keys in sorted order, so every report is kept and
// the keys do not depend on the order of the map. It returns the context's
// error when ctx is canceled before every report is collected.
func sanitizedFiles(ctx context.Context, files *xsync.Map[string, *malcontent.FileReport]) ([]fileEntry, error) {
	if files == nil {
		return nil, nil
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
		entries = append(entries, fileEntry{key: sanitizeUTF8(key), raw: key, fr: fr})
		return true
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	byKey := func(a, b fileEntry) int {
		return cmp.Or(strings.Compare(a.key, b.key), strings.Compare(a.raw, b.raw))
	}
	slices.SortFunc(entries, byKey)
	// Sorting puts keys that are equal once sanitized next to each other.
	collide := false
	for i := 1; i < len(entries) && !collide; i++ {
		collide = entries[i].key == entries[i-1].key
	}
	if !collide {
		return entries, nil
	}
	raw := make([]string, len(entries))
	for i, e := range entries {
		raw[i] = e.raw
	}
	for i, k := range uniqueKeys(raw) {
		entries[i].key = k
	}
	slices.SortFunc(entries, byKey)
	return entries, nil
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
// it with, and with DEL and the C1 controls escaped by escapeJSONControls.
// enc must write to b.
func encodeJSON(enc *json.Encoder, b *bytes.Buffer, v any) error {
	start := b.Len()
	if err := enc.Encode(v); err != nil {
		return err
	}
	b.Truncate(b.Len() - 1)
	escapeJSONControls(b, start)
	return nil
}

// escapeJSONControls rewrites DEL and the C1 controls, U+0080 through U+009F,
// in the JSON text b holds from start as \u007f through \u009f. encoding/json
// writes them raw, and a terminal showing the output may act on them. JSON
// text is ASCII outside its strings and encoding/json writes valid UTF-8, so
// every byte 0x7f and every 0xc2 lead byte followed by 0x80 through 0x9f is a
// character inside a string, and the escape decodes to the same text.
func escapeJSONControls(b *bytes.Buffer, start int) {
	text := b.Bytes()[start:]
	first := len(text)
	if i := bytes.IndexByte(text, 0x7f); i >= 0 {
		first = i
	}
	if i := bytes.IndexByte(text[:first], 0xc2); i >= 0 {
		first = i
	}
	if first == len(text) {
		return
	}

	const hex = "0123456789abcdef"
	escaped := make([]byte, 0, len(text)-first+16)
	for i := first; i < len(text); i++ {
		c := text[i]
		switch {
		case c == 0x7f:
		case c == 0xc2 && i+1 < len(text) && text[i+1] >= 0x80 && text[i+1] <= 0x9f:
			i++
			c = text[i]
		default:
			escaped = append(escaped, c)
			continue
		}
		escaped = append(escaped, '\\', 'u', '0', '0', hex[c>>4], hex[c&0x0f])
	}
	b.Truncate(start + first)
	b.Write(escaped)
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
