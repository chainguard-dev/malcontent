// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package malcontent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"go.yaml.in/yaml/v3"
)

// OrderedFileReports maps keys to file reports in the order the keys were
// first set, and encodes as a JSON object or YAML mapping in that order. Its
// zero value is empty and ready to use. Reading a nil map finds nothing.
type OrderedFileReports struct {
	index          map[string]*FileReportEntry
	oldest, newest *FileReportEntry
}

// FileReportEntry is one key and report of an OrderedFileReports.
type FileReportEntry struct {
	Key   string
	Value *FileReport

	prev, next *FileReportEntry
}

// Next returns the entry set after e, or nil.
func (e *FileReportEntry) Next() *FileReportEntry {
	return e.next
}

// Len returns the number of entries in m.
func (m *OrderedFileReports) Len() int {
	if m == nil {
		return 0
	}
	return len(m.index)
}

// Oldest returns the first entry of m, or nil.
func (m *OrderedFileReports) Oldest() *FileReportEntry {
	if m == nil {
		return nil
	}
	return m.oldest
}

// Get returns the report for key and whether m holds key.
func (m *OrderedFileReports) Get(key string) (*FileReport, bool) {
	if m == nil {
		return nil, false
	}
	e, ok := m.index[key]
	if !ok {
		return nil, false
	}
	return e.Value, true
}

// Set stores fr under key. A new key goes last; a key m holds keeps its place.
func (m *OrderedFileReports) Set(key string, fr *FileReport) {
	if e, ok := m.index[key]; ok {
		e.Value = fr
		return
	}
	if m.index == nil {
		m.index = make(map[string]*FileReportEntry)
	}
	e := &FileReportEntry{Key: key, Value: fr, prev: m.newest}
	if m.newest == nil {
		m.oldest = e
	} else {
		m.newest.next = e
	}
	m.newest = e
	m.index[key] = e
}

// Delete removes key from m.
func (m *OrderedFileReports) Delete(key string) {
	if m == nil {
		return
	}
	e, ok := m.index[key]
	if !ok {
		return
	}
	delete(m.index, key)
	if e.prev == nil {
		m.oldest = e.next
	} else {
		e.prev.next = e.next
	}
	if e.next == nil {
		m.newest = e.prev
	} else {
		e.next.prev = e.prev
	}
	e.prev, e.next = nil, nil
}

// MarshalJSON writes m as a JSON object in order. Keys and reports encode as
// encoding/json encodes them.
func (m *OrderedFileReports) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	var b bytes.Buffer
	b.WriteByte('{')
	for e := m.oldest; e != nil; e = e.next {
		if e != m.oldest {
			b.WriteByte(',')
		}
		k, err := json.Marshal(e.Key)
		if err != nil {
			return nil, err
		}
		v, err := json.Marshal(e.Value)
		if err != nil {
			return nil, fmt.Errorf("file report %q: %w", e.Key, err)
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// UnmarshalJSON reads a JSON object into m in order. A repeated key keeps its
// first place and its last report, as Set does. A JSON null changes nothing.
func (m *OrderedFileReports) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if t != json.Delim('{') {
		return fmt.Errorf("file reports: got %v, want a JSON object", t)
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		// The keys of a JSON object are strings.
		key, _ := t.(string)
		var fr *FileReport
		if err := dec.Decode(&fr); err != nil {
			return fmt.Errorf("file report %q: %w", key, err)
		}
		m.Set(key, fr)
	}
	_, err = dec.Token()
	return err
}

// MarshalYAML returns m as a YAML mapping in order.
func (m *OrderedFileReports) MarshalYAML() (any, error) {
	if m == nil {
		return nil, nil
	}
	n := &yaml.Node{Kind: yaml.MappingNode}
	for e := m.oldest; e != nil; e = e.next {
		var k, v yaml.Node
		if err := k.Encode(e.Key); err != nil {
			return nil, err
		}
		if err := v.Encode(e.Value); err != nil {
			return nil, fmt.Errorf("file report %q: %w", e.Key, err)
		}
		n.Content = append(n.Content, &k, &v)
	}
	return n, nil
}

// UnmarshalYAML reads a YAML mapping into m in order.
func (m *OrderedFileReports) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: file reports: want a YAML mapping", n.Line)
	}
	for kv := range slices.Chunk(n.Content, 2) {
		var key string
		if err := kv[0].Decode(&key); err != nil {
			return err
		}
		var fr *FileReport
		if err := kv[1].Decode(&fr); err != nil {
			return fmt.Errorf("file report %q: %w", key, err)
		}
		m.Set(key, fr)
	}
	return nil
}
