// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

// classBlob returns a synthetic, benign byte blob carrying the Java class
// file magic and version header, followed by the provided strings encoded
// the way CONSTANT_Utf8 entries appear in a constant pool. The blob is not
// a loadable class; it only needs to be detected as bytecode and carry the
// trigger strings.
func classBlob(tokens ...string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34})
	for _, tok := range tokens {
		b.WriteByte(0x01)
		b.WriteByte(byte(len(tok) >> 8))
		b.WriteByte(byte(len(tok)))
		b.WriteString(tok)
	}
	return b.Bytes()
}

// scanRuleNames scans a path and returns the set of matched rule names per
// file base name.
func scanRuleNames(t *testing.T, scanPath string) map[string]map[string]bool {
	t.Helper()
	ctx := t.Context()

	var out bytes.Buffer
	r, err := render.New("json", &out)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	mc := malcontent.Config{
		Concurrency: runtime.NumCPU(),
		IgnoreSelf:  false,
		MinFileRisk: 0,
		MinRisk:     0,
		Renderer:    r,
		Rules:       yrs,
		ScanPaths:   []string{scanPath},
	}
	res, err := Scan(ctx, mc)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]map[string]bool{}
	res.Files.Range(func(key string, fr *malcontent.FileReport) bool {
		if fr == nil {
			return true
		}
		names := make(map[string]bool, len(fr.Behaviors))
		for _, b := range fr.Behaviors {
			names[b.RuleName] = true
		}
		got[filepath.Base(key)] = names
		return true
	})
	return got
}

func TestJavaRulesOnClassFiles(t *testing.T) {
	t.Parallel()
	td := t.TempDir()

	filler := "synthetic benign fixture for malcontent rule tests"
	fixtures := map[string][]byte{
		// positive fixtures: each carries the co-occurring trigger strings
		"ReflectExec.class": classBlob("java/lang/reflect/Method", "invoke", "getRuntime", filler),
		"Deser.class":       classBlob("java/io/ObjectInputStream", "readObject", filler),
		"Gadget.class": classBlob("java/io/ObjectInputStream", "readObject",
			"InvokerTransformer", "ChainedTransformer", filler),
		"NativeLoad.class": classBlob("java/lang/System", "loadLibrary", "libagent.so", filler),
		"Wallet.class":     classBlob("javax/crypto", "0x1f3a9b7c2d4e5f60718293a4b5c6d7e8f9012345", filler),
		"UrlLoad.class":    classBlob("URLClassLoader", "http://203.0.113.7/payload/Update.class", filler),
		// proves jar,java scoped rules now apply to bare class files
		"ScopeProof.class": classBlob("java/lang/Runtime", "exec", filler),
		// negative fixtures: single capability tokens must not fire
		"OnlyReflect.class": classBlob("java/lang/reflect/Method", "invoke", filler),
		"OnlyCrypto.class":  classBlob("javax/crypto", "AES/CBC/PKCS5Padding", filler),
		"OnlyLoadLib.class": classBlob("java/lang/System", "loadLibrary", filler),
		"UrlBenign.class":   classBlob("URLClassLoader", "http://www.w3.org/2001/XMLSchema", filler),
		"Benign.class":      classBlob("java/lang/Object", "toString", "hello world", filler),
	}
	for name, content := range fixtures {
		if err := os.WriteFile(filepath.Join(td, name), content, 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}

	got := scanRuleNames(t, td)

	tests := []struct {
		file    string
		present []string
		absent  []string
	}{
		{"ReflectExec.class", []string{"java_reflect_exec"}, nil},
		{"Deser.class", []string{"java_object_deserialization"}, []string{"java_deserialization_gadget_chain"}},
		{"Gadget.class", []string{"java_object_deserialization", "java_deserialization_gadget_chain"}, nil},
		{"NativeLoad.class", []string{"java_native_library_load"}, nil},
		{"Wallet.class", []string{"java_hardcoded_wallet"}, nil},
		{"UrlLoad.class", []string{"java_url_class_load"}, nil},
		{"ScopeProof.class", []string{"java_exec"}, nil},
		{"OnlyReflect.class", nil, []string{"java_reflect_exec"}},
		{"OnlyCrypto.class", nil, []string{"java_hardcoded_wallet"}},
		{"OnlyLoadLib.class", nil, []string{"java_native_library_load"}},
		{"UrlBenign.class", nil, []string{"java_url_class_load"}},
		{"Benign.class", nil, []string{
			"java_reflect_exec", "java_object_deserialization",
			"java_deserialization_gadget_chain", "java_native_library_load",
			"java_hardcoded_wallet", "java_url_class_load", "java_exec",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			t.Parallel()
			names := got[tt.file]
			for _, rule := range tt.present {
				if !names[rule] {
					t.Errorf("%s: expected rule %q to fire, got %v", tt.file, rule, names)
				}
			}
			for _, rule := range tt.absent {
				if names[rule] {
					t.Errorf("%s: expected rule %q not to fire, got %v", tt.file, rule, names)
				}
			}
		})
	}
}

// TestJavaRulesInWar proves the end-to-end chain: a war archive is
// extracted, its inner class file is detected as bytecode, and rules
// scoped to jar,java filetypes fire on the extracted class.
func TestJavaRulesInWar(t *testing.T) {
	t.Parallel()
	td := t.TempDir()

	warPath := filepath.Join(td, "webapp.war")
	buildZipFile(t, warPath, map[string][]byte{
		"WEB-INF/web.xml": []byte("<web-app/>"),
		"WEB-INF/classes/WarInner.class": classBlob("java/lang/Runtime", "exec",
			"synthetic benign fixture for malcontent rule tests"),
	})

	got := scanRuleNames(t, warPath)

	union := map[string]bool{}
	for _, names := range got {
		for name := range names {
			union[name] = true
		}
	}
	if !union["java_exec"] {
		t.Errorf("expected java_exec to fire on class inside war, matched rules: %v", union)
	}
}
