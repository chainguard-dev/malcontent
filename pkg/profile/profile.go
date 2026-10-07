// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"syscall"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

// Config holds the configuration for profiling.
type Config struct {
	OutputDir      string
	FilePrefix     string
	SampleInterval time.Duration
}

// DefaultConfig returns a default profile configuration.
func DefaultConfig() *Config {
	return &Config{
		OutputDir:      "profiles",
		FilePrefix:     fmt.Sprintf("profile_%d", time.Now().UnixNano()),
		SampleInterval: 5 * time.Second,
	}
}

type Profiler struct {
	config     *Config
	cpuFile    *os.File
	memFile    *os.File
	traceFile  *os.File
	goroutFile *os.File
	closeOnce  sync.Once
	workers    sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

// StartProfiling begins profiling CPU, goroutines, and memory.
func StartProfiling(ctx context.Context, config *Config) (*Profiler, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := file.MkdirAll(config.OutputDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create profile directory: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)

	p := &Profiler{
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}

	if err := p.initializeProfiles(); err != nil {
		p.Stop()
		return nil, err
	}

	if err := pprof.StartCPUProfile(p.cpuFile); err != nil {
		p.Stop()
		return nil, fmt.Errorf("failed to start CPU profile: %w", err)
	}

	if err := trace.Start(p.traceFile); err != nil {
		p.Stop()
		return nil, fmt.Errorf("failed to start trace: %w", err)
	}

	p.workers.Go(p.profileGoroutines)

	if config.SampleInterval > 0 {
		p.workers.Go(p.periodicHeapProfile)
	}

	// Registering before StartProfiling returns means a signal that arrives
	// right afterward still stops the profiler.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go p.handleSignals(sigChan)

	return p, nil
}

func (p *Profiler) initializeProfiles() error {
	var err error

	p.cpuFile, err = p.createInOutputDir(p.config.FilePrefix + "_cpu.pprof")
	if err != nil {
		return fmt.Errorf("failed to create CPU profile: %w", err)
	}

	p.memFile, err = p.createInOutputDir(p.config.FilePrefix + "_mem_final.pprof")
	if err != nil {
		return fmt.Errorf("failed to create memory profile: %w", err)
	}

	p.traceFile, err = p.createInOutputDir(p.config.FilePrefix + "_trace.out")
	if err != nil {
		return fmt.Errorf("failed to create trace file: %w", err)
	}

	p.goroutFile, err = p.createInOutputDir(p.config.FilePrefix + "_goroutines.txt")
	if err != nil {
		return fmt.Errorf("failed to create goroutine profile: %w", err)
	}

	return nil
}

// createInOutputDir creates or truncates name inside the configured output
// directory. Opening it through an os.Root refuses a name that would resolve
// outside that directory.
func (p *Profiler) createInOutputDir(name string) (*os.File, error) {
	root, err := os.OpenRoot(p.config.OutputDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
}

// periodicHeapProfile writes a heap snapshot every sample interval until the
// profiler stops. It runs in p.workers.
func (p *Profiler) periodicHeapProfile() {
	ticker := time.NewTicker(p.config.SampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.writeHeapSnapshot()
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *Profiler) writeHeapSnapshot() {
	f, err := p.createInOutputDir(fmt.Sprintf("%s_mem_%d.pprof", p.config.FilePrefix, time.Now().UnixNano()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create heap profile: %v\n", err)
		return
	}
	defer func() { _ = f.Close() }()

	writeHeapProfile(f, "heap profile")
}

// writeHeapProfile writes the current heap profile to w and reports a failure
// on standard error, naming the profile as what.
func writeHeapProfile(w io.Writer, what string) {
	if err := pprof.WriteHeapProfile(w); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", what, err)
	}
}

// profileGoroutines appends a goroutine dump to the goroutine profile every
// five seconds until the profiler stops. It runs in p.workers.
func (p *Profiler) profileGoroutines() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	buf := make([]byte, 1<<20)

	for {
		select {
		case <-ticker.C:
			buf = writeGoroutineDump(p.goroutFile, buf, maxStackBuf)
		case <-p.ctx.Done():
			return
		}
	}
}

// maxStackBuf caps the buffer used to capture a goroutine dump.
const maxStackBuf = 64 << 20 // 64 MiB

// writeGoroutineDump appends a timestamped dump of every goroutine's stack to
// w. buf is reused scratch space that doubles until the dump fits or doubling
// would exceed limit, in which case the dump is cut at the buffer's size. The
// possibly grown buffer is returned for the next dump.
func writeGoroutineDump(w io.Writer, buf []byte, limit int) []byte {
	buf = buf[:cap(buf)]
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		// runtime.Stack filled the whole buffer.
		if cap(buf)*2 > limit {
			break
		}
		buf = make([]byte, cap(buf)*2)
	}

	if _, err := fmt.Fprintf(w, "\n--- Goroutine dump at %s ---\n", time.Now().Format(time.RFC3339)); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write goroutine timestamp: %v\n", err)
		return buf
	}

	if _, err := w.Write(buf); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write goroutine dump: %v\n", err)
	}
	return buf
}

func (p *Profiler) handleSignals(sigChan <-chan os.Signal) {
	select {
	case <-sigChan:
		p.Stop()
	case <-p.ctx.Done():
		return
	}
}

// Stop ends profiling. It waits for the goroutine dump and heap snapshot
// goroutines to exit, so neither writes to a file after it is closed, then
// writes the final heap profile and closes every profile file. Calls after
// the first do nothing.
func (p *Profiler) Stop() {
	p.closeOnce.Do(func() {
		p.cancel()
		p.workers.Wait()
		pprof.StopCPUProfile()

		writeHeapProfile(p.memFile, "final heap profile")

		trace.Stop()

		for _, f := range []*os.File{p.cpuFile, p.memFile, p.traceFile, p.goroutFile} {
			if f != nil {
				_ = f.Close()
			}
		}
	})
}
