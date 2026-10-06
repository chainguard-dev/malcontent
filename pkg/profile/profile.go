// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"syscall"
	"time"
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
	stopChan   chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc
}

// StartProfiling beings profiling CPU, goroutines, and memory.
func StartProfiling(ctx context.Context, config *Config) (*Profiler, error) {
	if config == nil {
		config = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(ctx)

	p := &Profiler{
		config:   config,
		stopChan: make(chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
	}

	if err := os.MkdirAll(config.OutputDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create profile directory: %w", err)
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

	go p.profileGoroutines()

	if config.SampleInterval > 0 {
		go p.periodicHeapProfile()
	}

	go p.handleSignals()

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

	if err := pprof.WriteHeapProfile(f); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write heap profile: %v\n", err)
	}
}

func (p *Profiler) profileGoroutines() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	buf := make([]byte, 1<<20)

	for {
		select {
		case <-ticker.C:
			buf = p.writeGoroutineDump(buf, maxStackBuf)
		case <-p.ctx.Done():
			return
		}
	}
}

// maxStackBuf caps the buffer used to capture a goroutine dump.
const maxStackBuf = 64 * 1024 * 1024 // 64MB

// writeGoroutineDump appends a timestamped dump of every goroutine's stack to
// the goroutine profile. buf is reused scratch space that doubles until the
// dump fits or doubling would exceed limit, in which case the dump is cut at
// the buffer's size. The possibly grown buffer is returned for the next dump.
func (p *Profiler) writeGoroutineDump(buf []byte, limit int) []byte {
	buf = buf[:cap(buf)]
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		if cap(buf)*2 > limit {
			buf = buf[:n]
			break
		}
		buf = make([]byte, cap(buf)*2)
	}

	if _, err := fmt.Fprintf(p.goroutFile, "\n--- Goroutine dump at %s ---\n", time.Now().Format(time.RFC3339)); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write goroutine timestamp: %v\n", err)
		return buf
	}

	if _, err := p.goroutFile.Write(buf); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write goroutine dump: %v\n", err)
	}
	return buf
}

func (p *Profiler) handleSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigChan:
		p.Stop()
	case <-p.ctx.Done():
		return
	}
}

func (p *Profiler) Stop() {
	p.closeOnce.Do(func() {
		p.cancel()
		pprof.StopCPUProfile()

		if err := pprof.WriteHeapProfile(p.memFile); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write final heap profile: %v\n", err)
		}

		trace.Stop()

		for _, f := range []*os.File{p.cpuFile, p.memFile, p.traceFile, p.goroutFile} {
			if f != nil {
				_ = f.Close()
			}
		}

		close(p.stopChan)
	})
}
