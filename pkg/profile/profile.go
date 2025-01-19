package profile

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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

	if err := os.MkdirAll(config.OutputDir, 0o755); err != nil {
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

	p.cpuFile, err = os.Create(filepath.Join(p.config.OutputDir, p.config.FilePrefix+"_cpu.pprof"))
	if err != nil {
		return fmt.Errorf("failed to create CPU profile: %w", err)
	}

	p.memFile, err = os.Create(filepath.Join(p.config.OutputDir, p.config.FilePrefix+"_mem_final.pprof"))
	if err != nil {
		return fmt.Errorf("failed to create memory profile: %w", err)
	}

	p.traceFile, err = os.Create(filepath.Join(p.config.OutputDir, p.config.FilePrefix+"_trace.out"))
	if err != nil {
		return fmt.Errorf("failed to create trace file: %w", err)
	}

	p.goroutFile, err = os.Create(filepath.Join(p.config.OutputDir, p.config.FilePrefix+"_goroutines.txt"))
	if err != nil {
		return fmt.Errorf("failed to create goroutine profile: %w", err)
	}

	return nil
}

func (p *Profiler) periodicHeapProfile() {
	ticker := time.NewTicker(p.config.SampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			timestamp := time.Now().UnixNano()
			filename := filepath.Join(p.config.OutputDir,
				fmt.Sprintf("%s_mem_%d.pprof", p.config.FilePrefix, timestamp))

			f, err := os.Create(filename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create heap profile: %v\n", err)
				continue
			}

			if err := pprof.WriteHeapProfile(f); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write heap profile: %v\n", err)
			}
			f.Close()
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *Profiler) profileGoroutines() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			buf := make([]byte, 1<<20)
			for i := 0; ; i++ {
				n := runtime.Stack(buf, true)
				if n < len(buf) {
					buf = buf[:n]
					break
				}
				buf = make([]byte, 2*len(buf))
			}

			if _, err := fmt.Fprintf(p.goroutFile, "\n--- Goroutine dump at %s ---\n", time.Now().Format(time.RFC3339)); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write goroutine timestamp: %v\n", err)
				continue
			}

			if _, err := p.goroutFile.Write(buf); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write goroutine dump: %v\n", err)
			}
		case <-p.ctx.Done():
			return
		}
	}
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
				f.Close()
			}
		}

		close(p.stopChan)
	})
}
