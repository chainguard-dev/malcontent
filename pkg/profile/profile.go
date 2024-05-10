package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"runtime/trace"
	"time"
)

func Profile() (func(), error) {
	timestamp := time.Now().Nanosecond()

	// Create the profiles directory if it does not already exist
	if _, err := os.Stat("profiles"); os.IsNotExist(err) {
		err := os.Mkdir("profiles", 0o755)
		if err != nil {
			return nil, fmt.Errorf("failed to create profiles directory: %w", err)
		}
	}

	// Create the CPU profile
	c, err := os.Create(filepath.Join("profiles", fmt.Sprintf("cpu_%d.pprof", timestamp)))
	if err != nil {
		return nil, fmt.Errorf("failed to create CPU profile: %w", err)
	}

	// Start the CPU profiling
	err = pprof.StartCPUProfile(c)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("failed to start CPU profile: %w", err)
	}

	// Create the memory profile
	m, err := os.Create(filepath.Join("profiles", fmt.Sprintf("mem_%d.pprof", timestamp)))
	if err != nil {
		c.Close()
		m.Close()
		return nil, fmt.Errorf("failed to create memory profile: %w", err)
	}

	// Create the trace file
	t, err := os.Create(filepath.Join("profiles", fmt.Sprintf("trace_%d.out", timestamp)))
	if err != nil {
		c.Close()
		m.Close()
		t.Close()
		return nil, fmt.Errorf("failed to create trace file: %w", err)
	}

	// Start tracing
	err = trace.Start(t)
	if err != nil {
		c.Close()
		m.Close()
		t.Close()
		return nil, fmt.Errorf("failed to start trace: %w", err)
	}

	// Handle cleanup for profiling, tracing, and file closures
	stop := func() {
		pprof.StopCPUProfile()
		if err := pprof.WriteHeapProfile(m); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write memory profile: %v\n", err)
		}
		trace.Stop()
		c.Close()
		m.Close()
		t.Close()
	}

	return stop, nil
}
