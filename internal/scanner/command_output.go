package scanner

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

func runCommandOutput(cmd *exec.Cmd, scannerName string, verbose bool) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	var stdoutPrefix, stderrPrefix *prefixedWriter
	if verbose {
		outputMu := &sync.Mutex{}
		stdoutPrefix = &prefixedWriter{destination: os.Stdout, label: scannerName, mu: outputMu}
		stderrPrefix = &prefixedWriter{destination: os.Stderr, label: scannerName + " stderr", mu: outputMu}
		cmd.Stdout = io.MultiWriter(&stdout, stdoutPrefix)
		cmd.Stderr = io.MultiWriter(&stderr, stderrPrefix)
	}

	err := cmd.Run()
	if stdoutPrefix != nil {
		if flushErr := stdoutPrefix.Flush(); err == nil {
			err = flushErr
		}
		if flushErr := stderrPrefix.Flush(); err == nil {
			err = flushErr
		}
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

type prefixedWriter struct {
	destination io.Writer
	label       string
	mu          *sync.Mutex
	pending     []byte
}

func (w *prefixedWriter) Write(data []byte) (int, error) {
	length := len(data)
	w.pending = append(w.pending, data...)
	for {
		newline := bytes.IndexByte(w.pending, '\n')
		if newline < 0 {
			break
		}
		if err := w.writeLine(w.pending[:newline]); err != nil {
			return 0, err
		}
		w.pending = w.pending[newline+1:]
	}
	return length, nil
}

func (w *prefixedWriter) Flush() error {
	if len(w.pending) == 0 {
		return nil
	}
	err := w.writeLine(w.pending)
	w.pending = nil
	return err
}

func (w *prefixedWriter) writeLine(line []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := fmt.Fprintf(w.destination, "[%s] %s\n", w.label, line)
	return err
}
