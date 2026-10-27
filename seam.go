package hostprobe

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// Seam is every system call the probe makes. System returns the real one;
// tests build their own.
type Seam struct {
	// LookPath resolves a program name to a path, as exec.LookPath.
	LookPath func(file string) (string, error)
	// Run starts a program and returns what it wrote to stdout and stderr.
	// The error is non-nil for a start failure or a non-zero exit; the output
	// is returned either way.
	Run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// ReadFile reads a small system file such as /etc/os-release.
	ReadFile func(name string) ([]byte, error)
	// Stat reports a file, following symbolic links.
	Stat func(name string) (fs.FileInfo, error)
	// Getenv reads one environment variable, for platform detection only.
	Getenv func(key string) string
	GOOS   string
	GOARCH string
}

// maxOutput caps what a version command may return. Versions are on the first
// lines; a program that prints its whole manual is cut short.
const maxOutput = 64 << 10

// System is the Seam for the machine this process runs on.
func System() Seam {
	return Seam{
		LookPath: exec.LookPath,
		Run:      runProgram,
		ReadFile: os.ReadFile,
		Stat:     os.Stat,
		Getenv:   os.Getenv,
		GOOS:     runtime.GOOS,
		GOARCH:   runtime.GOARCH,
	}
}

// runProgram runs with a minimal environment: enough to find the program's
// own files and print in a stable locale, never the caller's tokens.
func runProgram(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = scrubbedEnv()
	cmd.Stdin = nil
	var out limitedBuffer
	out.max = maxOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.WaitDelay = 500 * time.Millisecond
	err := cmd.Run()
	return out.Bytes(), err
}

// passEnv is the allow list for version commands. PATH and HOME let runtimes
// find their own install; the Windows names are needed for anything to start.
var passEnv = []string{"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "SystemRoot", "WINDIR", "TMP", "TEMP", "TMPDIR", "APPDATA", "LOCALAPPDATA", "ProgramFiles", "ProgramData"}

func scrubbedEnv() []string {
	env := []string{"LC_ALL=C", "LANG=C", "NO_COLOR=1", "TERM=dumb"}
	for _, k := range passEnv {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		b.Buffer.Write(p)
	}
	return n, nil
}

var _ io.Writer = (*limitedBuffer)(nil)
