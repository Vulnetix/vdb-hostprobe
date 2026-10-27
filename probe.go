package hostprobe

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Fact is one thing found on the machine.
type Fact struct {
	Name    string `json:"name"`
	Kind    Kind   `json:"kind"`
	Version string `json:"version,omitempty"`
	// Binary is the program name that was found, never a path.
	Binary string `json:"binary"`
	// Path is where the program was found. It stays on the machine: Public
	// drops it.
	Path string `json:"path,omitempty"`
	// Verify is the command that re-confirms this fact. It stays on the
	// machine: Public drops it.
	Verify *Verify `json:"verify,omitempty"`
}

// Verify is the stored command that found a fact.
type Verify struct {
	// Argv starts with the resolved path.
	Argv  []string `json:"argv"`
	Regex string   `json:"regex,omitempty"`
	// Presence means only that the file still exists; no command runs.
	Presence bool `json:"presence,omitempty"`
}

// Public is the fact without the path or verify command, for sending to a
// server.
func (f Fact) Public() Fact {
	f.Path = ""
	f.Verify = nil
	return f
}

// Result is the outcome of one probe. Fact is nil when nothing was found.
type Result struct {
	Probe Probe
	Fact  *Fact
}

// Options tune Run. The zero value is usable.
type Options struct {
	// Concurrency is how many version commands run at once. Default 4.
	Concurrency int
	// Timeout caps one version command. Default 5s.
	Timeout time.Duration
	// Cache remembers versions by file identity. nil runs every command.
	Cache VersionCache
	// OnResult is called once per probe as it finishes, never concurrently.
	OnResult func(Result)
}

// DefaultVersionRegex finds the first dotted version in a program's output.
const DefaultVersionRegex = `\d+\.\d+(?:\.\d+)?(?:[.\-+][0-9A-Za-z.\-]+)?`

var defaultVersionRe = regexp.MustCompile(DefaultVersionRegex)

// Run probes each entry that applies to the seam's OS and returns the
// results in the same order. It looks every program up on PATH first, which
// is cheap, then runs version commands for the ones found, Concurrency at a
// time.
func Run(ctx context.Context, s Seam, probes []Probe, opt Options) []Result {
	if opt.Concurrency <= 0 {
		opt.Concurrency = 4
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 5 * time.Second
	}
	results := make([]Result, len(probes))
	var mu sync.Mutex
	emit := func(r Result) {
		if opt.OnResult == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		opt.OnResult(r)
	}
	sem := make(chan struct{}, opt.Concurrency)
	var wg sync.WaitGroup
	for i, pr := range probes {
		results[i].Probe = pr
		if !pr.applies(s.GOOS) {
			continue
		}
		bin, path := find(s, pr.Binaries)
		if path == "" {
			emit(results[i])
			continue
		}
		f := &Fact{Name: pr.Name, Kind: pr.Kind, Binary: bin, Path: path}
		if pr.NoVersion {
			f.Verify = &Verify{Argv: []string{path}, Presence: true}
			results[i].Fact = f
			emit(results[i])
			continue
		}
		args := pr.Args
		if args == nil {
			args = []string{"--version"}
		}
		f.Verify = &Verify{Argv: append([]string{path}, args...), Regex: pr.Regex}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i].Fact = f
				emit(results[i])
				return
			}
			defer func() { <-sem }()
			f.Version = versionOf(ctx, s, opt, f.Verify)
			results[i].Fact = f
			emit(results[i])
		}(i)
	}
	wg.Wait()
	return results
}

// Facts keeps the found facts from results.
func Facts(results []Result) []Fact {
	out := make([]Fact, 0, len(results))
	for _, r := range results {
		if r.Fact != nil {
			out = append(out, *r.Fact)
		}
	}
	return out
}

func find(s Seam, bins []string) (string, string) {
	for _, b := range bins {
		if path, err := s.LookPath(b); err == nil && path != "" {
			return filepath.Base(b), path
		}
	}
	return "", ""
}

func versionOf(ctx context.Context, s Seam, opt Options, v *Verify) string {
	key := ""
	if opt.Cache != nil && s.Stat != nil {
		if info, err := s.Stat(v.Argv[0]); err == nil {
			key = CacheKey(v.Argv[0], info, v.Argv[1:])
			if got, ok := opt.Cache.Get(key); ok {
				return got
			}
		}
	}
	out := run(ctx, s, opt.Timeout, v.Argv[0], v.Argv[1:]...)
	version := extractVersion(out, v.Regex)
	if version != "" && key != "" {
		opt.Cache.Put(key, version)
	}
	return version
}

func extractVersion(out []byte, pattern string) string {
	re := defaultVersionRe
	if pattern != "" {
		var err error
		if re, err = regexp.Compile(pattern); err != nil {
			return ""
		}
	}
	// A pattern with a group reports the group, so it can anchor on a label
	// ("Elixir 1.18.3" after the Erlang banner) without returning the label.
	m := re.FindStringSubmatch(string(out))
	if m == nil {
		return ""
	}
	v := m[0]
	for _, g := range m[1:] {
		if g != "" {
			v = g
			break
		}
	}
	if len(v) > 64 {
		v = v[:64]
	}
	return strings.TrimSpace(v)
}
