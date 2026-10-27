package hostprobe

import (
	"context"
	"errors"
	"io/fs"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeFS is a fixed machine: programs on PATH with their output, and files.
type fakeFS struct {
	mu      sync.Mutex
	goos    string
	path    map[string]string // program -> resolved path
	output  map[string]string // "path args..." -> output
	fail    map[string]bool   // "path args..." -> non-zero exit
	files   map[string]string
	env     map[string]string
	ran     []string
	running int
	maxRun  int
	delay   time.Duration
}

type fakeInfo struct{ name string }

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 1 }
func (f fakeInfo) Mode() fs.FileMode  { return 0o755 }
func (f fakeInfo) ModTime() time.Time { return time.Unix(1, 0) }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return nil }

func (m *fakeFS) seam() Seam {
	return Seam{
		LookPath: func(file string) (string, error) {
			if p, ok := m.path[file]; ok {
				return p, nil
			}
			return "", errors.New("not found")
		},
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			key := strings.TrimSpace(name + " " + strings.Join(args, " "))
			m.mu.Lock()
			m.ran = append(m.ran, key)
			m.running++
			if m.running > m.maxRun {
				m.maxRun = m.running
			}
			m.mu.Unlock()
			if m.delay > 0 {
				time.Sleep(m.delay)
			}
			m.mu.Lock()
			m.running--
			m.mu.Unlock()
			out, ok := m.output[key]
			if !ok {
				return nil, errors.New("exec: not found")
			}
			if m.fail[key] {
				return []byte(out), errors.New("exit status 1")
			}
			return []byte(out), nil
		},
		ReadFile: func(name string) ([]byte, error) {
			if b, ok := m.files[name]; ok {
				return []byte(b), nil
			}
			return nil, fs.ErrNotExist
		},
		Stat: func(name string) (fs.FileInfo, error) {
			if _, ok := m.files[name]; ok {
				return fakeInfo{name}, nil
			}
			for _, p := range m.path {
				if p == name {
					return fakeInfo{name}, nil
				}
			}
			return nil, fs.ErrNotExist
		},
		Getenv: func(k string) string { return m.env[k] },
		GOOS:   m.goos,
		GOARCH: "amd64",
	}
}

func TestCatalogueNamesAreUniqueAndWellFormed(t *testing.T) {
	name := regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	seen := map[string]bool{}
	for _, pr := range Catalogue() {
		if !name.MatchString(pr.Name) {
			t.Errorf("probe name %q is not lower-case kebab", pr.Name)
		}
		if seen[pr.Name] {
			t.Errorf("probe %q appears twice", pr.Name)
		}
		seen[pr.Name] = true
		if len(pr.Binaries) == 0 {
			t.Errorf("probe %q has no binaries", pr.Name)
		}
		if pr.Kind == "" {
			t.Errorf("probe %q has no kind", pr.Name)
		}
		if pr.Regex != "" {
			if _, err := regexp.Compile(pr.Regex); err != nil {
				t.Errorf("probe %q regex: %v", pr.Name, err)
			}
		}
		if pr.NoVersion && pr.Args != nil {
			t.Errorf("probe %q is presence only but has version args", pr.Name)
		}
	}
	for _, want := range []string{"cpython", "node", "deno", "rust", "go", "java", "apt", "dnf", "apk", "pacman", "brew", "choco", "winget", "playwright", "k6", "ollama", "litellm", "podman", "pre-commit", "vulnetix"} {
		if !seen[want] {
			t.Errorf("catalogue is missing %q", want)
		}
	}
}

func TestRunFindsVersionsAndSkipsMissing(t *testing.T) {
	m := &fakeFS{
		goos: "linux",
		path: map[string]string{"python3": "/usr/bin/python3", "go": "/usr/local/go/bin/go", "erl": "/usr/bin/erl", "cl": "/c/cl.exe"},
		output: map[string]string{
			"/usr/bin/python3 --version":   "Python 3.12.7\n",
			"/usr/local/go/bin/go version": "go version go1.25.3 linux/amd64\n",
			`/usr/bin/erl -noshell -eval io:fwrite("~s~n",[erlang:system_info(otp_release)]),halt().`: "27\n",
		},
	}
	probes := []Probe{mustLookup(t, "cpython"), mustLookup(t, "pypy"), mustLookup(t, "go"), mustLookup(t, "erlang"), mustLookup(t, "msvc")}
	var seen []string
	res := Run(context.Background(), m.seam(), probes, Options{OnResult: func(r Result) { seen = append(seen, r.Probe.Name) }})
	got := map[string]string{}
	for _, f := range Facts(res) {
		got[f.Name] = f.Version
	}
	want := map[string]string{"cpython": "3.12.7", "go": "1.25.3", "erlang": "27"}
	if len(got) != len(want) {
		t.Fatalf("facts = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s version = %q, want %q", k, got[k], v)
		}
	}
	// msvc is windows only, so it is neither probed nor reported.
	if len(seen) != 4 {
		t.Errorf("OnResult called for %v, want 4 probes (msvc skipped)", seen)
	}
	py := res[0].Fact
	if py.Binary != "python3" || py.Path != "/usr/bin/python3" || py.Verify == nil || py.Verify.Argv[0] != "/usr/bin/python3" {
		t.Errorf("cpython fact = %+v", py)
	}
	if pub := py.Public(); pub.Path != "" || pub.Verify != nil {
		t.Errorf("Public kept path or verify: %+v", pub)
	}
}

func TestRunRespectsConcurrency(t *testing.T) {
	m := &fakeFS{goos: "linux", path: map[string]string{}, output: map[string]string{}, delay: 20 * time.Millisecond}
	var probes []Probe
	for _, name := range []string{"npm", "pnpm", "yarn", "uv", "poetry", "cargo", "gem", "composer"} {
		pr := mustLookup(t, name)
		m.path[pr.Binaries[0]] = "/bin/" + pr.Binaries[0]
		m.output["/bin/"+pr.Binaries[0]+" --version"] = "1.2.3"
		probes = append(probes, pr)
	}
	Run(context.Background(), m.seam(), probes, Options{Concurrency: 2})
	if m.maxRun > 2 {
		t.Errorf("ran %d at once, want at most 2", m.maxRun)
	}
}

type mapCache map[string]string

func (c mapCache) Get(k string) (string, bool) { v, ok := c[k]; return v, ok }
func (c mapCache) Put(k, v string)             { c[k] = v }

func TestRunUsesTheVersionCache(t *testing.T) {
	m := &fakeFS{goos: "linux", path: map[string]string{"node": "/usr/bin/node"}, output: map[string]string{"/usr/bin/node --version": "v22.11.0"}}
	cache := mapCache{}
	probes := []Probe{mustLookup(t, "node")}
	Run(context.Background(), m.seam(), probes, Options{Cache: cache})
	Run(context.Background(), m.seam(), probes, Options{Cache: cache})
	if len(m.ran) != 1 {
		t.Errorf("version command ran %d times, want once with a cache", len(m.ran))
	}
}

func TestPresenceOnlyProbesRunNothing(t *testing.T) {
	m := &fakeFS{goos: "linux", path: map[string]string{"hey": "/usr/bin/hey"}}
	res := Run(context.Background(), m.seam(), []Probe{mustLookup(t, "hey")}, Options{})
	if res[0].Fact == nil || !res[0].Fact.Verify.Presence {
		t.Fatalf("hey fact = %+v", res[0].Fact)
	}
	if len(m.ran) != 0 {
		t.Errorf("ran %v for a presence-only probe", m.ran)
	}
}

func TestCheckConfirmsChangesAndLoses(t *testing.T) {
	m := &fakeFS{goos: "linux", path: map[string]string{"cargo": "/usr/bin/cargo"}, output: map[string]string{"/usr/bin/cargo --version": "cargo 1.82.0"}}
	f := Facts(Run(context.Background(), m.seam(), []Probe{mustLookup(t, "cargo")}, Options{}))[0]

	m.output["/usr/bin/cargo --version"] = "cargo 1.83.0"
	got, err := Check(context.Background(), m.seam(), f, 0)
	if err != nil || got.Version != "1.83.0" {
		t.Fatalf("Check after upgrade = %+v, %v", got, err)
	}

	m.fail = map[string]bool{"/usr/bin/cargo --version": true}
	m.output["/usr/bin/cargo --version"] = ""
	if _, err := Check(context.Background(), m.seam(), f, 0); !errors.Is(err, ErrGone) {
		t.Errorf("Check of a broken program = %v, want ErrGone", err)
	}

	delete(m.path, "cargo")
	if _, err := Check(context.Background(), m.seam(), f, 0); !errors.Is(err, ErrGone) {
		t.Errorf("Check of a removed program = %v, want ErrGone", err)
	}
}

func TestCheckWithoutVerifyLooksUpTheBinary(t *testing.T) {
	m := &fakeFS{goos: "linux", path: map[string]string{"jq": "/usr/bin/jq"}}
	if _, err := Check(context.Background(), m.seam(), Fact{Name: "jq", Binary: "jq"}, 0); err != nil {
		t.Errorf("Check jq = %v", err)
	}
	if _, err := Check(context.Background(), m.seam(), Fact{Name: "yq", Binary: "yq"}, 0); !errors.Is(err, ErrGone) {
		t.Errorf("Check missing yq = %v, want ErrGone", err)
	}
}

func TestParseOSRelease(t *testing.T) {
	cases := []struct{ in, want, name string }{
		{"NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n", "ubuntu 24.04", "Ubuntu 24.04.1 LTS"},
		{"ID=fedora\nVERSION_ID=41\n", "fedora 41", ""},
		{"ID=\"arch\"\nBUILD_ID=rolling\n", "arch rolling", ""},
		{"ID=alpine\nVERSION_ID=3.20.3\n# comment\n", "alpine 3.20.3", ""},
		{"ID='opensuse-tumbleweed'\nVERSION_ID=\"20241020\"\n", "opensuse-tumbleweed 20241020", ""},
		{"garbage", "", ""},
	}
	for _, c := range cases {
		r := ParseOSRelease([]byte(c.in))
		if r.String() != c.want || r.Name != c.name {
			t.Errorf("ParseOSRelease(%q) = %q (%q), want %q (%q)", c.in, r.String(), r.Name, c.want, c.name)
		}
	}
}

func TestOSReleasePerPlatform(t *testing.T) {
	ctx := context.Background()
	linux := &fakeFS{goos: "linux", files: map[string]string{"/usr/lib/os-release": "ID=debian\nVERSION_ID=\"12\"\n"}}
	if got := OSRelease(ctx, linux.seam()).String(); got != "debian 12" {
		t.Errorf("linux fallback = %q", got)
	}
	mac := &fakeFS{goos: "darwin", output: map[string]string{"sw_vers -productVersion": "15.1\n"}}
	if got := OSRelease(ctx, mac.seam()).String(); got != "macos 15.1" {
		t.Errorf("darwin = %q", got)
	}
	win := &fakeFS{goos: "windows", output: map[string]string{
		`reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion /v ProductName`:  "\r\nHKEY_LOCAL_MACHINE\\...\r\n    ProductName    REG_SZ    Windows 11 Pro\r\n",
		`reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion /v CurrentBuild`: "\r\n    CurrentBuild    REG_SZ    22631\r\n",
	}}
	r := OSRelease(ctx, win.seam())
	if r.String() != "windows 22631" || r.Name != "Windows 11 Pro" {
		t.Errorf("windows = %+v", r)
	}
}

func TestMachineKey(t *testing.T) {
	ctx := context.Background()
	linux := &fakeFS{goos: "linux", files: map[string]string{"/etc/machine-id": "4f1c2a9e8b7d4c3a9e1f2b3c4d5e6f70\n"}}
	k := MachineKey(ctx, linux.seam())
	if len(k) != 64 {
		t.Fatalf("key = %q, want 64 hex characters", k)
	}
	if strings.Contains(k, "4f1c2a9e") {
		t.Errorf("key leaks the raw id: %q", k)
	}
	if again := MachineKey(ctx, linux.seam()); again != k {
		t.Errorf("key is not stable: %q then %q", k, again)
	}
	if HashMachineID("4F1C2A9E8B7D4C3A9E1F2B3C4D5E6F70") != k {
		t.Errorf("key depends on case")
	}
	mac := &fakeFS{goos: "darwin", output: map[string]string{"ioreg -rd1 -c IOPlatformExpertDevice": "  \"IOPlatformUUID\" = \"0A1B2C3D-1111-2222-3333-444455556666\"\n"}}
	if k := MachineKey(ctx, mac.seam()); len(k) != 64 {
		t.Errorf("darwin key = %q", k)
	}
	for _, bad := range []string{"", "short", "00000000-0000-0000-0000-000000000000", "uninitialized"} {
		if got := HashMachineID(bad); got != "" {
			t.Errorf("HashMachineID(%q) = %q, want empty", bad, got)
		}
	}
	none := &fakeFS{goos: "linux"}
	if k := MachineKey(ctx, none.seam()); k != "" {
		t.Errorf("container without machine-id: key = %q, want empty", k)
	}
}

func TestDetectPlatform(t *testing.T) {
	cases := []struct {
		env   map[string]string
		files map[string]string
		want  string
	}{
		{map[string]string{"GITHUB_ACTIONS": "true"}, nil, PlatformGitHub},
		{map[string]string{"GITLAB_CI": "true"}, nil, PlatformGitLab},
		{map[string]string{"TF_BUILD": "True"}, nil, PlatformAzure},
		{map[string]string{"KUBERNETES_SERVICE_HOST": "10.0.0.1"}, nil, PlatformKubernetes},
		{nil, map[string]string{"/run/.containerenv": ""}, PlatformPodman},
		{nil, map[string]string{"/.dockerenv": ""}, PlatformDocker},
		{nil, nil, PlatformMachine},
	}
	for _, c := range cases {
		m := &fakeFS{goos: "linux", env: c.env, files: c.files}
		if got := DetectPlatform(m.seam()); got != c.want {
			t.Errorf("env %v files %v: %q, want %q", c.env, c.files, got, c.want)
		}
	}
}

func TestFileCache(t *testing.T) {
	c := FileCache(t.TempDir())
	key := CacheKey("/usr/bin/node", fakeInfo{"node"}, []string{"--version"})
	if _, ok := c.Get(key); ok {
		t.Fatal("empty cache returned a value")
	}
	c.Put(key, "22.11.0")
	if v, ok := c.Get(key); !ok || v != "22.11.0" {
		t.Errorf("Get = %q, %v", v, ok)
	}
	c.Put("../escape", "x")
	if _, ok := c.Get("../escape"); ok {
		t.Error("cache accepted a path as a key")
	}
	if _, ok := FileCache("").Get(key); ok {
		t.Error("disabled cache returned a value")
	}
}

func TestLimitedBuffer(t *testing.T) {
	var b limitedBuffer
	b.max = 4
	n, err := b.Write([]byte("abcdef"))
	if n != 6 || err != nil || b.String() != "abcd" {
		t.Errorf("Write = %d, %v, %q", n, err, b.String())
	}
}

func mustLookup(t *testing.T, name string) Probe {
	t.Helper()
	pr, ok := Lookup(name)
	if !ok {
		t.Fatalf("no probe %q", name)
	}
	return pr
}
