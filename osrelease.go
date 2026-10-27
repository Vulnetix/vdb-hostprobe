package hostprobe

import (
	"bufio"
	"bytes"
	"context"
	"regexp"
	"strings"
	"time"
)

// Release names the operating system release.
type Release struct {
	// ID is lower case: ubuntu, debian, fedora, alpine, arch, macos, windows,
	// freebsd, and so on.
	ID string `json:"id"`
	// VersionID is the release number, such as 24.04, 15.1 or a Windows build.
	VersionID string `json:"versionId,omitempty"`
	// Name is the human name when the system gives one, such as "Ubuntu 24.04.1 LTS".
	Name string `json:"name,omitempty"`
}

// String is "ubuntu 24.04", or "" when nothing was found.
func (r Release) String() string {
	if r.ID == "" {
		return ""
	}
	if r.VersionID == "" {
		return r.ID
	}
	return r.ID + " " + r.VersionID
}

var tokenRe = regexp.MustCompile(`[^a-z0-9._-]+`)

func token(s string, max int) string {
	s = tokenRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-")
	s = strings.Trim(s, "-")
	if len(s) > max {
		s = s[:max]
	}
	return s
}

func clip(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// OSRelease reads the release from /etc/os-release on Linux, sw_vers on macOS,
// freebsd-version on FreeBSD and the registry on Windows.
func OSRelease(ctx context.Context, s Seam) Release {
	switch s.GOOS {
	case "linux":
		for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
			if b, err := s.ReadFile(p); err == nil {
				if r := ParseOSRelease(b); r.ID != "" {
					return r
				}
			}
		}
		return Release{ID: "linux"}
	case "darwin":
		v := strings.TrimSpace(string(run(ctx, s, 3*time.Second, "sw_vers", "-productVersion")))
		return Release{ID: "macos", VersionID: token(v, 32), Name: clip("macOS "+v, 64)}
	case "freebsd":
		v := strings.TrimSpace(string(run(ctx, s, 3*time.Second, "freebsd-version")))
		return Release{ID: "freebsd", VersionID: token(v, 32)}
	case "windows":
		const key = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
		name := regValue(run(ctx, s, 3*time.Second, "reg", "query", key, "/v", "ProductName"), "ProductName")
		build := regValue(run(ctx, s, 3*time.Second, "reg", "query", key, "/v", "CurrentBuild"), "CurrentBuild")
		return Release{ID: "windows", VersionID: token(build, 32), Name: clip(name, 64)}
	}
	return Release{ID: token(s.GOOS, 32)}
}

// ParseOSRelease reads the os-release format (freedesktop.org): KEY=value
// lines, values optionally quoted.
func ParseOSRelease(b []byte) Release {
	vals := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		vals[strings.TrimSpace(k)] = v
	}
	version := vals["VERSION_ID"]
	if version == "" {
		version = vals["BUILD_ID"]
	}
	return Release{ID: token(vals["ID"], 32), VersionID: token(version, 32), Name: clip(vals["PRETTY_NAME"], 64)}
}

// regValue reads "    Name    REG_SZ    value" from `reg query` output.
func regValue(out []byte, name string) string {
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && strings.EqualFold(f[0], name) && strings.HasPrefix(f[1], "REG_") {
			return strings.Join(f[2:], " ")
		}
	}
	return ""
}

// run is Seam.Run with its own timeout, returning the output or nil.
func run(ctx context.Context, s Seam, timeout time.Duration, name string, args ...string) []byte {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := s.Run(ctx, name, args...)
	if err != nil && len(out) == 0 {
		return nil
	}
	return out
}
