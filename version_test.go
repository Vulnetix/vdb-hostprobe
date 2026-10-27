package hostprobe

import "testing"

// Real outputs that the default pattern gets wrong, pinned to the probe's
// own pattern.
func TestVersionPatternsOnRealOutput(t *testing.T) {
	cases := []struct{ probe, out, want string }{
		{"java", "openjdk version \"26\" 2026-03-17\nOpenJDK Runtime Environment (build 26+35)\n", "26"},
		{"java", "openjdk version \"21.0.5\" 2024-10-15 LTS\n", "21.0.5"},
		{"javac", "javac 26\n", "26"},
		{"elixir", "Erlang/OTP 27 [erts-15.1] [source] [64-bit]\n\nElixir 1.18.3 (compiled with Erlang/OTP 27)\n", "1.18.3"},
		{"compose", "podman-compose version 1.3.0\npodman version 6.1.4\n", "1.3.0"},
		{"compose", "Docker Compose version v2.29.1\n", "2.29.1"},
		{"go", "go version go1.25.3 linux/amd64\n", "1.25.3"},
		{"perl", "This is perl 5, version 40, subversion 0 (v5.40.0) built for x86_64-linux\n", "5.40.0"},
		{"erlang", "27\n", "27"},
	}
	for _, c := range cases {
		pr := mustLookup(t, c.probe)
		if got := extractVersion([]byte(c.out), pr.Regex); got != c.want {
			t.Errorf("%s on %q = %q, want %q", c.probe, c.out, got, c.want)
		}
	}
}
