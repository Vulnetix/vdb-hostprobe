# vdb-hostprobe

Last Updated: 2026-10-27

What a machine has installed, read the same way by the Vulnetix CLI and Belai. It reports:

- the OS release
- the architecture
- a stable anonymous machine key
- the CI or container platform the process runs in
- one fact per tool found, from a catalogue of about 280 probes: language runtimes, package managers, toolchain managers, build, test and lint tools, browsers, container runtimes, GPUs, local AI servers, cloud CLIs, source control, git hook managers, security tools, databases, media tools and shells

It uses the standard library only. Every system call goes through a `Seam`, so tests and callers decide what it may touch.

```go
import hostprobe "github.com/Vulnetix/vdb-hostprobe"

s := hostprobe.System()
release := hostprobe.OSRelease(ctx, s)   // {ID: "ubuntu", VersionID: "24.04"}
key := hostprobe.MachineKey(ctx, s)      // 64 hex characters, or "" in a container without a machine id
platform := hostprobe.DetectPlatform(s)  // github, gitlab, azure, bitbucket, jenkins, kubernetes, podman, docker or cli

results := hostprobe.Run(ctx, s, hostprobe.For(s.GOOS), hostprobe.Options{
    Concurrency: 4,
    Cache:       hostprobe.FileCache(cacheDir),
    OnResult:    func(r hostprobe.Result) { /* stream progress */ },
})
for _, f := range hostprobe.Facts(results) {
    send(f.Public()) // name, kind, version, binary; no path, no command
}

// Later, re-confirm one cached fact with only the command that found it.
f, err := hostprobe.Check(ctx, s, cached, 3*time.Second) // err is ErrGone when it no longer works
```

## API

| Name | What it does |
| --- | --- |
| `System()` | The `Seam` for this machine. Version commands run with a minimal environment (PATH, HOME and the Windows basics, `LC_ALL=C`), never the caller's tokens. |
| `OSRelease(ctx, s)` | Reads `/etc/os-release` on Linux, `sw_vers` on macOS, `freebsd-version` on FreeBSD and the registry on Windows. `ParseOSRelease` parses the os-release text. |
| `MachineKey(ctx, s)` | `sha256("vulnetix-machine:" + id)`, where the id is `/etc/machine-id`, `IOPlatformUUID`, `MachineGuid` or `/etc/hostid`. The raw id never leaves the process. `HashMachineID` hashes an id the caller already has. |
| `DetectPlatform(s)` | The CI system or container runtime, matching the CLI's `config.DetectPlatform`. |
| `Catalogue()`, `For(goos)`, `Lookup(name)` | The probes. A probe has a fact name, a kind, the binaries to try in order, version arguments and a version pattern, or is marked presence only. |
| `Run(ctx, s, probes, opts)` | Looks every program up on PATH, then runs version commands for the ones found, `Concurrency` at a time, each capped by `Timeout`. `OnResult` streams results as they finish. |
| `Fact` | `Name`, `Kind`, `Version`, `Binary`, plus `Path` and `Verify`, which stay on the machine. `Public()` drops them. |
| `Check(ctx, s, fact, timeout)` | Runs only the fact's stored verify command. Returns the fact with the version printed now, or `ErrGone`. |
| `FileCache(dir)`, `CacheKey` | Remembers versions by program path, size, modification time and arguments, so an upgrade is asked again. |

## Probe rules

- A version command must be safe to run on anyone's machine: no network, no update check, no first-run setup, no prompt. A program whose version flag can do any of those is presence only (`bare()`). Flutter, Leiningen, `az`, Heroku, Vercel, Netlify and Nuclei are presence only today.
- Fact names are lower-case kebab and unique. Servers key capability rules on them, so renaming one is a breaking change.
- Add a pinned output to `version_test.go` whenever the default pattern (the first dotted number) would read the wrong number.

## Checks

```sh
go vet ./... && gofmt -l . && go test -race ./...
```

## Licence

Apache-2.0. The Vulnetix CLI (AGPL-3.0) and Belai (Apache-2.0) both import it.
