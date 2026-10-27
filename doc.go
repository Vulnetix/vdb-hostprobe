// Package hostprobe reports what a machine has installed: its OS release,
// architecture, a stable machine key, the CI or container platform it runs in,
// and one fact per tool found from a catalogue of language runtimes, package
// managers, build and test tools, browsers, container runtimes, AI servers,
// security tools and more.
//
// The Vulnetix CLI and Belai share it, so a machine reports the same facts to
// both. It is standard library only. Every system call goes through a Seam, so
// callers and tests decide what the probe may touch.
//
// A Fact carries the command that found it (Verify). Check runs only that
// command, which is how a caller re-confirms a cached fact quickly without
// sweeping the whole catalogue again.
//
// Facts are identifiers and versions. Fact.Public drops the resolved path and
// the verify command, which stay on the machine. Nothing here reads a
// credential, an environment value or a file under the user's home directory
// beyond the machine id files.
package hostprobe
