# vdb-hostprobe notes for agents

Last Updated: 2026-10-27

Purpose: one implementation of host detection for the Vulnetix CLI and Belai.
See README.md for the API.

## Rules

- Standard library only. Every system call goes through `Seam`. Never call
  `os`, `exec` or `runtime` directly outside `seam.go`.
- A version command must be safe on anyone's machine: no network, no update
  check, no first-run setup, no prompt. If in doubt, make the probe presence
  only with `bare()` and say why in a trailing comment.
- Facts are identifiers and versions. `Fact.Public()` must drop anything that
  could locate a user's files (`Path`, `Verify`). Never read a credential or an
  environment value into a fact.
- Fact names are part of the contract with vdb-site's capability catalogue
  (`api/internal/handler/testdata/host-capabilities.json`) and the website copy.
  Do not rename one; add a new probe and retire the old one in both places.
- `MachineKey` hashes with the `vulnetix-machine:` prefix. Changing it splits
  every machine in two on the server.
- No em dashes in prose or comments.

## How to add a probe

1. Add a `p(name, kind, binaries...)` line in `catalogue.go`, in its kind's
   block, most common first.
2. Version arguments with `.args(...)`. A pattern only when the default (the
   first dotted number) is wrong; use a group to anchor on a label.
3. OS-specific tools take `.on("linux")` and so on.
4. Pin any non-default pattern with a real output line in `version_test.go`.
5. If a capability should use it, add the fact to the capability catalogue in
   vdb-site and the website in the same change.

## Checks

```sh
go vet ./... && gofmt -l . && go test -race ./...
```

`gofmt -l .` must print nothing.

## Consumers

- Vulnetix CLI: `internal/scan/binaries.go` and `internal/agent/capabilities.go`,
  and `vulnetix host -o json`.
- Belai: `internal/hostprobe`, which adds sign-in state, GPUs from machineprobe
  and the three detection lanes (cache, verify, sweep).
