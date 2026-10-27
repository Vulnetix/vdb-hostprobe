package hostprobe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// keyPrefix separates this hash from any other use of the machine id. The
// CLI and Belai hash with the same prefix, so one machine has one key.
const keyPrefix = "vulnetix-machine:"

// MachineKey is a stable, anonymous key for this machine: the hex SHA-256 of
// the platform's machine id. The raw id never leaves the process. It is ""
// when no usable id is found, for example in a container without
// /etc/machine-id.
//
// Linux: /etc/machine-id, then /var/lib/dbus/machine-id. macOS:
// IOPlatformUUID from ioreg. Windows: MachineGuid from the registry. FreeBSD:
// /etc/hostid.
func MachineKey(ctx context.Context, s Seam) string {
	return HashMachineID(machineID(ctx, s))
}

// HashMachineID turns a raw platform id into the key. Exported so a caller
// that has the id from elsewhere (a container's injected id) keys it the same
// way. It returns "" for an empty or placeholder id.
func HashMachineID(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if len(id) < 8 || strings.Trim(id, "0-") == "" || id == "uninitialized" {
		return ""
	}
	sum := sha256.Sum256([]byte(keyPrefix + id))
	return hex.EncodeToString(sum[:])
}

func machineID(ctx context.Context, s Seam) string {
	switch s.GOOS {
	case "linux":
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if b, err := s.ReadFile(p); err == nil {
				if id := strings.TrimSpace(string(b)); id != "" {
					return id
				}
			}
		}
	case "freebsd":
		if b, err := s.ReadFile("/etc/hostid"); err == nil {
			return strings.TrimSpace(string(b))
		}
	case "darwin":
		out := run(ctx, s, 3*time.Second, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(line, "IOPlatformUUID") {
				continue
			}
			if _, v, ok := strings.Cut(line, "="); ok {
				return strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
	case "windows":
		return regValue(run(ctx, s, 3*time.Second, "reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid"), "MachineGuid")
	}
	return ""
}
