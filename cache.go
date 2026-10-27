package hostprobe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// VersionCache remembers the version a program printed. Keys come from
// CacheKey, so an upgraded program (a new file, size or time) is asked again.
type VersionCache interface {
	Get(key string) (string, bool)
	Put(key, version string)
}

// CacheKey identifies one program file and the arguments that printed its
// version.
func CacheKey(path string, info fs.FileInfo, args []string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%d\x00%s", path, info.Size(), info.ModTime().UnixNano(), strings.Join(args, "\x00"))))
	return hex.EncodeToString(sum[:16])
}

// FileCache keeps one small file per key in dir, written atomically. An empty
// dir disables it.
func FileCache(dir string) VersionCache {
	return fileCache(dir)
}

type fileCache string

func (c fileCache) Get(key string) (string, bool) {
	if c == "" || !validKey(key) {
		return "", false
	}
	b, err := os.ReadFile(filepath.Join(string(c), key))
	if err != nil || len(b) == 0 || len(b) > 64 {
		return "", false
	}
	return string(b), true
}

func (c fileCache) Put(key, version string) {
	if c == "" || !validKey(key) || version == "" {
		return
	}
	if os.MkdirAll(string(c), 0o700) != nil {
		return
	}
	tmp, err := os.CreateTemp(string(c), ".tmp-*")
	if err != nil {
		return
	}
	_, werr := tmp.WriteString(version)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), filepath.Join(string(c), key)) != nil {
		_ = os.Remove(tmp.Name())
	}
}

func validKey(k string) bool {
	if len(k) != 32 {
		return false
	}
	_, err := hex.DecodeString(k)
	return err == nil
}
