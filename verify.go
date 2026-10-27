package hostprobe

import (
	"context"
	"errors"
	"time"
)

// ErrGone means a fact no longer holds: the program was removed, fails to
// start, or no longer prints a version.
var ErrGone = errors.New("hostprobe: no longer present")

// Check re-confirms one fact with only its stored Verify command. It is the
// fast path for a cached fact: one process start, not a sweep. The returned
// fact carries the version printed now, which may differ from before.
//
// A fact without Verify (one received from elsewhere) is checked by looking
// its binary up on PATH again.
func Check(ctx context.Context, s Seam, f Fact, timeout time.Duration) (Fact, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if f.Verify == nil || len(f.Verify.Argv) == 0 {
		if f.Binary == "" {
			return f, ErrGone
		}
		path, err := s.LookPath(f.Binary)
		if err != nil || path == "" {
			return f, ErrGone
		}
		f.Path = path
		return f, nil
	}
	if s.Stat != nil {
		if _, err := s.Stat(f.Verify.Argv[0]); err != nil {
			return f, ErrGone
		}
	}
	if f.Verify.Presence {
		return f, nil
	}
	out := run(ctx, s, timeout, f.Verify.Argv[0], f.Verify.Argv[1:]...)
	if len(out) == 0 {
		return f, ErrGone
	}
	v := extractVersion(out, f.Verify.Regex)
	if v == "" {
		return f, ErrGone
	}
	f.Version = v
	return f, nil
}
