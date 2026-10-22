package analysis

// Regression tests for the findings recorded in security-review.md. Each test
// reproduces the documented payload and asserts the corrected verdict, so a
// future change that reopens a finding fails here with the finding's number.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// effectOn reports whether rep carries an effect of kind whose target scope
// names want (a literal target, matched by exact value).
func effectOn(rep *Report, kind engine.EffectKind, want string) bool {
	for _, e := range rep.Effects {
		if e.Kind != kind {
			continue
		}
		if e.Target.IsTop() && want == "" {
			return true
		}
		for _, t := range e.Target.Targets() {
			if t == want {
				return true
			}
		}
	}
	return false
}

func mustEffect(t *testing.T, rep *Report, kind engine.EffectKind, target, src string) {
	t.Helper()
	if !effectOn(rep, kind, target) {
		t.Errorf("%q: missing %s on %q (effects=%v)", src, kind, target, rep.Effects)
	}
}

func mustGradeAtLeast(t *testing.T, rep *Report, want engine.Destructiveness, src string) {
	t.Helper()
	if rep.Score.Grade < want {
		t.Errorf("%q: grade %s, want >= %s (effects=%v)", src, rep.Score.Grade, want, rep.Effects)
	}
}

// TestFinding010InstallDestinationIsWrite pins F10: `install` copies file
// content, so its destination (and -t's target directory) is an FSWrite, not
// metadata — parity with cp.
func TestFinding010InstallDestinationIsWrite(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`install evil /etc/passwd`,
		`install -m 755 evil /etc/passwd`,
		`cp evil /etc/passwd`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSWrite, "/etc/passwd", src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}
	rep := a.Analyze(LangBash, `install -t /etc/cron.d evil`)
	mustEffect(t, rep, engine.KindFSWrite, "/etc/cron.d", `install -t /etc/cron.d evil`)
}

// TestFinding012CompressorsWrite pins F12: compressing rewrites the input (it
// creates the archive and removes the original), so the operand carries an
// FSWrite in every single-file compressor, not only in the flag spellings.
func TestFinding012CompressorsWrite(t *testing.T) {
	a := mustAnalyzer(t)
	cases := []struct{ src, target string }{
		{`gzip -r /home/victim`, "/home/victim"},
		{`gzip /home/victim`, "/home/victim"},
		{`gunzip /home/victim/a.gz`, "/home/victim/a.gz"},
		{`bzip2 /home/victim`, "/home/victim"},
		{`bunzip2 /home/victim/a.bz2`, "/home/victim/a.bz2"},
		{`xz /home/victim`, "/home/victim"},
		{`unxz /home/victim/a.xz`, "/home/victim/a.xz"},
		{`zstd /home/victim`, "/home/victim"},
		{`compress /home/victim`, "/home/victim"},
		{`uncompress /home/victim/a.Z`, "/home/victim/a.Z"},
	}
	for _, c := range cases {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSWrite, c.target, c.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
	}
	// The decompress flags keep their write effect.
	rep := a.Analyze(LangBash, `gzip -d /home/victim/a.gz`)
	mustEffect(t, rep, engine.KindFSWrite, "/home/victim/a.gz", `gzip -d`)
}

// TestFinding057DiskutilEraseVerbs pins F57: the whole-disk erase verbs are
// declared FSWrite and destructive, so they cannot fall through to the
// read-only list/info siblings or to DEVICE metadata.
func TestFinding057DiskutilEraseVerbs(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`diskutil zeroDisk /dev/disk2`,
		`diskutil randomDisk /dev/disk2`,
		`diskutil secureErase /dev/disk2`,
		`diskutil eraseDisk JHFS+ x /dev/disk2`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSWrite, "/dev/disk2", src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}
	for _, src := range []string{`diskutil list`, `diskutil info /dev/disk2`} {
		rep := a.Analyze(LangBash, src)
		if hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: read-only verb reported a write: %v", src, rep.Effects)
		}
	}
}

// TestFinding075RimrafDeletes pins F75: rimraf's operand is content deletion
// (FSWrite), matching rm -rf, and the same convention applies to rename's
// default overwrite and ln -f's replacement.
func TestFinding075RimrafDeletes(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`rimraf /home/victim/project`,
		`npx rimraf /home/victim/project`,
		`rm -rf /home/victim/project`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSWrite, "/home/victim/project", src)
		// Grade parity with the rm -rf twin is what the finding's fix (c) asks
		// for: a grade-keyed policy must not treat the two spellings differently.
		if rep.Score.Grade != engine.DestructCritical {
			t.Errorf("%q: grade %s, want Critical (parity with rm -rf, effects=%v)",
				src, rep.Score.Grade, rep.Effects)
		}
	}
	rep := a.Analyze(LangBash, `ln -f a b`)
	mustEffect(t, rep, engine.KindFSWrite, "b", `ln -f a b`)
	rep = a.Analyze(LangBash, `rename x y file`)
	mustEffect(t, rep, engine.KindFSWrite, "file", `rename x y file`)
}
