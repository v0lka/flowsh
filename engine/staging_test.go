package engine

// Unit tests for the cross-command staging rule (Finding 94).

import "testing"

// TestPathKey pins the comparison key the staging rule uses: lexical
// normalisation, plus case folding only for a Windows-shaped spelling.
func TestPathKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/tmp/x", "/tmp/x"},
		{"/tmp//x", "/tmp/x"},
		{"/tmp/./x", "/tmp/x"},
		{"/tmp/sub/../x", "/tmp/x"},
		{"/tmp/X", "/tmp/X"}, // POSIX is case-sensitive
		{`C:\Temp\X`, "c:/temp/x"},
		{`C:\Temp\..\X`, "c:/x"},
	}
	for _, c := range cases {
		if got := PathKey(c.in); got != c.want {
			t.Errorf("PathKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestApplySecretStaging pins the two halves of the rule and their order.
func TestApplySecretStaging(t *testing.T) {
	read := Effect{Kind: KindFSRead, Target: ScopeOf("/etc/shadow"), Mode: ModeDirect, Certainty: CertaintyCertain}
	write := Effect{Kind: KindFSWrite, Target: ScopeOf("/tmp/x"), Mode: ModeDirect, Certainty: CertaintyCertain}

	// A command that reads a credential and writes a file stages the file.
	staged := map[string]bool{}
	stmt := []Effect{read, write}
	ApplySecretStaging(stmt, staged)
	if !stmt[1].Taint.Contains(TaintSecret) {
		t.Errorf("the write of a credential carries no secret label: %v", stmt[1].Taint)
	}
	if !staged[PathKey("/tmp/x")] {
		t.Errorf("the staged path is not recorded: %v", staged)
	}

	// A later read of that path is a secret read.
	back := []Effect{{Kind: KindFSRead, Target: ScopeOf("/tmp//x"), Mode: ModeDirect, Certainty: CertaintyCertain}}
	ApplySecretStaging(back, staged)
	if !IsSecretRead(back[0]) {
		t.Errorf("the read-back of a staged credential is not a secret source: %v", back[0].Taint)
	}

	// An archiver row that binds its operands as writes (`7z a ARCHIVE SECRET`
	// reports FSWrite over both) still handles credential material: a target
	// that names a credential location is evidence enough.
	staged = map[string]bool{}
	sevenZip := []Effect{
		{Kind: KindFSWrite, Target: ScopeOf("/tmp/x.7z", "/etc/shadow"), Mode: ModeDirect, Certainty: CertaintyCertain},
	}
	ApplySecretStaging(sevenZip, staged)
	if !staged[PathKey("/tmp/x.7z")] {
		t.Errorf("an archiver naming a credential did not stage its archive: %v", staged)
	}

	// A credential carried as data rather than read — the value came from an
	// earlier command — is staged the same way (`x=$(cat key); printf '%s' "$x"
	// > /tmp/k`): the statement's own effect carries the label.
	staged = map[string]bool{}
	carried := []Effect{
		{Kind: KindStdio, Target: ScopeBottom(), Mode: ModeDirect, Certainty: CertaintyCertain,
			Taint: TaintOf(TaintSecret, TaintUntrusted)},
		{Kind: KindFSWrite, Target: ScopeOf("/tmp/k"), Mode: ModeDirect, Certainty: CertaintyCertain},
	}
	ApplySecretStaging(carried, staged)
	if !staged[PathKey("/tmp/k")] {
		t.Errorf("a credential carried as data did not stage the write: %v", staged)
	}

	// An unknown (⊤) *label* alone is not evidence of credential material: a
	// write whose provenance is unknown must not be staged, or every unknown
	// write would be relabelled. (A ⊤-tainted *read* is a different matter: the
	// analysis already treats it as a secret source — see IsSecretRead — so the
	// write derived from it is staged by step 2, exactly as the pairing rule
	// requires.)
	staged = map[string]bool{}
	unknown := []Effect{
		{Kind: KindEnvWrite, Target: ScopeOf("Y"), Mode: ModeDirect, Certainty: CertaintyCertain,
			Taint: TaintTop()},
		{Kind: KindFSWrite, Target: ScopeOf("/tmp/k"), Mode: ModeDirect, Certainty: CertaintyCertain,
			Taint: TaintTop()},
	}
	ApplySecretStaging(unknown, staged)
	if len(staged) != 0 {
		t.Errorf("an unknown label staged %v", staged)
	}

	// A directory write stages its children: `cp -r ~/.ssh /tmp/k` writes
	// /tmp/k, and a read of /tmp/k/id_rsa reads staged material.
	staged = map[string]bool{}
	apply := []Effect{
		{Kind: KindFSRead, Target: ScopeOf("/root/.ssh"), Mode: ModeDirect, Certainty: CertaintyCertain},
		{Kind: KindFSWrite, Target: ScopeOf("/tmp/k"), Mode: ModeDirect, Certainty: CertaintyCertain},
	}
	ApplySecretStaging(apply, staged)
	child := []Effect{{Kind: KindFSRead, Target: ScopeOf("/tmp/k/id_rsa"), Mode: ModeDirect, Certainty: CertaintyCertain}}
	ApplySecretStaging(child, staged)
	if !IsSecretRead(child[0]) {
		t.Errorf("a read under a staged directory is not a secret source: %v", child[0].Taint)
	}

	// A generated-name prefix stages the names built from it: `split FILE
	// /tmp/x.` writes /tmp/x.aa while the model names only the prefix.
	staged = map[string]bool{}
	split := []Effect{
		{Kind: KindFSRead, Target: ScopeOf("/etc/shadow"), Mode: ModeDirect, Certainty: CertaintyCertain},
		{Kind: KindFSWrite, Target: ScopeOf("/tmp/x."), Mode: ModeDirect, Certainty: CertaintyCertain},
	}
	ApplySecretStaging(split, staged)
	chunk := []Effect{{Kind: KindFSRead, Target: ScopeOf("/tmp/x.aa"), Mode: ModeDirect, Certainty: CertaintyCertain}}
	ApplySecretStaging(chunk, staged)
	if !IsSecretRead(chunk[0]) {
		t.Errorf("a read of a generated chunk is not a secret source: %v", chunk[0].Taint)
	}

	// The prefix rule cannot leak across names: staging /tmp/x must not match a
	// read of /tmp/xyz.
	staged = map[string]bool{}
	exact := []Effect{
		{Kind: KindFSRead, Target: ScopeOf("/etc/shadow"), Mode: ModeDirect, Certainty: CertaintyCertain},
		{Kind: KindFSWrite, Target: ScopeOf("/tmp/x"), Mode: ModeDirect, Certainty: CertaintyCertain},
	}
	ApplySecretStaging(exact, staged)
	sibling := []Effect{{Kind: KindFSRead, Target: ScopeOf("/tmp/xyz"), Mode: ModeDirect, Certainty: CertaintyCertain}}
	ApplySecretStaging(sibling, staged)
	if IsSecretRead(sibling[0]) {
		t.Errorf("a sibling name matched a staged path: %v", sibling[0].Taint)
	}

	// Precision: a command that reads no credential stages nothing, however
	// much it writes.
	staged = map[string]bool{}
	plain := []Effect{
		{Kind: KindFSRead, Target: ScopeOf("/tmp/notes.txt"), Mode: ModeDirect, Certainty: CertaintyCertain},
		{Kind: KindFSWrite, Target: ScopeOf("/tmp/y"), Mode: ModeDirect, Certainty: CertaintyCertain},
	}
	ApplySecretStaging(plain, staged)
	if len(staged) != 0 {
		t.Errorf("a non-credential read staged %v", staged)
	}
	if plain[1].Taint.Contains(TaintSecret) {
		t.Errorf("a non-credential write is labelled secret: %v", plain[1].Taint)
	}

	// Order: the read-back consults the set as it stood before the command, so
	// a command that both reads and writes the same path does not stage its own
	// read (an archiver naming its own archive).
	staged = map[string]bool{}
	self := []Effect{
		{Kind: KindFSRead, Target: ScopeOf("/etc/shadow", "/tmp/a.tgz"), Mode: ModeDirect, Certainty: CertaintyCertain},
		{Kind: KindFSWrite, Target: ScopeOf("/tmp/a.tgz"), Mode: ModeDirect, Certainty: CertaintyCertain},
	}
	ApplySecretStaging(self, staged)
	// The scan itself is the /etc/shadow read, already a secret source; what
	// matters is that the write is staged for a LATER read, not that this
	// command's own read was relabelled by its own write.
	if !staged[PathKey("/tmp/a.tgz")] {
		t.Errorf("the archive is not staged for a later upload: %v", staged)
	}
}
