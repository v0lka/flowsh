package kb

import (
	"os"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/v0lka/flowsh/engine"
)

// mustLoad loads the embedded knowledge base or fails the test.
func mustLoad(t *testing.T) *KB {
	t.Helper()
	k, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return k
}

// loadSrc loads an in-memory document set (names are relative to the data dir).
func loadSrc(files map[string]string) (*KB, error) {
	fsys := fstest.MapFS{}
	for name, body := range files {
		fsys["data/"+name] = &fstest.MapFile{Data: []byte(body)}
	}
	return loadFS(fsys, "data")
}

// ---------------------------------------------------------------------------
// Loading, coverage and size
// ---------------------------------------------------------------------------

// TestEmbeddedLoad proves the acceptance criterion "the KB loads from go:embed
// with at least 40 commands, each carrying per-flag effects".
func TestEmbeddedLoad(t *testing.T) {
	k := mustLoad(t)

	if k.Version != SchemaVersion {
		t.Errorf("version = %q, want %q", k.Version, SchemaVersion)
	}
	if len(k.Commands) < 40 {
		t.Fatalf("got %d commands, want at least 40", len(k.Commands))
	}
	if len(k.Destructive) == 0 {
		t.Fatal("destructive table is empty")
	}

	commandParams := 0
	for _, c := range k.Commands {
		if len(c.Params) == 0 {
			t.Errorf("command %q has no params", c.Name)
			continue
		}
		commandParams += len(c.Params)
		for _, p := range c.Params {
			if err := p.Effect.Validate(); err != nil {
				t.Errorf("command %q param %q: %v", c.Name, p.Spec, err)
			}
		}
	}
	if commandParams < 40 {
		t.Errorf("only %d param effects total, want at least one per command", commandParams)
	}
	t.Logf("%d commands, %d param effects, %d destructive entries",
		len(k.Commands), commandParams, len(k.Destructive))
}

// TestEmbeddedDocuments proves the data really comes from multiple embedded
// files (not a single hard-coded blob).
func TestEmbeddedDocuments(t *testing.T) {
	names, err := EmbeddedFiles()
	if err != nil {
		t.Fatalf("EmbeddedFiles: %v", err)
	}
	if len(names) < 4 {
		t.Errorf("got %d embedded documents, want several: %v", len(names), names)
	}
	for _, n := range names {
		if !strings.HasSuffix(n, ".yaml") {
			t.Errorf("embedded document %q is not a .yaml file", n)
		}
	}
	t.Logf("embedded documents: %v", names)
}

// TestLoadUnderBudget proves the acceptance criterion "loads from go:embed
// within a fixed budget and with no external files".
//
// The budget is a smoke test for the design property — a hermetic, in-memory
// load with no disk I/O — not a benchmark of the host. Every Load() re-parses
// the dataset and allocates ~7 MB across ~70k objects, so the average over 50
// runs is dominated by GC, and the shared CI runners (2 vCPU) are several times
// slower than a developer machine. The value is therefore generous enough to
// hold on all three CI OSes while still failing an order-of-magnitude regression
// or any accidental disk I/O. See ADR-0011.
func TestLoadUnderBudget(t *testing.T) {
	if raceDetectorEnabled {
		t.Skip("wall-clock load budget is not meaningful under the race detector")
	}
	const budget = 50 * time.Millisecond
	const runs = 50

	var min, total time.Duration
	for i := 0; i < runs; i++ {
		start := time.Now()
		k, err := Load()
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if k == nil {
			t.Fatal("Load returned a nil KB")
		}
		if min == 0 || elapsed < min {
			min = elapsed
		}
		total += elapsed
	}
	avg := total / runs
	t.Logf("Load(): min=%v avg=%v over %d runs (budget %v)", min, avg, runs, budget)
	if min > budget {
		t.Errorf("fastest Load() = %v, want < %v", min, budget)
	}
	if avg > budget {
		t.Errorf("average Load() = %v, want < %v", avg, budget)
	}
}

// TestLoadCRLFTolerant proves the YAML reader tolerates CRLF line endings, so a
// Windows checkout (core.autocrlf=true) cannot break the embedded load. It uses
// the bare `key:` form — a mapping key with an empty block value — which a naive
// CRLF read would mis-parse as `key:\r` and reject with "expected `key: value`".
func TestLoadCRLFTolerant(t *testing.T) {
	const lf = "version: effect-kb/v2\n" +
		"commands:\n" +
		"  - name: x\n" +
		"    dialect: posix\n" +
		"    params:\n" +
		"      - spec: \"-a\"\n" +
		"        kind: flag\n" +
		"        effect: {kind: FSRead, mode: Direct, valueFrom: args}\n"
	crlf := strings.ReplaceAll(lf, "\n", "\r\n")

	k, err := loadSrc(map[string]string{"crlf.yaml": crlf})
	if err != nil {
		t.Fatalf("CRLF document rejected: %v", err)
	}
	c, ok := k.Command("x")
	if !ok {
		t.Fatal("command x not found in the CRLF document")
	}
	if len(c.Params) != 1 || c.Params[0].Spec != "-a" {
		t.Fatalf("CRLF document decoded incorrectly: %+v", c.Params)
	}
}

// TestLoadNeedsNoExternalFiles moves to an empty directory and loads again: the
// embedded FS must be self-sufficient.
func TestLoadNeedsNoExternalFiles(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(old); err != nil {
			t.Fatal(err)
		}
	}()

	k, err := Load()
	if err != nil {
		t.Fatalf("Load from a foreign working directory: %v", err)
	}
	if len(k.Commands) < 40 {
		t.Fatalf("got %d commands, want at least 40", len(k.Commands))
	}
}

// TestDefaultCaches proves Default parses once and returns a stable value.
func TestDefaultCaches(t *testing.T) {
	a, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	b, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if a != b {
		t.Errorf("Default returned different instances across calls")
	}
}

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

// TestVersionValidation proves the acceptance criterion "the schema version is
// checked; an unknown version is an explicit error".
func TestVersionValidation(t *testing.T) {
	const goodDoc = `version: effect-kb/v2
commands:
  - name: x
    dialect: posix
    params:
      - spec: "-a"
        kind: flag
        effect: {kind: FSRead, mode: Direct, valueFrom: args}
`
	if _, err := loadSrc(map[string]string{"a.yaml": goodDoc}); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}

	// Unknown version: the error must name the offending version.
	_, err := loadSrc(map[string]string{"a.yaml": "version: effect-kb/v999\ncommands: []\n"})
	if err == nil {
		t.Fatal("expected an error for an unknown schema version")
	}
	if !strings.Contains(err.Error(), "effect-kb/v999") {
		t.Errorf("error should name the unknown version, got: %v", err)
	}
	if !strings.Contains(err.Error(), "unsupported schema version") {
		t.Errorf("error should say the version is unsupported, got: %v", err)
	}

	// Missing version.
	_, err = loadSrc(map[string]string{"a.yaml": "commands: []\n"})
	if err == nil || !strings.Contains(err.Error(), "missing schema version") {
		t.Errorf("expected a missing-version error, got: %v", err)
	}

	// No documents at all.
	fsys := fstest.MapFS{"data/notes.txt": &fstest.MapFile{Data: []byte("hi")}}
	if _, err := loadFS(fsys, "data"); err == nil || !strings.Contains(err.Error(), "no *.yaml documents") {
		t.Errorf("expected a no-documents error, got: %v", err)
	}

	// A second document disagreeing with the first is rejected.
	old := KnownVersions
	KnownVersions = []string{SchemaVersion, "effect-kb/v3"}
	defer func() { KnownVersions = old }()
	if _, err := loadSrc(map[string]string{
		"a.yaml": "version: effect-kb/v2\ncommands: []\n",
		"b.yaml": "version: effect-kb/v3\ncommands: []\n",
	}); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Errorf("expected a version-conflict error, got: %v", err)
	}
}

func TestKnown(t *testing.T) {
	if !Known(SchemaVersion) {
		t.Errorf("Known(%q) = false, want true", SchemaVersion)
	}
	if Known("effect-kb/v0") {
		t.Error("Known accepted an undefined version")
	}
}

// ---------------------------------------------------------------------------
// Destructive table
// ---------------------------------------------------------------------------

// TestDestructiveClassETable is the acceptance test-table: at least ten
// destructive cases of class E, each resolved by (command, spec).
func TestDestructiveClassETable(t *testing.T) {
	k := mustLoad(t)

	cases := []struct {
		command string
		spec    string
	}{
		{"find", "-delete"},
		{"dd", "of="},
		{"tar", "-C"},
		{"tar", "-x"},
		{"install", "-m"},
		{"sed", "-i"},
		{"rm", "-r"},
		{"rm", "-f"},
		{"shred", "FILE"},
		{"truncate", "-s"},
		{"wipefs", "-a"},
		{"mkfs.ext4", "DEVICE"},
		{"fdisk", "DEVICE"},
		{"git", "clean"},
		{"git", "--hard"},
		{"rsync", "--delete"},
	}
	if len(cases) < 10 {
		t.Fatalf("the class-E table must have at least 10 entries, has %d", len(cases))
	}
	for _, tc := range cases {
		d, ok := k.DestructiveFor(tc.command, tc.spec)
		if !ok {
			t.Errorf("no destructive entry for %s %s", tc.command, tc.spec)
			continue
		}
		if d.Class != ClassCritical {
			t.Errorf("%s %s: class = %s, want E", tc.command, tc.spec, d.Class)
		}
		if d.Reason == "" {
			t.Errorf("%s %s: empty reason", tc.command, tc.spec)
		}
	}

	// The attribute form of "at least ten class-E cases".
	nE := 0
	for _, d := range k.Destructive {
		if d.Class == ClassCritical {
			nE++
		}
	}
	if nE < 10 {
		t.Errorf("got %d class-E entries, want at least 10", nE)
	}

	// Every class E entry must map to the core's top destructiveness.
	if got := ClassCritical.Severity(); got != engine.DestructCritical {
		t.Errorf("class E severity = %v, want %v", got, engine.DestructCritical)
	}
}

// TestDestructiveCuratedB10 pins the destructive flags surfaced by the B1-B9
// knowledge-base expansion (roadmap B10): every curated (command, spec) must
// resolve to an entry of the expected class with a non-empty reason.
func TestDestructiveCuratedB10(t *testing.T) {
	k := mustLoad(t)

	cases := []struct {
		command string
		spec    string
		class   DestructiveClass
	}{
		{"chattr", "-R", ClassHigh},
		{"setfacl", "-R", ClassHigh},
		{"iptables", "-F", ClassHigh},
		{"nft", "flush", ClassHigh},
		{"launchctl", "unload", ClassMedium},
		{"diskutil", "eraseDisk", ClassCritical},
		{"crontab", "-r", ClassHigh},
		{"systemctl", "disable", ClassHigh},
		{"pip", "uninstall", ClassMedium},
		{"npm", "uninstall", ClassMedium},
		{"parted", "rm", ClassCritical},
		{"sgdisk", "-Z", ClassCritical},
		{"mdadm", "--zero-superblock", ClassCritical},
		{"swapoff", "-a", ClassMedium},
		{"dd", "of=", ClassCritical},
	}
	for _, tc := range cases {
		d, ok := k.DestructiveFor(tc.command, tc.spec)
		if !ok {
			t.Errorf("B10: no destructive entry for %s %s", tc.command, tc.spec)
			continue
		}
		if d.Class != tc.class {
			t.Errorf("B10: %s %s class = %s, want %s", tc.command, tc.spec, d.Class, tc.class)
		}
		if d.Reason == "" {
			t.Errorf("B10: %s %s: empty reason", tc.command, tc.spec)
		}
	}
}

// TestDestructiveIntegrity checks that every destructive entry refers to a
// parameter actually declared by the named command.
func TestDestructiveIntegrity(t *testing.T) {
	k := mustLoad(t)
	for _, d := range k.Destructive {
		cmd, ok := k.Command(d.Command)
		if !ok {
			t.Errorf("destructive %s %s: unknown command", d.Command, d.Spec)
			continue
		}
		if !cmd.HasParam(d.Spec) {
			t.Errorf("destructive %s %s: param not declared on the command", d.Command, d.Spec)
		}
	}
}

// TestDestructiveClassesProduceSeverities pins the class → lattice mapping.
func TestDestructiveClassesProduceSeverities(t *testing.T) {
	want := map[DestructiveClass]engine.Destructiveness{
		ClassNone:     engine.DestructNone,
		ClassLow:      engine.DestructLow,
		ClassMedium:   engine.DestructMedium,
		ClassHigh:     engine.DestructHigh,
		ClassCritical: engine.DestructCritical,
	}
	for c, sev := range want {
		if got := c.Severity(); got != sev {
			t.Errorf("class %s severity = %v, want %v", c, got, sev)
		}
	}
}

// ---------------------------------------------------------------------------
// Coverage and lookup
// ---------------------------------------------------------------------------

// TestDialectCoverage proves every family named by the dataset is represented.
func TestDialectCoverage(t *testing.T) {
	k := mustLoad(t)
	have := map[Dialect]int{}
	for _, c := range k.Commands {
		have[c.Dialect]++
	}
	for _, d := range Dialects {
		if have[d] == 0 {
			t.Errorf("no command with dialect %q", d)
		}
	}
}

// TestAliasLookup proves commands resolve by every declared alias.
func TestAliasLookup(t *testing.T) {
	k := mustLoad(t)
	cases := []struct{ alias, want string }{
		{"remove", "rm"},
		{"netcat", "nc"},
		{"typeset", "declare"},
		{".", "source"},
		{"[", "test"},
	}
	for _, tc := range cases {
		c, ok := k.Command(tc.alias)
		if !ok {
			t.Errorf("alias %q did not resolve", tc.alias)
			continue
		}
		if c.Name != tc.want {
			t.Errorf("alias %q resolved to %q, want %q", tc.alias, c.Name, tc.want)
		}
	}
}

// TestCommandNamesSorted proves the canonical order is deterministic.
func TestCommandNamesSorted(t *testing.T) {
	k := mustLoad(t)
	names := k.CommandNames()
	if !sort.StringsAreSorted(names) {
		t.Error("CommandNames is not sorted")
	}
	for i := 1; i < len(names); i++ {
		if names[i] == names[i-1] {
			t.Errorf("duplicate command name %q", names[i])
		}
	}
}

// TestSpotCheckEntries pins a few decoded entries exactly, so a parser
// regression cannot pass silently.
func TestSpotCheckEntries(t *testing.T) {
	k := mustLoad(t)
	check := func(cmd, spec string, kind engine.EffectKind, mode engine.EffectMode, vf ValueSource) {
		t.Helper()
		c, ok := k.Command(cmd)
		if !ok {
			t.Fatalf("command %q not found", cmd)
		}
		p, ok := c.Param(spec)
		if !ok {
			t.Fatalf("command %q has no param %q", cmd, spec)
		}
		if p.Effect.Kind != kind || p.Effect.Mode != mode || p.Effect.ValueFrom != vf {
			t.Errorf("%s %s = {%s %s %s}, want {%s %s %s}",
				cmd, spec, p.Effect.Kind, p.Effect.Mode, p.Effect.ValueFrom, kind, mode, vf)
		}
	}
	check("rm", "-r", engine.KindFSWrite, engine.ModeDirect, ValueArgs)
	check("rm", "-i", engine.KindFSWrite, engine.ModeConditional, ValueArgs)
	check("dd", "of=", engine.KindFSWrite, engine.ModeDirect, ValueFlagValue)
	check("dd", "if=", engine.KindFSRead, engine.ModeDirect, ValueFlagValue)
	check("install", "-m", engine.KindPrivEsc, engine.ModeConditional, ValueFlagValue)
	check("sed", "-i", engine.KindFSWrite, engine.ModeDirect, ValueArgs)
	check("find", "-delete", engine.KindFSWrite, engine.ModeDirect, ValueArgs)
	check("tar", "-C", engine.KindFSWrite, engine.ModeDirect, ValueFlagValue)
	check("ssh", "COMMAND", engine.KindCodeExec, engine.ModeConditional, ValueArgs)
	check("git", "clean", engine.KindFSWrite, engine.ModeDirect, ValueArgs)
}

// TestCommandParamIndexMatchesScan locks the invariant behind Command.Param's
// O(1) index: after KB.build every command must answer Param/HasParam exactly
// as a linear scan over its Params would, for declared specs and for unknown
// ones. It also pins the unindexed fallback so a Command literal that never went
// through build stays usable. This guards the binder's per-token name/flag match
// against a stale or mis-built index.
func TestCommandParamIndexMatchesScan(t *testing.T) {
	k := mustLoad(t)
	if len(k.Commands) == 0 {
		t.Fatal("empty KB")
	}
	probed := 0
	for _, c := range k.Commands {
		if c.idx == nil {
			t.Fatalf("command %q has no param index after KB.build", c.Name)
		}
		for _, p := range c.Params {
			got, ok := c.Param(p.Spec)
			if !ok || got.Spec != p.Spec {
				t.Errorf("%s: Param(%q) = %q,%v; want the declared param", c.Name, p.Spec, got.Spec, ok)
			}
			if !c.HasParam(p.Spec) {
				t.Errorf("%s: HasParam(%q) = false; want true", c.Name, p.Spec)
			}
			probed++
		}
		// Unknown specs must not match; skip any that happen to be declared.
		for _, miss := range []string{"", "\x00", "-zzz-not-declared", "zzz-not-declared"} {
			declared := false
			for _, p := range c.Params {
				if p.Spec == miss {
					declared = true
					break
				}
			}
			if declared {
				continue
			}
			if _, ok := c.Param(miss); ok {
				t.Errorf("%s: Param(%q) unexpectedly matched", c.Name, miss)
			}
			if c.HasParam(miss) {
				t.Errorf("%s: HasParam(%q) unexpectedly matched", c.Name, miss)
			}
		}

		// AssignParams must be exactly the ParamAssign subset, in order.
		var wantAssign []string
		for _, p := range c.Params {
			if p.Kind == ParamAssign {
				wantAssign = append(wantAssign, p.Spec)
			}
		}
		if got := c.AssignParams(); len(got) != len(wantAssign) {
			t.Errorf("%s: AssignParams = %d entries, want %d", c.Name, len(got), len(wantAssign))
		} else {
			for i := range wantAssign {
				if got[i].Spec != wantAssign[i] {
					t.Errorf("%s: AssignParams[%d] = %q, want %q", c.Name, i, got[i].Spec, wantAssign[i])
				}
			}
		}
	}
	if probed == 0 {
		t.Fatal("no params probed")
	}
}

// TestCommandParamUnindexedFallback proves Param/HasParam still work on a
// Command that never went through KB.build (idx == nil), so hand-built Command
// literals — common in unit tests — keep their linear-scan behaviour.
func TestCommandParamUnindexedFallback(t *testing.T) {
	c := Command{Name: "x", Dialect: DialectPOSIX, Params: []Param{
		{Spec: "-x", Kind: ParamFlag},
		{Spec: "FILE", Kind: ParamPositional},
	}}
	if c.idx != nil {
		t.Fatal("zero-value Command should have a nil index")
	}
	if _, ok := c.Param("-x"); !ok {
		t.Error("unindexed Param missed a declared spec")
	}
	if !c.HasParam("FILE") {
		t.Error("unindexed HasParam missed a declared spec")
	}
	if _, ok := c.Param("-missing"); ok {
		t.Error("unindexed Param matched an unknown spec")
	}
	if c.HasParam("-missing") {
		t.Error("unindexed HasParam matched an unknown spec")
	}

	c.buildIndex()
	if c.idx == nil {
		t.Fatal("buildIndex left idx nil")
	}
	if _, ok := c.Param("FILE"); !ok {
		t.Error("indexed Param missed a declared spec")
	}
	if c.HasParam("-missing") {
		t.Error("indexed HasParam matched an unknown spec")
	}
}

// TestEffectsLowerToCore proves every KB effect is expressible in the frozen
// core IR.
func TestEffectsLowerToCore(t *testing.T) {
	k := mustLoad(t)
	for _, c := range k.Commands {
		for _, p := range c.Params {
			e := p.Effect.EngineEffect(engine.ScopeOf("target"), engine.TaintBottom(), engine.CertaintyCertain)
			if err := e.Validate(); err != nil {
				t.Errorf("%s %s: %v", c.Name, p.Spec, err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Parser subset and error paths
// ---------------------------------------------------------------------------

func TestParserSubset(t *testing.T) {
	doc := `version: effect-kb/v2
# a whole-line comment
commands:
  - name: demo
    dialect: posix
    aliases: [alpha, beta]   # trailing comment
    params:
      - spec: "-x"    # inline comment
        kind: flag
        effect: {kind: FSRead, mode: Direct, valueFrom: args}
      - spec: "of="
        kind: assign
        effect:
          kind: FSWrite
          mode: Direct
          valueFrom: flagValue
`
	k, err := loadSrc(map[string]string{"a.yaml": doc})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	c, ok := k.Command("demo")
	if !ok {
		t.Fatal("command demo not found")
	}
	if got := strings.Join(c.Aliases, ","); got != "alpha,beta" {
		t.Errorf("aliases = %q, want alpha,beta", got)
	}
	if p, ok := c.Param("of="); !ok || p.Effect.Kind != engine.KindFSWrite {
		t.Errorf("flow/block effect decoded wrongly: %+v", p)
	}
	if p, ok := c.Param("-x"); !ok || p.Effect.Mode != engine.ModeDirect {
		t.Errorf("inline-comment param decoded wrongly: %+v", p)
	}
}

func TestParserErrors(t *testing.T) {
	base := "version: effect-kb/v2\n"
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "tab indentation",
			doc:  "version: effect-kb/v2\ncommands:\n\t- name: x\n",
			want: "tab indentation",
		},
		{
			name: "unknown top-level key",
			doc:  base + "bogus: 1\n",
			want: "unknown top-level key",
		},
		{
			name: "unknown command key",
			doc:  base + "commands:\n  - name: x\n    dialect: posix\n    bogus: 1\n",
			want: "unknown key",
		},
		{
			name: "unknown param key",
			doc:  base + "commands:\n  - name: x\n    dialect: posix\n    params:\n      - spec: \"-a\"\n        bogus: 1\n",
			want: "unknown key",
		},
		{
			name: "duplicate key",
			doc:  base + "commands:\n  - name: x\n    name: y\n    dialect: posix\n",
			want: "duplicate key",
		},
		{
			name: "unterminated quote",
			doc:  base + "commands:\n  - name: \"x\n    dialect: posix\n",
			want: "unterminated",
		},
		{
			name: "duplicate command name",
			doc: base + "commands:\n  - name: x\n    dialect: posix\n    params:\n      - spec: \"-a\"\n        kind: flag\n        effect: {kind: FSRead, mode: Direct, valueFrom: args}\n" +
				"  - name: x\n    dialect: posix\n    params:\n      - spec: \"-b\"\n        kind: flag\n        effect: {kind: FSRead, mode: Direct, valueFrom: args}\n",
			want: "duplicate command name/alias",
		},
		{
			name: "duplicate alias",
			doc: base + "commands:\n  - name: x\n    dialect: posix\n    aliases: [z]\n    params:\n      - spec: \"-a\"\n        kind: flag\n        effect: {kind: FSRead, mode: Direct, valueFrom: args}\n" +
				"  - name: y\n    dialect: posix\n    aliases: [z]\n    params:\n      - spec: \"-b\"\n        kind: flag\n        effect: {kind: FSRead, mode: Direct, valueFrom: args}\n",
			want: "duplicate command name/alias",
		},
		{
			name: "invalid dialect",
			doc:  base + "commands:\n  - name: x\n    dialect: nope\n    params:\n      - spec: \"-a\"\n        kind: flag\n        effect: {kind: FSRead, mode: Direct, valueFrom: args}\n",
			want: "invalid dialect",
		},
		{
			name: "invalid effect kind",
			doc:  base + "commands:\n  - name: x\n    dialect: posix\n    params:\n      - spec: \"-a\"\n        kind: flag\n        effect: {kind: Nope, mode: Direct, valueFrom: args}\n",
			want: "invalid effect kind",
		},
		{
			name: "invalid valueFrom",
			doc:  base + "commands:\n  - name: x\n    dialect: posix\n    params:\n      - spec: \"-a\"\n        kind: flag\n        effect: {kind: FSRead, mode: Direct, valueFrom: nowhere}\n",
			want: "invalid valueFrom",
		},
		{
			name: "flag spec without dash",
			doc:  base + "commands:\n  - name: x\n    dialect: posix\n    params:\n      - spec: \"a\"\n        kind: flag\n        effect: {kind: FSRead, mode: Direct, valueFrom: args}\n",
			want: "requires a spec starting with",
		},
		{
			name: "command without params",
			doc:  base + "commands:\n  - name: x\n    dialect: posix\n",
			want: "no params",
		},
		{
			name: "destructive refers to missing param",
			doc: base + "commands:\n  - name: x\n    dialect: posix\n    params:\n      - spec: \"-a\"\n        kind: flag\n        effect: {kind: FSRead, mode: Direct, valueFrom: args}\n" +
				"destructive:\n  - command: x\n    spec: \"-z\"\n    class: E\n    reason: nope\n",
			want: "not declared on the command",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadSrc(map[string]string{"a.yaml": tc.doc})
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestValidateRejectsBrokenKB exercises KB.Validate directly.
func TestValidateRejectsBrokenKB(t *testing.T) {
	k := &KB{Version: "effect-kb/v2", Commands: []Command{{Name: "x", Dialect: DialectPOSIX}}}
	if err := k.Validate(); err == nil {
		t.Error("expected validation error for a command with no params")
	}
	k = &KB{Version: "nope"}
	if err := k.Validate(); err == nil {
		t.Error("expected validation error for an unknown version")
	}
}

// ---------------------------------------------------------------------------
// fileRef (@file) marker
// ---------------------------------------------------------------------------

// TestFileRefMarker proves the @file marker is part of the schema v2: it parses
// into Effect.FileRef, and a parameter that does not declare it stays false.
func TestFileRefMarker(t *testing.T) {
	doc := `version: effect-kb/v2
commands:
  - name: upload
    dialect: curl
    params:
      - spec: "-d"
        kind: option
        effect: {kind: NetEgress, mode: Direct, valueFrom: flagValue, fileRef: true}
      - spec: "-H"
        kind: option
        effect: {kind: NetEgress, mode: Direct, valueFrom: flagValue}
`
	k, err := loadSrc(map[string]string{"a.yaml": doc})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	c, ok := k.Command("upload")
	if !ok {
		t.Fatal("command upload not found")
	}
	if p, ok := c.Param("-d"); !ok || !p.Effect.FileRef {
		t.Errorf("-d must carry fileRef: %+v", p)
	}
	if p, ok := c.Param("-H"); !ok || p.Effect.FileRef {
		t.Errorf("-H must not carry fileRef: %+v", p)
	}
}

// TestFileRefValidation rejects the marker where it cannot apply and a spelling
// that is not a boolean.
func TestFileRefValidation(t *testing.T) {
	base := "version: effect-kb/v2\n"
	cases := []struct {
		name, doc, want string
	}{
		{
			name: "requires flagValue",
			doc:  base + "commands:\n  - name: x\n    dialect: posix\n    params:\n      - spec: \"-a\"\n        kind: flag\n        effect: {kind: FSRead, mode: Direct, valueFrom: args, fileRef: true}\n",
			want: "fileRef requires valueFrom",
		},
		{
			name: "must be a boolean",
			doc:  base + "commands:\n  - name: x\n    dialect: posix\n    params:\n      - spec: \"-a\"\n        kind: option\n        effect: {kind: FSRead, mode: Direct, valueFrom: flagValue, fileRef: maybe}\n",
			want: "must be true or false",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadSrc(map[string]string{"a.yaml": tc.doc}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestEmbeddedFileRefParams guards the embedded dataset: curl's data-carrying
// flags use the @file convention; its header flag does not.
func TestEmbeddedFileRefParams(t *testing.T) {
	k := mustLoad(t)
	c, ok := k.Command("curl")
	if !ok {
		t.Fatal("curl not in the knowledge base")
	}
	for _, spec := range []string{"-d", "--data", "--data-binary", "-F", "--form"} {
		p, ok := c.Param(spec)
		if !ok || !p.Effect.FileRef {
			t.Errorf("curl %s must carry fileRef: %+v", spec, p)
		}
	}
	if p, ok := c.Param("-H"); !ok || p.Effect.FileRef {
		t.Errorf("curl -H must not carry fileRef: %+v", p)
	}
}
