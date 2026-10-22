package kb

// ===========================================================================
// Finding 86 — a parameter may declare two independent effects
// ===========================================================================
//
// A single command word frequently carries two effects at once: a package
// manager's `install`/`add`/`update` subcommand both reaches a registry
// (NetEgress) and rewrites the local store or manifest (FSWrite), and a VCS
// `update`/`sync` both fetches and rewrites the working copy. The v2 schema
// held exactly one effect per parameter, so every such row had to drop one half
// and every deny rule keyed on the dropped kind admitted the operation.
//
// v3 adds the optional `also` list. These tests pin the schema surface: the
// field parses, both entries are validated, and the declarations that would
// make lowering ambiguous (a duplicate kind, a secondary `fileRef`) are
// rejected at load time rather than silently mis-lowered.

import (
	"strings"
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestParamAlsoParses proves the `also` list round-trips through the
// hand-written loader: the primary stays where it was and every secondary is
// decoded with its own kind, mode and value source.
func TestParamAlsoParses(t *testing.T) {
	k, err := loadSrc(map[string]string{"a.yaml": `version: effect-kb/v3
commands:
  - name: pm
    dialect: pkgmgr
    params:
      - spec: install
        kind: positional
        effect: {kind: NetEgress, mode: Direct, valueFrom: args}
        also:
          - kind: FSWrite
            mode: Direct
            valueFrom: args
`})
	if err != nil {
		t.Fatalf("loadSrc: %v", err)
	}
	c, ok := k.Command("pm")
	if !ok {
		t.Fatal("command pm not loaded")
	}
	p := c.Params[0]
	if p.Effect.Kind != engine.KindNetEgress {
		t.Errorf("primary = %s, want NetEgress", p.Effect.Kind)
	}
	if len(p.Also) != 1 {
		t.Fatalf("also len = %d, want 1", len(p.Also))
	}
	if got := p.Also[0]; got.Kind != engine.KindFSWrite || got.Mode != engine.ModeDirect || got.ValueFrom != ValueArgs {
		t.Errorf("also[0] = %+v, want FSWrite/Direct/args", got)
	}
}

// TestParamAlsoValidation pins the three declarations that would make a
// parameter's effect list ambiguous or contradictory. Each is a load error, so
// a data edit cannot introduce it silently.
func TestParamAlsoValidation(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{
			name: "duplicate kind",
			body: `      - spec: install
        kind: positional
        effect: {kind: FSWrite, mode: Direct, valueFrom: args}
        also:
          - kind: FSWrite
            mode: Direct
            valueFrom: args
`,
			want: "duplicate effect kind",
		},
		{
			name: "secondary fileRef",
			body: `      - spec: "-d"
        kind: option
        effect: {kind: FSRead, mode: Direct, valueFrom: flagValue}
        also:
          - kind: FSWrite
            mode: Direct
            valueFrom: flagValue
            fileRef: true
`,
			want: "fileRef belongs to the primary effect only",
		},
		{
			name: "invalid kind",
			body: `      - spec: install
        kind: positional
        effect: {kind: FSWrite, mode: Direct, valueFrom: args}
        also:
          - kind: NotAnEffect
            mode: Direct
            valueFrom: args
`,
			want: "invalid effect kind",
		},
		{
			name: "also is a scalar",
			body: `      - spec: install
        kind: positional
        effect: {kind: FSWrite, mode: Direct, valueFrom: args}
        also: FSWrite
`,
			want: "`also` must be a sequence",
		},
	} {
		_, err := loadSrc(map[string]string{"a.yaml": "version: effect-kb/v3\ncommands:\n  - name: pm\n    dialect: pkgmgr\n    params:\n" + c.body})
		if err == nil {
			t.Errorf("%s: expected a load error, got nil", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

// TestPackageInstallDeclaresBothEffects is the mechanical invariant behind
// Finding 86, applied to the whole shipped knowledge base: every package
// manager/toolchain subcommand that installs, adds, updates or otherwise
// resolves packages must declare both the local write and the registry egress.
// A new row — or a row edited to a single effect — fails here instead of
// silently re-opening the class.
//
// The two documented exceptions are index refreshes, which the KB's own
// modelling doctrine classifies as network operations (they rewrite only the
// package index, not the installed store); they are listed explicitly so a new
// exception cannot be added without this test noticing.
func TestPackageInstallDeclaresBothEffects(t *testing.T) {
	verbs := map[string]bool{
		"install": true, "add": true, "update": true, "upgrade": true,
		"reinstall": true, "inject": true, "restore": true, "require": true,
		"ci": true, "sync": true, "lock": true, "workload": true,
		"component": true, "target": true,
	}
	// Documented exceptions: an index/metadata refresh is NetEgress by doctrine.
	exceptions := map[[2]string]string{
		{"apt", "update"}: "index refresh (NetEgress by doctrine)",
		{"apk", "update"}: "index refresh (NetEgress by doctrine)",
	}
	k, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	seenExceptions := 0
	for _, name := range k.CommandNames() {
		c, _ := k.Command(name)
		if c.Dialect != DialectPkgmgr {
			continue
		}
		for _, p := range c.Params {
			if p.Kind != ParamPositional || !verbs[p.Spec] {
				continue
			}
			if why, ok := exceptions[[2]string{c.Name, p.Spec}]; ok {
				seenExceptions++
				_ = why
				continue
			}
			kinds := map[engine.EffectKind]bool{p.Effect.Kind: true}
			for _, e := range p.Also {
				kinds[e.Kind] = true
			}
			if !kinds[engine.KindFSWrite] || !kinds[engine.KindNetEgress] {
				t.Errorf("%s %s: kinds=%v, want both FSWrite and NetEgress (Finding 86)", c.Name, p.Spec, kinds)
			}
		}
	}
	if seenExceptions != len(exceptions) {
		t.Errorf("matched %d of %d documented index-refresh exceptions: %v", seenExceptions, len(exceptions), exceptions)
	}
}
