package engine

import (
	"bytes"
	"encoding/json"
	"flag"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// ---------------------------------------------------------------------------
// Golden JSON tests
// ---------------------------------------------------------------------------

// sampleReport builds a representative report that exercises every part of the
// frozen model: multiple effect kinds, a Scope top, taint labels, a pair of
// effects that merge under join, why-traces with and without locations, and
// notes.
func sampleReport() *Report {
	fsPasswd := Effect{
		Kind: KindFSRead, Target: ScopeOf("/etc/passwd"), Mode: ModeDirect,
		Certainty: CertaintyCertain, Taint: TaintOf(TaintUserInput), Reversible: true,
	}
	fsShadow := Effect{
		Kind: KindFSRead, Target: ScopeOf("/etc/shadow"), Mode: ModeDirect,
		Certainty: CertaintyPossible, Taint: TaintOf(TaintSecret, TaintUserInput), Reversible: true,
	}
	netEgress := Effect{
		Kind: KindNetEgress, Target: ScopeOf("api.example.com:443"), Mode: ModeTransitive,
		Certainty: CertaintyLikely, Taint: TaintOf(TaintUntrusted, TaintNetwork),
	}
	privEsc := Effect{
		Kind: KindPrivEsc, Target: ScopeTop(), Mode: ModeConditional,
		Certainty: CertaintyPossible, Taint: TaintOf(TaintUntrusted),
	}
	codeExec := Effect{
		Kind: KindCodeExec, Target: ScopeOf("bash", "sh"), Mode: ModeDirect,
		Certainty: CertaintyCertain, Taint: TaintOf(TaintUntrusted),
	}

	r := &Report{SchemaVersion: SchemaVersion, Root: "demo"}
	r.Effects = []Effect{fsPasswd, fsShadow, netEgress, privEsc, codeExec}
	r.Why = []WhyTrace{
		{
			Effect: netEgress.Key(),
			Because: []WhyStep{
				{
					Rule:     "net.call",
					Premises: []string{"call:http.Get", "arg:url"},
					Note:     "HTTP client egress",
					Loc:      &SourceLoc{File: "demo.go", Line: 12, Col: 3},
				},
			},
		},
		{
			Effect: codeExec.Key(),
			Because: []WhyStep{
				{Rule: "exec.spawn", Premises: []string{"call:os/exec.Command", "arg:sh"}, Loc: &SourceLoc{File: "demo.go", Line: 20}},
				{Rule: "taint.sink", Premises: []string{TaintUntrusted}},
			},
		},
	}
	r.Notes = []string{"sample report for the frozen core"}
	r.Normalize()
	return r
}

func TestReportGolden(t *testing.T) {
	got, err := sampleReport().Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	checkGolden(t, filepath.Join("testdata", "report.golden.json"), got)
}

func TestEffectGolden(t *testing.T) {
	e := Effect{
		Kind:       KindNetEgress,
		Target:     ScopeOf("api.example.com:443"),
		Mode:       ModeTransitive,
		Certainty:  CertaintyLikely,
		Taint:      TaintOf(TaintUntrusted, TaintNetwork),
		Reversible: false,
	}
	got, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		t.Fatalf("marshal effect: %v", err)
	}
	checkGolden(t, filepath.Join("testdata", "effect.golden.json"), got)
}

func checkGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(append([]byte(nil), got...), '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate with: go test ./engine -run %s -update)", path, err, t.Name())
	}
	if !bytes.Equal(bytes.TrimRight(want, "\n"), bytes.TrimRight(got, "\n")) {
		t.Errorf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	in := sampleReport()
	raw, err := in.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var out Report
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out.Normalize()
	if !reflect.DeepEqual(in, &out) {
		t.Errorf("round-trip mismatch\n--- want ---\n%+v\n--- got ---\n%+v", in, &out)
	}
}

func TestReportValidate(t *testing.T) {
	good := sampleReport()
	if err := good.Validate(); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}

	bad := NewReport()
	bad.Effects = []Effect{{Kind: "NotAKind", Target: ScopeOf("x"), Mode: ModeDirect, Certainty: CertaintyCertain}}
	if err := bad.Validate(); err == nil {
		t.Errorf("expected validation error for unknown kind")
	}

	noVersion := &Report{Root: "x"}
	if err := noVersion.Validate(); err == nil {
		t.Errorf("expected validation error for missing schema version")
	}
}

// ---------------------------------------------------------------------------
// Lattice law tests
// ---------------------------------------------------------------------------

type latticeOps[T any] struct {
	join   func(a, b T) T
	meet   func(a, b T) T
	eq     func(a, b T) bool
	bottom T
	top    T
}

// checkLatticeLaws verifies the standard lattice identities over the supplied
// sample elements: idempotence, commutativity, associativity, absorption, the
// bottom/top identities and domination.
func checkLatticeLaws[T any](t *testing.T, name string, ops latticeOps[T], elems []T) {
	t.Helper()
	for _, a := range elems {
		if !ops.eq(ops.join(a, a), a) {
			t.Errorf("%s: join not idempotent at %v", name, a)
		}
		if !ops.eq(ops.meet(a, a), a) {
			t.Errorf("%s: meet not idempotent at %v", name, a)
		}
		if !ops.eq(ops.join(a, ops.bottom), a) {
			t.Errorf("%s: join bottom not identity at %v", name, a)
		}
		if !ops.eq(ops.meet(a, ops.top), a) {
			t.Errorf("%s: meet top not identity at %v", name, a)
		}
		if !ops.eq(ops.join(a, ops.top), ops.top) {
			t.Errorf("%s: join top not absorbing at %v", name, a)
		}
		if !ops.eq(ops.meet(a, ops.bottom), ops.bottom) {
			t.Errorf("%s: meet bottom not absorbing at %v", name, a)
		}
		for _, b := range elems {
			if !ops.eq(ops.join(a, b), ops.join(b, a)) {
				t.Errorf("%s: join not commutative: %v, %v", name, a, b)
			}
			if !ops.eq(ops.meet(a, b), ops.meet(b, a)) {
				t.Errorf("%s: meet not commutative: %v, %v", name, a, b)
			}
			if !ops.eq(ops.join(a, ops.meet(a, b)), a) {
				t.Errorf("%s: join-absorption fails: %v, %v", name, a, b)
			}
			if !ops.eq(ops.meet(a, ops.join(a, b)), a) {
				t.Errorf("%s: meet-absorption fails: %v, %v", name, a, b)
			}
			for _, c := range elems {
				if !ops.eq(ops.join(ops.join(a, b), c), ops.join(a, ops.join(b, c))) {
					t.Errorf("%s: join not associative: %v, %v, %v", name, a, b, c)
				}
				if !ops.eq(ops.meet(ops.meet(a, b), c), ops.meet(a, ops.meet(b, c))) {
					t.Errorf("%s: meet not associative: %v, %v, %v", name, a, b, c)
				}
			}
		}
	}
}

func TestLatticeLaws(t *testing.T) {
	t.Run("certainty", func(t *testing.T) {
		checkLatticeLaws(t, "certainty", latticeOps[Certainty]{
			join:   func(a, b Certainty) Certainty { return a.Join(b) },
			meet:   func(a, b Certainty) Certainty { return a.Meet(b) },
			eq:     func(a, b Certainty) bool { return a == b },
			bottom: CertaintyBottom(),
			top:    CertaintyTop(),
		}, []Certainty{CertaintyUnknown, CertaintyUnlikely, CertaintyPossible, CertaintyLikely, CertaintyCertain})
	})

	t.Run("destructiveness", func(t *testing.T) {
		checkLatticeLaws(t, "destructiveness", latticeOps[Destructiveness]{
			join:   func(a, b Destructiveness) Destructiveness { return a.Join(b) },
			meet:   func(a, b Destructiveness) Destructiveness { return a.Meet(b) },
			eq:     func(a, b Destructiveness) bool { return a == b },
			bottom: DestructBottom(),
			top:    DestructTop(),
		}, []Destructiveness{DestructNone, DestructLow, DestructMedium, DestructHigh, DestructCritical})
	})

	t.Run("scope", func(t *testing.T) {
		checkLatticeLaws(t, "scope", latticeOps[Scope]{
			join:   func(a, b Scope) Scope { return a.Join(b) },
			meet:   func(a, b Scope) Scope { return a.Meet(b) },
			eq:     func(a, b Scope) bool { return a.Equal(b) },
			bottom: ScopeBottom(),
			top:    ScopeTop(),
		}, []Scope{
			ScopeBottom(), ScopeTop(),
			ScopeOf("a"), ScopeOf("b"), ScopeOf("c"),
			ScopeOf("a", "b"), ScopeOf("b", "c"), ScopeOf("a", "b", "c"),
		})
	})

	t.Run("taint", func(t *testing.T) {
		checkLatticeLaws(t, "taint", latticeOps[Taint]{
			join:   func(a, b Taint) Taint { return a.Join(b) },
			meet:   func(a, b Taint) Taint { return a.Meet(b) },
			eq:     func(a, b Taint) bool { return a.Equal(b) },
			bottom: TaintBottom(),
			top:    TaintTop(),
		}, []Taint{
			TaintBottom(), TaintTop(),
			TaintOf(TaintUntrusted), TaintOf(TaintUserInput),
			TaintOf(TaintUntrusted, TaintUserInput), TaintOf(TaintSecret),
		})
	})
}

func TestEffectJoin(t *testing.T) {
	a := Effect{
		Kind: KindFSRead, Target: ScopeOf("/a"), Mode: ModeDirect,
		Certainty: CertaintyPossible, Taint: TaintOf(TaintUserInput), Reversible: true,
	}
	b := Effect{
		Kind: KindFSRead, Target: ScopeOf("/b"), Mode: ModeDirect,
		Certainty: CertaintyCertain, Taint: TaintOf(TaintSecret), Reversible: true,
	}

	got, ok := a.Join(b)
	if !ok {
		t.Fatalf("join of matching kind/mode returned not-ok")
	}
	if want := ScopeOf("/a", "/b"); !got.Target.Equal(want) {
		t.Errorf("target: got %v want %v", got.Target, want)
	}
	if got.Certainty != CertaintyCertain {
		t.Errorf("certainty: got %v want Certain", got.Certainty)
	}
	if want := TaintOf(TaintSecret, TaintUserInput); !got.Taint.Equal(want) {
		t.Errorf("taint: got %v want %v", got.Taint, want)
	}
	if !got.Reversible {
		t.Errorf("reversible: got false want true")
	}

	rev, _ := b.Join(a)
	if !reflect.DeepEqual(got, rev) {
		t.Errorf("join not commutative: %+v vs %+v", got, rev)
	}

	c := b
	c.Kind = KindFSWrite
	if _, ok := a.Join(c); ok {
		t.Errorf("join of different kinds should not be ok")
	}
	d := b
	d.Mode = ModeTransitive
	if _, ok := a.Join(d); ok {
		t.Errorf("join of different modes should not be ok")
	}
}

// ---------------------------------------------------------------------------
// Dependency-direction test
// ---------------------------------------------------------------------------

// TestCoreDoesNotImportFrontends parses every .go file of this package and
// asserts that the core depends on nothing but the standard library (and, in
// the future, other core packages of the same module). Any frontend import —
// detected both structurally and by an explicit marker check — fails the test.
func TestCoreDoesNotImportFrontends(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	mod := modulePath(t, dir)

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse package dir: %v", err)
	}

	imports := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, imp := range file.Imports {
				p, uerr := strconv.Unquote(imp.Path.Value)
				if uerr != nil {
					t.Fatalf("bad import path %q: %v", imp.Path.Value, uerr)
				}
				imports[p] = true
			}
		}
	}
	if len(imports) == 0 {
		t.Fatalf("no imports found in %s — did the parse succeed?", dir)
	}

	paths := make([]string, 0, len(imports))
	for p := range imports {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		if isStdlibImport(p) {
			continue
		}
		if hasFrontendMarker(p) {
			t.Errorf("core package imports a frontend package: %q", p)
			continue
		}
		if p == mod || strings.HasPrefix(p, mod+"/") {
			continue // another core package of this module
		}
		t.Errorf("core package imports a non-core, non-stdlib package: %q (the core must depend on the standard library only)", p)
	}
}

// TestFrontendDetection guards against the import test passing vacuously: it
// pins the classifier so that a real frontend path is provably rejected.
func TestFrontendDetection(t *testing.T) {
	cases := []struct {
		path     string
		stdlib   bool
		frontend bool
	}{
		{"encoding/json", true, false},
		{"go/parser", true, false},
		{"github.com/v0lka/flowsh/engine", false, false},
		{"github.com/v0lka/flowsh/frontends/golang", false, true},
		{"github.com/acme/lifter-ts", false, true},
	}
	for _, tc := range cases {
		if got := isStdlibImport(tc.path); got != tc.stdlib {
			t.Errorf("isStdlibImport(%q) = %v, want %v", tc.path, got, tc.stdlib)
		}
		if got := hasFrontendMarker(tc.path); got != tc.frontend {
			t.Errorf("hasFrontendMarker(%q) = %v, want %v", tc.path, got, tc.frontend)
		}
	}
}

// isStdlibImport reports whether p names a standard-library package. Standard
// library import paths have no dot in their first path element.
func isStdlibImport(p string) bool {
	if p == "" || strings.HasPrefix(p, ".") {
		return false
	}
	first := p
	if i := strings.Index(p, "/"); i >= 0 {
		first = p[:i]
	}
	return !strings.Contains(first, ".")
}

var frontendMarkers = []string{"frontend", "lifter"}

func hasFrontendMarker(p string) bool {
	lp := strings.ToLower(p)
	for _, m := range frontendMarkers {
		if strings.Contains(lp, m) {
			return true
		}
	}
	return false
}

func modulePath(t *testing.T, dir string) string {
	t.Helper()
	for d := dir; ; {
		data, err := os.ReadFile(filepath.Join(d, "go.mod"))
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "module ") {
					return strings.TrimSpace(strings.TrimPrefix(line, "module "))
				}
			}
			t.Fatalf("go.mod in %s has no module directive", d)
		}
		parent := filepath.Dir(d)
		if parent == d {
			t.Fatalf("go.mod not found above %s", dir)
		}
		d = parent
	}
}
