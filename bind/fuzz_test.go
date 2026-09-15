package bind_test

import (
	"strings"
	"testing"
	"time"

	"github.com/v0lka/flowsh/bind"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/bash"
)

// This file is roadmap task C4 (reliability/security): fuzzing for the binder,
// plus adversarial bound checks.
//
// The binder feeds the whole analysis path (bash abstract execution resolves
// names through it), so its contract is the same fail-closed one the rest of the
// analysed path obeys:
//
//   - Bind / BindBash / BindProgram never panic and never return nil;
//   - every result serialises;
//   - Conservative is never set without the shared ⊤ effect (CodeExec over the
//     any-target scope);
//   - a call the binder cannot resolve degrades to ⊤ (Conservative), never to an
//     empty "no effect" result — the no-silent-miss invariant at the binding
//     layer.
//
// PowerShell has no separate Binder method (its frontend resolves cmdlets in
// front/ps via the Cmdlets table, and the PS path is fuzzed in
// front/ps/fuzz_test.go); the generic Bind is nonetheless exercised under
// StylePS below so the PowerShell-shaped call path stays panic-free too.

// bindTopEffect reports whether e is the ⊤ shape (CodeExec over any target).
func bindTopEffect(e engine.Effect) bool {
	return e.Kind == engine.KindCodeExec && e.Target.IsTop()
}

func bindHasTop(effs []engine.Effect) bool {
	for _, e := range effs {
		if bindTopEffect(e) {
			return true
		}
	}
	return false
}

// checkBindContract enforces the binder's fail-closed contract on one result.
func checkBindContract(t *testing.T, src string, r *bind.Result) {
	t.Helper()
	if r == nil {
		t.Fatalf("nil bind.Result for %q", src)
	}
	if _, err := r.Encode(); err != nil {
		t.Fatalf("bind.Result.Encode failed for %q: %v", src, err)
	}
	if r.Conservative && !bindHasTop(r.Effects) {
		t.Fatalf("conservative result without a ⊤ effect for %q", src)
	}
	// An unresolved or function-typed call must degrade to ⊤, never to a
	// benign/empty miss.
	switch r.Resolution.Kind {
	case bind.ResolveUnknown, bind.ResolveFunction:
		if !r.Conservative || !bindHasTop(r.Effects) {
			t.Fatalf("resolution %q must be ⊤ (conservative) for %q", r.Resolution.Kind, src)
		}
	}
}

// FuzzBind asserts the binder contract on arbitrary input. Seeds include
// adversarial shapes (deep nesting, huge pipelines, unbalanced quotes, repeated
// alias records) so a seed-only `go test` run already exercises the paths.
func FuzzBind(f *testing.F) {
	b, err := bind.NewDefault()
	if err != nil {
		f.Fatalf("bind.NewDefault: %v", err)
	}
	seeds := []string{
		"", "ls -la", "rm -rf /", `sed -i s/a/b/ file`,
		"sudo env FOO=1 rm -rf /", "cat < in.txt > out.txt",
		"$(date)", "a | b && c", "`echo rm` -rf /",
		"for f in *; do rm $f; done", "cat <<EOF\n$(rm -rf /tmp/h)\nEOF\n",
		"function f { rm -rf /; }; f", "alias r='rm -rf'; r /",
		"X=rm; $X -rf /", "while true; do rm -rf /tmp/x; done",
		"echo aGVsbG8= | base64 -d | sh", "frobnicate --wat /y",
		// Malformed / adversarial trivia.
		`echo "unterminated`, "&&&", "(((", ";;;", "\x00\x01\x02",
		// Adversarial scale.
		strings.Repeat("a | ", 500) + "cat",
		strings.Repeat("( ", 500),
		strings.Repeat("'", 1000),
		strings.Repeat("alias a=b; ", 300),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, src string) {
		// Parse never panics for either dialect (bash variants).
		for _, v := range []bash.Variant{bash.Bash, bash.POSIX} {
			prog := bash.Parse(v, "fuzz", src)
			if prog == nil {
				t.Fatalf("nil program for %q", src)
			}
			// BindProgram binds every command at every nesting level; BindBash
			// binds one command directly.
			for _, r := range b.BindProgram(prog) {
				checkBindContract(t, src, r)
			}
			if !prog.Top {
				for _, s := range prog.Stmts {
					if s != nil && s.Cmd != nil {
						checkBindContract(t, src, b.BindBash(s.Cmd, prog))
					}
				}
			}
		}
		for _, r := range b.BindScript(src) {
			checkBindContract(t, src, r)
		}

		// Generic Bind totality: the nil call and synthetic calls in both styles
		// (bash argv and PowerShell-shaped) must stay panic-free and fail closed.
		checkBindContract(t, src, b.Bind(nil))
		checkBindContract(t, src, b.Bind(&bind.Call{Style: bind.StyleBash}))
		checkBindContract(t, src, b.Bind(&bind.Call{
			Style:       bind.StylePS,
			Name:        src,
			NameOK:      true,
			NamePresent: true,
		}))
	})
}

// TestBindAdversarialInputsAreBounded is acceptance criterion C4.3 for the
// binder: adversarial inputs (deep nesting, huge pipelines, unbalanced quotes,
// repeated alias records) terminate quickly, never panic, and any command the
// binder cannot resolve degrades to ⊤ rather than to an empty miss.
func TestBindAdversarialInputsAreBounded(t *testing.T) {
	b, err := bind.NewDefault()
	if err != nil {
		t.Fatalf("bind.NewDefault: %v", err)
	}
	cases := []struct {
		name string
		src  string
	}{
		{"deep-nesting", strings.Repeat("( ", 4000)},
		{"huge-pipeline", strings.Repeat("frobnicate | ", 4000) + "cat"},
		{"unbalanced-quotes", strings.Repeat("'\"", 8000)},
		{"repeated-alias", strings.Repeat("alias a=b; ", 2000)},
		{"repeated-unknown", strings.Repeat("unknowncmd /x; ", 2000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			results := b.BindScript(tc.src)
			elapsed := time.Since(start)
			if elapsed > 5*time.Second {
				t.Fatalf("not bounded: took %s", elapsed)
			}
			for _, r := range results {
				checkBindContract(t, tc.src, r)
			}
		})
	}
}
