package bind

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestArgsScopeNumericConfined pins the pure lowering rule for operand scopes:
// a confined dynamic operand (Dir set: every dynamic part is numeric-class, so
// its expansion lands inside that directory) contributes the directory as a
// target, while any unconfined dynamic operand still forces the group to ⊤ —
// resolution adds precision, it never loosens the default.
func TestArgsScopeNumericConfined(t *testing.T) {
	confined := Arg{Value: "", Literal: false, Dir: "/tmp"}
	unconfined := Arg{Value: "", Literal: false}
	literal := Arg{Value: "a.go", Literal: true}

	if got := argsScope([]Arg{confined}); !got.Equal(engine.ScopeOf("/tmp")) {
		t.Errorf("confined operand scope = %s, want {/tmp}", got)
	}
	if got := argsScope([]Arg{literal, confined}); !got.Equal(engine.ScopeOf("a.go", "/tmp")) {
		t.Errorf("literal+confined group scope = %s, want {a.go,/tmp}", got)
	}
	if got := argsScope([]Arg{unconfined}); !got.IsTop() {
		t.Errorf("unconfined operand scope = %s, want ⊤", got)
	}
	if got := argsScope([]Arg{confined, unconfined}); !got.IsTop() {
		t.Errorf("one unconfined operand must force the group to ⊤, got %s", got)
	}
	if got := argsScope(nil); !got.IsBottom() {
		t.Errorf("empty group scope = %s, want ⊥", got)
	}
}
