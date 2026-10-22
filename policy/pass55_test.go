package policy_test

// ===========================================================================
// Pass 55 decisions: Finding 86 — the half that used to be dropped
// ===========================================================================

import (
	"testing"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/policy"
)

// TestFinding086WriteDenyCatchesInstalls pins the write half: a policy that
// denies FSWrite is the configuration the finding was measured against, and it
// admitted `uv add`, `cargo update`, `poetry add`, `pdm update`, `bundle
// update`, `dotnet restore`, `pipx install`, `rustup install`, `corepack
// install` and `svn update` because those rows declared only NetEgress. Each
// rewrites the local store or manifest, so each must now be refused.
func TestFinding086WriteDenyCatchesInstalls(t *testing.T) {
	writeDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindFSWrite: policy.Deny,
	}}
	for _, src := range []string{
		`uv add requests`,
		`cargo update`,
		`poetry add requests`,
		`poetry update`,
		`pdm add requests`,
		`pdm update`,
		`bundle update`,
		`composer update`,
		`dotnet add package Evil`,
		`dotnet restore`,
		`pipx install black`,
		`rustup install nightly`,
		`corepack install`,
		`ansible-galaxy install geerlingguy.docker`,
		`svn update`,
		`fossil sync`,
	} {
		mustDecide(t, writeDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (FSWrite deny)")
	}
}

// TestFinding086EgressDenyCatchesInstalls pins the mirror half: a policy that
// denies NetEgress admitted `pip install`, `npm install`, `apt install`, `gem
// install` and their siblings because their rows declared only the write. The
// registry contact is real, so the same deny rule must now catch them — and
// must still leave a purely local install alone (no fabricated egress).
func TestFinding086EgressDenyCatchesInstalls(t *testing.T) {
	egressDeny := policy.Config{Effects: map[engine.EffectKind]policy.Action{
		engine.KindNetEgress: policy.Deny,
	}}
	for _, src := range []string{
		`pip install requests`,
		`npm install lodash`,
		`apt install curl`,
		`gem install rails`,
		`apk add curl`,
		`pip download requests`,
		`uv add requests`,
	} {
		mustDecide(t, egressDeny, analyzeOK(t, api.LangBash, src), policy.Deny, src+" (NetEgress deny)")
	}
	for _, src := range []string{
		`pip install ./pkg`,
		`pip install requests.whl`,
		`npm install ./local`,
	} {
		mustDecide(t, egressDeny, analyzeOK(t, api.LangBash, src), policy.Allow, src+" (local artefact)")
	}
}
