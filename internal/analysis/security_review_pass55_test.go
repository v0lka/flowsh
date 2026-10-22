package analysis

// ===========================================================================
// Pass 55 — Finding 86: one parameter, two effects
// ===========================================================================
//
// A package manager's install/add/update subcommand both reaches a registry and
// rewrites the local store or manifest. The v2 KB schema held one effect per
// parameter, so each row declared one half: `pip install` reported the write and
// no egress, while `uv add`/`cargo update`/`poetry add` reported the egress and
// no write. Either way a deny rule keyed on the missing kind admitted the
// operation, and the row's own siblings disagreed about the same verb
// (`npm install` → FSWrite, `cargo update` → NetEgress).
//
// These tests pin both halves on the documented payloads, and pin the fail-safe
// side: a local artefact or an operand-less spelling must not fabricate the
// network effect.

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestFinding086InstallCarriesBothEffects pins the pair on every family
// representative: the write the store/manifest receives and the egress the
// registry contact performs.
func TestFinding086InstallCarriesBothEffects(t *testing.T) {
	a := mustAnalyzer(t)
	for _, c := range []struct{ src, remote string }{
		{`uv add requests`, "requests"},
		{`poetry add requests`, "requests"},
		{`poetry update`, ""},
		{`pdm add requests`, "requests"},
		{`pdm update`, ""},
		{`bundle update`, ""},
		{`composer update`, ""},
		{`composer require vendor/pkg`, "vendor/pkg"},
		{`cargo update`, ""},
		{`dotnet add package Evil`, "package"},
		{`dotnet restore`, ""},
		{`pipx install black`, "black"},
		{`rustup install nightly`, "nightly"},
		{`corepack install`, ""},
		{`svn update`, ""},
		{`fossil sync`, ""},
		{`ansible-galaxy install geerlingguy.docker`, ""},
		// The mirror direction: rows that already declared the write now
		// declare the registry contact too, so the two spellings agree.
		{`pip install requests`, "requests"},
		{`apt install curl`, "curl"},
		{`npm install lodash`, "lodash"},
		{`gem install rails`, "rails"},
		{`apk add curl`, "curl"},
	} {
		rep := a.Analyze(LangBash, c.src)
		if !hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: missing FSWrite (the store/manifest rewrite), effects=%v", c.src, rep.Effects)
		}
		if !hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: missing NetEgress (the registry contact), effects=%v", c.src, rep.Effects)
		}
		if c.remote != "" {
			mustEffect(t, rep, engine.KindNetEgress, c.remote, c.src)
		}
	}
}

// TestFinding086NoFabricatedEgress is the fail-safe control: a purely local
// install spelling — a path, an artefact file, an editable install — must not
// gain a network effect from the new declaration. The write stays; the egress
// would be a fabricated destination a NetEgress-denying policy acts on.
func TestFinding086NoFabricatedEgress(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`pip install ./pkg`,
		`pip install requests.whl`,
		`pip install -e .`,
		`pip install /tmp/requests-2.0-py3-none-any.whl`,
		`npm install ./local`,
	} {
		rep := a.Analyze(LangBash, src)
		if hasKind(rep, engine.KindNetEgress) {
			t.Errorf("%q: fabricated NetEgress from a local artefact: %v", src, rep.Effects)
		}
		if !hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: the local write disappeared: %v", src, rep.Effects)
		}
	}
}

// TestFinding086BareSpellingKeepsWrite pins the operand-less spelling: with no
// package named there is no registry contact to assert, but the store write the
// row's primary effect declares must survive.
func TestFinding086BareSpellingKeepsWrite(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{`npm install`, `pip install`, `poetry install`, `bundle install`} {
		rep := a.Analyze(LangBash, src)
		if !hasKind(rep, engine.KindFSWrite) {
			t.Errorf("%q: missing FSWrite, effects=%v", src, rep.Effects)
		}
	}
}
