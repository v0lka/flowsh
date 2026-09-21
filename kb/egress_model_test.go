package kb_test

import (
	"os"
	"strings"
	"testing"

	"github.com/v0lka/flowsh/bind"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/kb"
)

// This file pins the knowledge-base corrections of the review: the effect
// directions of the client flags (#24 redis-cli, #56 psql), the output/selector
// parameters modelled as file reads (#52), the code-host comment that
// contradicted the data (#25), the egress a code-host subcommand really makes
// (#28) and the phantom egress a lenient dialect used to accept for a service
// or resource word (#51).

// netEgressTargets returns every NetEgress target of a bound result.
func netEgressTargets(res *bind.Result) []string {
	var out []string
	for _, e := range res.Effects {
		if e.Kind == engine.KindNetEgress {
			out = append(out, e.Target.Targets()...)
		}
	}
	return out
}

func hasKindAndTarget(res *bind.Result, kind engine.EffectKind, target string) bool {
	for _, e := range res.Effects {
		if e.Kind == kind && e.Target.Contains(target) {
			return true
		}
	}
	return false
}

func hasKindT(res *bind.Result, kind engine.EffectKind) bool {
	for _, e := range res.Effects {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

// TestRedisCLIFlagDirections pins #24: -n selects the database index and -r a
// repeat count, so neither may be reported as an FSRead of "2" or a ProcSpawn
// of "5".
func TestRedisCLIFlagDirections(t *testing.T) {
	b := newBinder(t)
	for _, src := range []string{"redis-cli -n 2 ping", "redis-cli -r 5 ping", "redis-cli --db 2 ping"} {
		res := bindSrc(t, b, src)
		if hasKindAndTarget(res, engine.KindFSRead, "2") || hasKindAndTarget(res, engine.KindProcSpawn, "5") {
			t.Errorf("%q: flag mapped to a fabricated effect: %v", src, res.Effects)
		}
	}
	if res := bindSrc(t, b, "redis-cli -n 2 ping"); !hasKindT(res, engine.KindNetEgress) {
		t.Errorf("the client still connects, want NetEgress, got %v", res.Effects)
	}
}

// TestPsqlNoPasswordReadsNoCredential pins #56: -w/--no-password means "never
// prompt", so it accesses no credential material.
func TestPsqlNoPasswordReadsNoCredential(t *testing.T) {
	b := newBinder(t)
	for _, src := range []string{
		"psql -w -c 'select 1'",
		"psql --no-password -c 'select 1'",
	} {
		res := bindSrc(t, b, src)
		if hasKindT(res, engine.KindCredAccess) {
			t.Errorf("%q: fabricated CredAccess: %v", src, res.Effects)
		}
	}
	// -W/--password forces a prompt, so credential material does enter the
	// process: it stays CredAccess.
	if res := bindSrc(t, b, "psql -W -c 'select 1'"); !hasKindT(res, engine.KindCredAccess) {
		t.Errorf("psql -W must stay CredAccess, got %v", res.Effects)
	}
}

// TestOutputSelectorParamsAreNotFileReads pins #52: an output-format or
// selector parameter names no file, so neither its value nor the subcommand
// operand may be reported as a file read.
func TestOutputSelectorParamsAreNotFileReads(t *testing.T) {
	b := newBinder(t)
	cases := []struct {
		src   string
		value string // the selector value that must not be a file the tool reads
	}{
		{src: "gh pr list --json state", value: "state"},
		{src: "gh pr list -q .state", value: ".state"},
		{src: "glab mr list --output json", value: "json"},
		{src: "kubectl get pods -n default", value: "default"},
		{src: "kubectl get pods -o wide", value: "wide"},
		{src: "kubectl get pods --output wide", value: "wide"},
		{src: "aws s3 ls --output table", value: "table"},
		{src: "az group list -o table", value: "table"},
	}
	for _, tc := range cases {
		res := bindSrc(t, b, tc.src)
		for _, e := range res.Effects {
			if e.Kind == engine.KindFSRead && e.Target.Contains(tc.value) {
				t.Errorf("%q: fabricated FSRead of the selector %q: %s", tc.src, tc.value, e.Target)
			}
		}
		if !hasKindT(res, engine.KindStdio) {
			t.Errorf("%q: an output/selector parameter is advisory, want a Stdio effect, got %v", tc.src, res.Effects)
		}
	}
}

// TestCodeHostEgressIsUnresolved pins #28: a code-host subcommand really talks
// to the host, so its egress must be reported — as an unresolved destination,
// because the operand group holds the subcommand's arguments and not an address.
func TestCodeHostEgressIsUnresolved(t *testing.T) {
	b := newBinder(t)
	for _, src := range []string{
		"gh pr list",
		"gh pr view 5",
		"gh api /user",
		"glab mr list",
		"jj git fetch",
		"jj push",
	} {
		res := bindSrc(t, b, src)
		if !hasKindT(res, engine.KindNetEgress) {
			t.Errorf("%q: the remote subcommand must report NetEgress, got %v", src, res.Effects)
		}
		for _, tg := range netEgressTargets(res) {
			if tg == "list" || tg == "view" || tg == "5" || tg == "/user" || tg == "fetch" || tg == "push" {
				t.Errorf("%q: operand word %q became an egress target", src, tg)
			}
		}
	}
}

// TestCodeHostDestinationOperandStaysConcrete pins the other half of #28: an
// address the operand does name still lowers to its concrete host.
func TestCodeHostDestinationOperandStaysConcrete(t *testing.T) {
	b := newBinder(t)
	res := bindSrc(t, b, "gh -R evil.example/repo pr list")
	if !hasKindAndTarget(res, engine.KindNetEgress, "evil.example/repo") {
		t.Errorf("explicit destination operand lost: %v", res.Effects)
	}
}

// TestServiceClientHasNoPhantomEgress pins #51: under a lenient dialect the
// operand of a service client is the operation word or the resource, never a
// network address, so no such word may become an egress target.
func TestServiceClientHasNoPhantomEgress(t *testing.T) {
	b := newBinder(t)
	phantoms := map[string]bool{
		"pods": true, "ls": true, "list": true, "instances": true, "default": true,
		"ping": true, "mydb": true, "describe": true, "get": true, "compute": true,
		"group": true, "s3": true, "state": true, "wide": true,
	}
	srcs := []string{
		"kubectl get pods",
		"kubectl get pods -n default",
		"kubectl describe pod x",
		"aws s3 ls",
		"gcloud compute instances list",
		"az group list",
		"redis-cli ping",
		"psql mydb",
		"helm list",
	}
	for _, src := range srcs {
		res := bindSrc(t, b, src)
		for _, tg := range netEgressTargets(res) {
			if phantoms[tg] {
				t.Errorf("%q: phantom egress target %q (effects %v)", src, tg, res.Effects)
			}
		}
		// The remote operation is still reported, as an unresolved destination
		// or a real host the operand named.
		if !hasKindT(res, engine.KindNetEgress) && !hasKindT(res, engine.KindStdio) {
			t.Errorf("%q: the client operation vanished, got %v", src, res.Effects)
		}
	}
}

// TestServiceClientExplicitHostStaysConcrete pins that a host written on the
// command line still lowers concretely, so the unresolved-destination modelling
// does not blind the report to a named server.
func TestServiceClientExplicitHostStaysConcrete(t *testing.T) {
	b := newBinder(t)
	for _, src := range []string{
		"kubectl -s https://api.example:6443 get pods",
		"psql -h db.example -c 'select 1'",
		"aws --endpoint-url https://s3.example s3 ls",
	} {
		res := bindSrc(t, b, src)
		if !hasKindT(res, engine.KindNetEgress) {
			t.Errorf("%q: explicit destination lost, got %v", src, res.Effects)
		}
	}
}

// TestCodeHostCommentMatchesData pins #25: the document header must not claim a
// ProcSpawn/CodeExec subcommand (the claim that contradicted the data), and the
// data must model the two named subcommands as the remote operations they are.
func TestCodeHostCommentMatchesData(t *testing.T) {
	data, err := os.ReadFile("data/codehost.yaml")
	if err != nil {
		t.Fatalf("read codehost.yaml: %v", err)
	}
	if strings.Contains(string(data), "runs another program") {
		t.Errorf("codehost.yaml still claims a subcommand runs another program, which the data denies")
	}
	k, err := kb.Load()
	if err != nil {
		t.Fatalf("kb.Load: %v", err)
	}
	for name, spec := range map[string]string{"gh": "run", "jj": "git"} {
		c, ok := k.Command(name)
		if !ok {
			t.Fatalf("%s not in the knowledge base", name)
		}
		p, ok := c.Param(spec)
		if !ok {
			t.Fatalf("%s %s not in the knowledge base", name, spec)
		}
		if p.Effect.Kind != engine.KindNetEgress {
			t.Errorf("%s %s: kind %s, want NetEgress (the code-host / git-backend remote)", name, spec, p.Effect.Kind)
		}
	}
	// No code-host subcommand runs a local program, so none may be ProcSpawn or
	// CodeExec.
	for _, name := range []string{"gh", "glab", "jj"} {
		c, ok := k.Command(name)
		if !ok {
			t.Fatalf("%s not in the knowledge base", name)
		}
		for _, p := range c.Params {
			if p.Effect.Kind == engine.KindProcSpawn || p.Effect.Kind == engine.KindCodeExec {
				t.Errorf("%s %s: unexpected %s", name, p.Spec, p.Effect.Kind)
			}
		}
	}
}
