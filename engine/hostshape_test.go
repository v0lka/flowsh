package engine

import "testing"

// TestHostShaped pins the strict host/URL grammar a literal NetEgress target
// must pass. The rejects are the phantom spellings the gate exists to stop:
// git subcommand names, commit SHAs, refspecs, pathspecs and git object specs
// that the binder's index-order positional fallback used to report as egress
// targets. The accepts are the forms a real destination takes.
func TestHostShaped(t *testing.T) {
	strict := []struct {
		in   string
		want bool
	}{
		// URLs — any scheme declares network intent.
		{"https://example.com/x", true},
		{"http://evil", true},
		{"http://evil/x.ps1", true},
		{"ftp://10.0.0.1/pub", true},
		{"git://example.com/r.git", true},
		{"ssh://user@host.example/r", true},
		{"https://2130706433/x", true}, // obfuscated decimal IP inside a URL
		{"https://0x7f000001/x", true}, // obfuscated hex IP inside a URL
		{"https://api.example/v1", true},
		{"://missing-scheme", false},

		// Hosts with dots, ports, userinfo.
		{"api.example.com", true},
		{"evil.example", true},
		{"r2cdn.perplexity.ai", true},
		{"api.example.com:443", true},
		{"evil.example:4444", true},
		{"user@evil.example", true},
		{"user@evil.example:22", true},
		{"localhost", true},
		{"LOCALHOST", true},

		// scp-style remotes: the host part must itself be host-shaped.
		{"attacker@evil.example:/", true},
		{"git@github.com:org/repo.git", true},
		{"evil.example:sub/path", true},

		// Addresses, including the obfuscated IPv4 spellings.
		{"127.0.0.1", true},
		{"10.0.0.1:8080", true},
		{"::1", true},
		{"fe80::1", true},
		{"[2001:db8::1]:443", true},
		{"0x7f000001", true},
		{"2130706433", true},
		{"134744072", true}, // 8.8.8.8

		// The phantom spellings: subcommands, SHAs, refs, pathspecs, object
		// specs, regex operands, numbers.
		{"show", false},
		{"status", false},
		{"diff", false},
		{"origin", false},
		{"cd234ef7f17d30a3c32803810246676c5afb221b", false},
		{"17198597", false}, // 8-digit git short SHA: below the 9-digit decimal-IP floor
		{"main...HEAD", false},
		{"pr-36", false},
		{"HEAD", false},
		{"core/tools/registry.go", false},
		{"backend.diff", false}, // dotted, but the final label names a file extension: a diff artifact, not a host
		{"/tmp/changed.txt", false},
		{"main:backend/config/defaults.go", false}, // git object spec: "main" is not a host
		{"pr-36:build/appicon.png", false},
		{"code-review.md", false},
		{"evil.sh", false}, // the .sh label names a shell script here; a real URL to such a host keeps scheme:// or the lenient grammar
		{"{print $1}", false},
		{"^??", false},
		{"4444", false},
		{"-1", false},
		{"", false},
		{"a b", false},
		{`C:\Windows`, false},
		{"foo_bar.example.com", false}, // underscore is not a hostname character
		{"-leading.example.com", false},
		{"trailing-.example.com", false},
		{"example..com", false},
		{"192.168.0", false},       // incomplete quad is not an address
		{"999.999.999.999", false}, // out-of-range octets
	}
	for _, tc := range strict {
		if got := HostShaped(tc.in); got != tc.want {
			t.Errorf("HostShaped(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestHostShapedLenient pins the destination-slot grammar: everything strict
// accepts, plus a bare single-label DNS name (an intranet/NetBIOS-style host).
// The lenient mode is for constructs whose destination role is declared
// (nc HOST, ssh HOST, /dev/tcp/host/port, PowerShell -ComputerName).
func TestHostShapedLenient(t *testing.T) {
	lenient := []struct {
		in   string
		want bool
	}{
		{"evil", true},
		{"host", true},
		{"bastion", true},
		{"SERVER01", true},
		{"evil:4444", true},
		{"show", true},  // same shape as "evil": only destination-declaring contexts may use the lenient mode
		{"4444", false}, // an all-numeric label is a port, never a host
		{"main:backend/config", false},
		{"-x", false},
		{"a_b", false}, // underscore is not a hostname character
		{"", false},
	}
	for _, tc := range lenient {
		if got := HostShapedLenient(tc.in); got != tc.want {
			t.Errorf("HostShapedLenient(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestFilterEgressTargets pins the scope-level gate: ⊤ and ⊥ pass through
// (unresolved egress / payload-only egress), literals are filtered, and an
// empty residue means the effect must not be created.
func TestFilterEgressTargets(t *testing.T) {
	cases := []struct {
		name    string
		scope   Scope
		lenient bool
		want    Scope
		keep    bool
	}{
		{"top stays", ScopeTop(), false, ScopeTop(), true},
		{"bottom stays", ScopeBottom(), false, ScopeBottom(), true},
		{
			"literal url kept",
			ScopeOf("https://evil.example/x"),
			false,
			ScopeOf("https://evil.example/x"),
			true,
		},
		{
			"phantom word dropped strict",
			ScopeOf("status"),
			false,
			ScopeBottom(),
			false,
		},
		{
			"phantom word kept lenient",
			ScopeOf("status"),
			true,
			ScopeOf("status"),
			true,
		},
		{
			"mixed set filtered to host-shaped",
			ScopeOf("diff", "main...HEAD", "https://example.com/x"),
			false,
			ScopeOf("https://example.com/x"),
			true,
		},
		{
			"paths and shas all dropped",
			ScopeOf("diff", "cd234ef7f17d30a3c32803810246676c5afb221b", "core/tools/registry.go"),
			false,
			ScopeBottom(),
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, keep := FilterEgressTargets(tc.scope, tc.lenient)
			if keep != tc.keep {
				t.Fatalf("keep = %v, want %v", keep, tc.keep)
			}
			if !got.Equal(tc.want) {
				t.Errorf("scope = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestFilterEgressTargetsDeterministic pins that filtering preserves the
// canonical (sorted) scope form, so effect keys stay stable.
func TestFilterEgressTargetsDeterministic(t *testing.T) {
	a, _ := FilterEgressTargets(ScopeOf("z.example", "diff", "a.example"), false)
	b, _ := FilterEgressTargets(ScopeOf("a.example", "diff", "z.example"), false)
	if !a.Equal(b) {
		t.Errorf("filter is order-sensitive: %s vs %s", a, b)
	}
	want := ScopeOf("a.example", "z.example")
	if !a.Equal(want) {
		t.Errorf("got %s, want %s", a, want)
	}
}
