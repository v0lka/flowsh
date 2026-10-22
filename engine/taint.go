package engine

import (
	"fmt"
	"sort"
	"strings"
)

// ===========================================================================
// Provenance: source classes and attacker influence
// ===========================================================================

// SourceClass names the origin class of a value observed by the taint flow. The
// four classes are exactly those the analysis distinguishes: untrusted external
// content, the process environment, file content, and statically-known
// literals. Literal is the only trusted class; the others are progressively
// attacker-influenced.
type SourceClass string

const (
	// SourceUntrustedContent is content the attacker can steer directly:
	// network responses, prompt text, stdin of a pipeline fed by an untrusted
	// producer.
	SourceUntrustedContent SourceClass = "UntrustedContent"
	// SourceEnv is the process environment.
	SourceEnv SourceClass = "Env"
	// SourceFile is file content.
	SourceFile SourceClass = "File"
	// SourceLiteral is a statically-known literal: trusted by construction.
	SourceLiteral SourceClass = "Literal"
)

// SourceClasses lists every source class, in canonical order (most
// attacker-influenced first).
var SourceClasses = []SourceClass{SourceUntrustedContent, SourceEnv, SourceFile, SourceLiteral}

// Valid reports whether c is a defined source class.
func (c SourceClass) Valid() bool {
	switch c {
	case SourceUntrustedContent, SourceEnv, SourceFile, SourceLiteral:
		return true
	}
	return false
}

// Influence is the lattice of attacker control over a value: how far an
// adversary can steer it.
//
//	None ⊑ Indirect ⊑ Direct
//
// Join (⊔) is the least upper bound (max).
type Influence int

const (
	// InfluenceNone means the value is not attacker-controlled.
	InfluenceNone Influence = iota
	// InfluenceIndirect means the value is attacker-controlled only insofar as
	// its container is (the environment or a file the attacker could have
	// written).
	InfluenceIndirect
	// InfluenceDirect means the value is directly attacker-controlled.
	InfluenceDirect
)

var influenceNames = [...]string{"None", "Indirect", "Direct"}

// Valid reports whether i is a defined influence level.
func (i Influence) Valid() bool { return i >= InfluenceNone && i <= InfluenceDirect }

// String returns the canonical name of the influence level.
func (i Influence) String() string {
	if !i.Valid() {
		return fmt.Sprintf("Influence(%d)", int(i))
	}
	return influenceNames[i]
}

// Join returns the least upper bound (⊔) of i and o.
func (i Influence) Join(o Influence) Influence {
	if o > i {
		return o
	}
	return i
}

// LessOrEqual reports whether i ⊑ o.
func (i Influence) LessOrEqual(o Influence) bool { return i <= o }

// Severity maps attacker influence onto the shared severity scale (the
// destructiveness lattice) so it can be folded into a composite score.
func (i Influence) Severity() Destructiveness {
	switch i {
	case InfluenceDirect:
		return DestructHigh
	case InfluenceIndirect:
		return DestructMedium
	default:
		return DestructNone
	}
}

// Influence returns the attacker control over a value of class c.
func (c SourceClass) Influence() Influence {
	switch c {
	case SourceUntrustedContent:
		return InfluenceDirect
	case SourceEnv, SourceFile:
		return InfluenceIndirect
	default:
		return InfluenceNone
	}
}

// Labels returns the taint a value of class c carries: the core labels the
// analysis attaches to a value whose provenance is class c.
func (c SourceClass) Labels() Taint {
	switch c {
	case SourceUntrustedContent:
		return TaintOf(TaintUntrusted)
	case SourceEnv:
		return TaintOf(TaintEnv)
	case SourceFile:
		return TaintOf(TaintFileSystem)
	default:
		return TaintBottom()
	}
}

// Provenance is the source-class summary of the data an effect consumes: the
// set of provenance classes a value flows from. It is what the taint flow
// produces before the classes are folded into taint labels and attacker
// influence.
type Provenance struct {
	Sources []SourceClass `json:"sources,omitempty"`
}

// NewProvenance returns a provenance over the given classes, normalised
// (sorted, de-duplicated, empty entries dropped).
func NewProvenance(classes ...SourceClass) Provenance {
	return Provenance{Sources: normaliseClasses(classes)}
}

func normaliseClasses(cs []SourceClass) []SourceClass {
	if len(cs) == 0 {
		return nil
	}
	tmp := make([]SourceClass, 0, len(cs))
	for _, c := range cs {
		if c != "" {
			tmp = append(tmp, c)
		}
	}
	if len(tmp) == 0 {
		return nil
	}
	// Total order: by canonical class position, then lexicographically by name.
	// The name tie-break matters for unrecognised classes — they all share the
	// last position — so normaliseClasses is order-independent for any input
	// (sort.Slice is unstable, so without it the result depended on input order).
	sort.Slice(tmp, func(i, j int) bool {
		oi, oj := classOrder(tmp[i]), classOrder(tmp[j])
		if oi != oj {
			return oi < oj
		}
		return tmp[i] < tmp[j]
	})
	w := 1
	for i := 1; i < len(tmp); i++ {
		if tmp[i] != tmp[w-1] {
			tmp[w] = tmp[i]
			w++
		}
	}
	return tmp[:w]
}

// classOrder returns the canonical position of c in SourceClasses (most
// attacker-influenced first), so normaliseClasses preserves the documented
// class order rather than sorting lexicographically. An unrecognised class
// sorts last, so it never displaces a known one.
func classOrder(c SourceClass) int {
	for i, x := range SourceClasses {
		if x == c {
			return i
		}
	}
	return len(SourceClasses)
}

// Taint returns the join of the taint labels of every source class.
func (p Provenance) Taint() Taint {
	t := TaintBottom()
	for _, c := range p.Sources {
		t = t.Join(c.Labels())
	}
	return t
}

// Influence returns the greatest attacker influence over the source classes.
func (p Provenance) Influence() Influence {
	i := InfluenceNone
	for _, c := range p.Sources {
		i = i.Join(c.Influence())
	}
	return i
}

// Trusted reports whether the provenance is entirely literal (no attacker
// influence at all).
func (p Provenance) Trusted() bool { return p.Influence() == InfluenceNone }

// ===========================================================================
// Taint flow: reading influence off an effect
// ===========================================================================

// Flow is one taint-flow edge: a value read from a source class reaches an
// effect. It is the unit the taint analysis produces before effects are folded
// into a score.
type Flow struct {
	Source SourceClass `json:"source"`
	Effect Effect      `json:"effect"`
}

// InfluenceOf returns the attacker influence over the data an effect consumes,
// read off its taint labels (⊤ taint is direct control).
func InfluenceOf(e Effect) Influence {
	switch {
	case e.Taint.IsTop():
		return InfluenceDirect
	case e.Taint.Contains(TaintUntrusted) || e.Taint.Contains(TaintUserInput):
		return InfluenceDirect
	case e.Taint.Contains(TaintEnv) || e.Taint.Contains(TaintNetwork) || e.Taint.Contains(TaintProcess):
		return InfluenceIndirect
	case e.Taint.Contains(TaintFileSystem):
		return InfluenceIndirect
	default:
		return InfluenceNone
	}
}

// MaxInfluence folds the influence of every effect with join (max).
func MaxInfluence(effects []Effect) Influence {
	i := InfluenceNone
	for _, e := range effects {
		i = i.Join(InfluenceOf(e))
	}
	return i
}

// ===========================================================================
// Secrets and exfiltration
// ===========================================================================

// secretPathMarkers are the well-known credential or secret locations the
// analysis recognises. Matching is case-insensitive. Three rules apply, chosen
// per marker so the common spellings match without over-matching:
//
//   - a marker containing a path separator (".kube/config", "/etc/shadow") is a
//     path fragment and matches as a substring of the lexically normalised path
//     (see SecretPath: "/etc//shadow", "/etc/./shadow" and the Windows
//     "C:\…\.kube\config" spelling all resolve to the marker's file);
//   - a dot-prefixed marker (".ssh", ".env", …) matches at the start of a path
//     component or as the basename's suffix, so "my.envelope" does not match
//     ".env" but "prod.env" (the common ".env" file name) does;
//   - any other marker ("id_rsa", "credentials", …) is a distinctive name and
//     matches as a substring.
//
// File-name extensions that mark private keys and key stores are handled
// separately by secretExtensionMarkers, matched as a basename suffix or as a
// basename that carries further extension text after the marker.
var secretPathMarkers = []string{
	".ssh", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys",
	".aws", ".gnupg", ".netrc", ".pgpass", ".my.cnf", ".git-credentials",
	".kube/config", ".docker/config.json", ".npmrc", ".pypirc", ".htpasswd",
	".bash_history", ".zsh_history", ".env", "/etc/shadow", "/etc/gshadow",
	"/etc/sudoers", "keystore", "credentials", "secrets",
	// Interactively-authenticated and token-based tool stores: a live OAuth or
	// API token is as good as a password, and none of these carries a
	// credential-shaped basename ("hosts.yml", "wg0.conf", "token_cache.json"),
	// so they are listed by location.
	".azure",                // Azure CLI token cache (msal_token_cache.json, accessTokens.json)
	".config/gh",            // gh CLI OAuth token (hosts.yml)
	".config/hub",           // hub CLI OAuth token
	".config/gcloud",        // gcloud credentials (application_default_credentials.json)
	".config/rclone",        // rclone remotes, including their plaintext secrets
	".config/containers",    // podman/skopeo registry auth.json
	".config/pip",           // pip index credentials
	".vault-token",          // HashiCorp Vault client token
	".terraform.d",          // Terraform registry credentials
	".composer",             // Composer auth.json
	".filezilla",            // stored FTP/SFTP credentials
	".remmina",              // stored remote-desktop credentials
	".mozilla",              // Firefox logins.json / key4.db
	".config/google-chrome", // Chrome Login Data / Cookies
	"/etc/wireguard",        // WireGuard peer private keys
	"/etc/apt/auth.conf",    // apt repository credentials
	"/etc/ppp",              // PPP/PPTP/pppoe secrets
	// The next stores carry neither a credential-shaped basename nor an
	// already-listed directory, so each is listed by location (Finding 39):
	// a plain-text S3 key in `~/.s3cfg`, a boto profile in `~/.boto`, an OCI
	// CLI key in `~/.oci/config`, a Terraform Cloud token in `~/.terraformrc`,
	// a DigitalOcean token in `~/.config/doctl/config.yaml`, an SMTP password
	// in `~/.msmtprc`, an age/`sops` private key in `~/.config/sops`, and the
	// macOS login keychain in `~/Library/Keychains`.
	".s3cfg",                // s3cmd access key and secret key
	".boto",                 // boto/boto3 profile credentials
	".oci",                  // OCI CLI profile (key_file, fingerprint, tenancy)
	".terraformrc",          // Terraform CLI config (credentials block, host tokens)
	".config/doctl",         // DigitalOcean CLI access token
	".msmtprc",              // msmtp account passwords
	".config/sops",          // sops age/pgp key material
	".config/age",           // age identity files
	".password-store",       // pass(1) password store
	"library/keychains",     // macOS login keychain database
	".local/share/keyrings", // GNOME keyring databases
	"microsoft/credentials", // Windows Credential Manager blob store
	// Build-tool, package-manager and shell-history stores that hold plaintext
	// registry passwords or auth tokens under a name that carries no credential
	// word (settings.xml, gradle.properties, yarnrc.yml, config, dbshell, …), so
	// each is listed by location (Finding 39, second sweep).
	".m2/settings.xml",          // Maven server passwords and mirrors
	".m2/settings-security.xml", // Maven master password
	".gradle/gradle.properties", // Gradle signing and repository passwords
	".nuget/nuget/nuget.config", // NuGet API keys and package sources
	".yarnrc.yml",               // Yarn Berry npmAuthToken / npmAuthIdent
	".bundle/config",            // Bundler registry credentials
	".config/pypoetry",          // Poetry repository tokens
	".config/tea",               // Gitea CLI login tokens
	".config/glab-cli",          // GitLab CLI OAuth token
	".config/linode-cli",        // Linode CLI tokens
	".config/heroku",            // Heroku CLI session token
	".config/mysql",             // MySQL client login paths
	".config/mercurial",         // Mercurial auth sections
	".hg/hgrc",                  // Mercurial auth sections (legacy location)
	".dbshell",                  // MongoDB shell history
	".mysql_history",            // MySQL client history (statements with passwords)
	".rediscli_history",         // redis-cli history (AUTH lines)
	"/etc/mysql/debian.cnf",     // Debian maintenance account password
	"/etc/security/opasswd",     // PAM old-password history
	// OpenSSH host keys are spelled with underscores and end in "_key", so the
	// dotted ".key" extension rule never saw them.
	"ssh_host_rsa_key", "ssh_host_ed25519_key", "ssh_host_ecdsa_key", "ssh_host_dsa_key",
}

// secretEnvironmentTokens are the name components that mark an environment
// variable as holding credential material: a value read from such a variable is
// a secret source, exactly as a read of a secret file is.
//
// The test is per name component (split on "_" and on the other non-alphanumeric
// bytes), not a blind substring, so "AWS_REGION" and "GITHUB_REPOSITORY" are not
// secrets while "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "MY_API_KEY" and
// "PGPASSWORD" are. A component must equal one of the tokens, so "MONKEY" is not
// a "KEY".
var secretEnvironmentTokens = map[string]bool{
	"SECRET": true, "SECRETS": true, "TOKEN": true, "TOKENS": true,
	"PASSWORD": true, "PASSWD": true, "PGPASSWORD": true, "PASSPHRASE": true,
	"CREDENTIAL": true, "CREDENTIALS": true, "CRED": true, "CREDS": true,
	"KEY": true, "APIKEY": true, "ACCESSKEY": true, "PRIVATEKEY": true,
	"SESSIONKEY": true, "AUTH": true, "AUTHORIZATION": true, "BEARER": true,
	"COOKIE": true, "COOKIES": true, "PAT": true,
}

// SecretEnvName reports whether an environment-variable name marks the variable
// as holding credential material. name is accepted in the spellings a frontend
// may carry: "GITHUB_TOKEN", "$GITHUB_TOKEN", "${GITHUB_TOKEN}", "$env:GITHUB_TOKEN",
// "%GITHUB_TOKEN%".
func SecretEnvName(name string) bool {
	n := strings.TrimSpace(name)
	n = strings.TrimPrefix(n, "${")
	n = strings.TrimPrefix(n, "$env:")
	n = strings.TrimPrefix(n, "$")
	n = strings.TrimPrefix(n, "%")
	n = strings.TrimSuffix(n, "}")
	n = strings.TrimSuffix(n, "%")
	if n == "" {
		return false
	}
	for _, comp := range strings.FieldsFunc(n, func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ':' || r == '/' || r == '\\'
	}) {
		if secretEnvironmentTokens[strings.ToUpper(comp)] {
			return true
		}
	}
	return false
}

// secretExtensionMarkers are file-name extensions that mark a private key or a
// key/certificate store; each matches when it is the basename's suffix
// ("/etc/ssl/private/tls.key") or when the basename carries further extension
// text right after it ("/etc/ssl/private/server.pem.old", "id_rsa.key.2024").
var secretExtensionMarkers = []string{".pem", ".key", ".p12", ".pfx", ".pkcs12"}

// SecretPath reports whether p names (or lies under) a well-known credential or
// secret location.
//
// The marker comparison runs on the lexically normalised path as well as on the
// spelling as written: the kernel resolves "/etc//shadow", "/etc/./shadow",
// "/tmp/../etc/shadow" and the Windows "C:\…\.kube\config" spelling to exactly
// the file the marker names, and a denylist that compares raw text does not.
// Normalisation is lexical only — nothing is read from the filesystem — and it
// can only ADD matches, so every path recognised before is still recognised.
func SecretPath(p string) bool {
	if p == "" {
		return false
	}
	lp := strings.ToLower(p)
	if pathHasSecretMarker(lp) {
		return true
	}
	if c := cleanTargetPath(lp); c != lp {
		if pathHasSecretMarker(c) {
			return true
		}
	}
	// A word carrying glob metacharacters is not one file but a set selected by
	// the pattern; its static part still names the location the command reads
	// (Finding 67's residual: `cat /etc/shad*` selects /etc/shadow).
	return secretPatternPath(lp)
}

// globMetas are the unquoted shell metacharacters that turn a word into a
// pattern: `*`, `?` and the `[` of a bracket expression.
const globMetas = "*?["

// secretPatternPath reports whether a shell glob pattern selects credential
// material. Only the pattern's static part (the text before its first
// metacharacter) is evidence, and three shapes are recognised:
//
//   - the static part ends at a credential directory (`/root/.ssh/*`,
//     `/tmp/app/.env/*`), so every entry the pattern enumerates is credential
//     material;
//   - the static part is a file inside a credential directory
//     (`/root/.ssh/id_*`, `~/.aws/cred*`);
//   - the static basename is the beginning of a credential name in the same
//     directory (`/etc/shad*` → /etc/shadow, `~/.ssh/id_` → id_rsa).
//
// The rule is deliberately one-sided: it can label a pattern as credential
// material, never unlabel a path the exact rules already recognise, and it
// reads nothing from the filesystem (the directory is never enumerated).
func secretPatternPath(lp string) bool {
	i := strings.IndexAny(lp, globMetas)
	if i < 0 {
		return false
	}
	prefix := lp[:i]
	if prefix == "" {
		return false
	}
	// The pattern enumerates a directory: the directory is the static part.
	if strings.HasSuffix(prefix, "/") || strings.HasSuffix(prefix, `\`) {
		return pathHasSecretMarker(strings.TrimRight(prefix, `/\`))
	}
	dir, base := splitDirBase(prefix)
	// Every entry of a credential directory is credential material.
	if dir != "" && pathHasSecretMarker(dir) {
		return true
	}
	// The static basename begins a credential name.
	return basePrefixesMarker(dir, base)
}

// splitDirBase splits a path spelling at its last separator. dir carries no
// trailing separator; base is the final component (possibly empty).
func splitDirBase(p string) (dir, base string) {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

// basePrefixesMarker reports whether base is a proper prefix of a credential
// name that lives in dir. A path-valued marker ("/etc/shadow") also pins the
// directory, so `/etc/shad*` matches while `/tmp/shad*` does not; a bare marker
// ("id_rsa", ".env", "credentials") is matched by basename alone. A one-byte
// prefix is ignored: it selects too much to be evidence of anything.
func basePrefixesMarker(dir, base string) bool {
	if len(base) < 2 {
		return false
	}
	for _, m := range secretPathMarkers {
		md, mb := splitDirBase(m)
		if md == "" {
			if strings.HasPrefix(m, base) {
				return true
			}
			continue
		}
		if strings.HasPrefix(mb, base) && strings.HasSuffix(md, "/"+strings.TrimPrefix(dir, "/")) {
			return true
		}
	}
	for _, ext := range secretExtensionMarkers {
		if strings.HasPrefix(ext, base) {
			return true
		}
	}
	return false
}

// pathHasSecretMarker applies the marker rules to one path spelling.
func pathHasSecretMarker(lp string) bool {
	base := lp
	if i := strings.LastIndexAny(lp, "/\\"); i >= 0 {
		base = lp[i+1:]
	}
	for _, m := range secretPathMarkers {
		if m[0] == '.' && !strings.Contains(m, "/") {
			// A dot marker is a hidden name: it matches at the start of a path
			// component (".ssh", "…/.env") or as the basename's suffix
			// ("prod.env"), but never mid-component, so "my.envelope" is not a
			// ".env" secret.
			if componentStarts(lp, m) || strings.HasSuffix(base, m) {
				return true
			}
			continue
		}
		if strings.Contains(lp, m) {
			return true
		}
	}
	for _, ext := range secretExtensionMarkers {
		if baseMatchesExt(base, ext) {
			return true
		}
	}
	return false
}

// baseMatchesExt reports whether the extension ext marks the basename b: it is
// b's suffix ("tls.key") or b carries further extension text right after it
// ("server.pem.old", "id_rsa.key.2024"). A marker followed by non-extension
// text ("app.pemx") does not match.
func baseMatchesExt(b, ext string) bool {
	i := strings.LastIndex(b, ext)
	if i < 0 {
		return false
	}
	rest := b[i+len(ext):]
	return rest == "" || rest[0] == '.'
}

// componentStarts reports whether marker begins a path component of lp: it is
// found at the start of lp or immediately after a path separator. The marker
// may be a prefix of the component (".env" matches ".env.recon") but must not
// appear mid-component, so ".env" does not match "my.envelope".
func componentStarts(lp, marker string) bool {
	for i := 0; i < len(lp); {
		j := strings.Index(lp[i:], marker)
		if j < 0 {
			return false
		}
		at := i + j
		if at == 0 || lp[at-1] == '/' || lp[at-1] == '\\' {
			return true
		}
		i = at + 1
	}
	return false
}

// anySecretTarget reports whether s includes at least one secret path.
func anySecretTarget(s Scope) bool {
	for _, t := range s.Targets() {
		if SecretPath(t) {
			return true
		}
	}
	return false
}

// IsSecretRead reports whether e obtains credential/secret material: a
// CredAccess effect, a read of a secret-bearing path, a read of a
// credential-shaped environment variable (AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN,
// …), or secret-tainted data.
func IsSecretRead(e Effect) bool {
	switch e.Kind {
	case KindCredAccess:
		return true
	case KindFSRead, KindFSMeta:
		return e.Taint.Contains(TaintSecret) || anySecretTarget(e.Target)
	case KindEnvRead:
		// A credential held in the environment is as much a secret source as the
		// file that holds it: `printenv AWS_SECRET_ACCESS_KEY | curl -d @- …`
		// must pair like `curl -d @~/.aws/credentials …` does. Only a
		// credential-SHAPED name qualifies, so a read of PATH or HOME is not a
		// secret and never fabricates an exfiltration finding.
		if e.Taint.Contains(TaintSecret) || anySecretEnvTarget(e.Target) {
			return true
		}
		// Reading the environment as a whole — `printenv` with no operand,
		// `export -p`, `declare -p`, PowerShell's `Get-ChildItem Env:`, or an
		// environment read whose variable name is not statically known (⊥/⊤
		// target) — selects whatever credentials the process environment holds
		// (CI runners and agent runtimes export GITHUB_TOKEN,
		// AWS_SECRET_ACCESS_KEY, NPM_TOKEN). The set of names is not known, so
		// the read is secret-bearing by construction: an upload of it is the
		// exfiltration Finding 7 records, not an ordinary request.
		if len(e.Target.Targets()) == 0 {
			return true
		}
		return false
	default:
		return false
	}
}

// anySecretEnvTarget reports whether s includes at least one credential-shaped
// environment-variable name or names the environment as a whole.
func anySecretEnvTarget(s Scope) bool {
	for _, t := range s.Targets() {
		if SecretEnvName(t) || wholeEnvironmentTarget(t) {
			return true
		}
	}
	return false
}

// wholeEnvironmentTarget reports whether t names the process environment as a
// whole rather than a single variable. The spellings are the ones the frontends
// emit for an enumeration: PowerShell's `Get-ChildItem Env:` provider target,
// the `/proc/self/environ` pseudo-file, and the bare provider/namespace names.
// `ENV` is included because a shell that spells the whole environment that way
// (`$ENV`) is reading the same set; over-approximating a read of a variable
// literally named ENV is the safe side.
func wholeEnvironmentTarget(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "env:", "env", "environment", "environ", "/proc/self/environ":
		return true
	}
	return false
}

// ===========================================================================
// Cross-command staging of credential material (Finding 94)
// ===========================================================================

// PathKey returns the key two filesystem targets are compared by when the
// analysis follows content from one command to another: the lexical
// normalisation cleanTargetPath applies (separator runs, "." and ".."
// segments) plus case folding for a Windows-shaped spelling, where the
// filesystem itself is case-insensitive. Nothing is read from the filesystem.
func PathKey(p string) string {
	k := cleanTargetPath(strings.TrimSpace(p))
	if isWindowsShaped(k) {
		k = strings.ToLower(k)
	}
	return k
}

// ApplySecretStaging applies the two halves of the staging rule (Finding 94) to
// one command's effects, in statement order.
//
// A credential can leave the host in two steps: one command copies it into a
// file (`tar czf /tmp/x.tgz /etc/shadow`, `cp key /tmp/k`, `cat key > /tmp/k`)
// and a later command uploads that file. The IR records both operations
// correctly — a read, a write, an egress — but the write carries none of the
// provenance of what the writing command read, so the upload's read is not a
// secret source and DetectExfil reports no pair.
//
// The rule restores the flow in two one-sided steps, each applied only within
// the command that performs it:
//
//  1. read-back — a read (FSRead/FSMeta) of a path an *earlier* command staged
//     is a read of credential material, so the secret label is joined onto it;
//  2. staging — every path a command writes (FSWrite) while it reads credential
//     material holds that material, so the secret label is joined onto the
//     write and the path enters staged.
//
// staged is the program's set of staged path keys (see PathKey); the caller
// keeps it across statements, so a chain of commands (tar → convert → upload)
// keeps the label. Step 1 consults the set as it stood before this command, so
// a command that both reads and writes the same path (an archiver that names
// its own archive as an operand) does not stage itself: only a later read pairs.
//
// The rule never fabricates a source — a command that reads no credential
// material stages nothing, so an ordinary staged build artefact stays
// unpaired — and it only ever adds the secret label, never removes one. It
// mutates stmt in place; callers pass a slice of their own effect list.
func ApplySecretStaging(stmt []Effect, staged map[string]bool) {
	if len(stmt) == 0 {
		return
	}
	// 1. Read-back: content an earlier command staged is credential material.
	promoted := false
	for i := range stmt {
		e := &stmt[i]
		if e.Kind != KindFSRead && e.Kind != KindFSMeta {
			continue
		}
		for _, t := range e.Target.Targets() {
			if stagedMatch(PathKey(t), staged) {
				e.Taint = e.Taint.Join(TaintOf(TaintSecret))
				promoted = true
				break
			}
		}
	}
	if promoted {
		// A command that reads staged credential material and reaches the
		// network in the same statement carries that material out: the sink
		// takes the secret label the read now has. The join is scoped to the
		// statement that performed the read, so a program that merely staged a
		// file does not taint an unrelated request, and a command that carries
		// the credential as data (a token in a header) is left to the existing
		// per-command rules.
		for i := range stmt {
			if stmt[i].Kind == KindNetEgress {
				stmt[i].Taint = stmt[i].Taint.Join(TaintOf(TaintSecret))
			}
		}
	}
	// 2. Staging: what this command handled of credential material, it wrote.
	// "Handled" is deliberately wider than "read": a credential can reach the
	// writing command through a variable rather than through an operand
	// (`x=$(cat key); printf '%s' "$x" > /tmp/k`), so an effect that carries
	// the secret label counts as well as a secret read. An unknown (⊤)
	// provenance is not evidence of credential material — treating it as such
	// would relabel every unknown write — so only an explicit label stages.
	secret := false
	for _, e := range stmt {
		// A secret read, a value that already carries the label, or a target
		// that *names* a credential location: the last case is what an archiver
		// row that binds its operands as writes (`7z a ARCHIVE SECRET`) reports
		// instead of a read, and the material it names is credential material
		// all the same.
		if IsSecretRead(e) || (!e.Taint.IsTop() && e.Taint.Contains(TaintSecret)) || anySecretTarget(e.Target) {
			secret = true
			break
		}
	}
	if !secret {
		return
	}
	for i := range stmt {
		if stmt[i].Kind != KindFSWrite {
			continue
		}
		stmt[i].Taint = stmt[i].Taint.Join(TaintOf(TaintSecret))
		if staged == nil {
			continue
		}
		for _, t := range stmt[i].Target.Targets() {
			staged[PathKey(t)] = true
		}
	}
}

// stagedMatch reports whether a read of the path key reads material a command
// staged. Besides the exact path, two shapes are recognised, both of which name
// a *set* of paths rather than one:
//
//   - a directory write covers every name under it: `cp -r ~/.ssh /tmp/k`
//     stages /tmp/k, and a read of /tmp/k/id_rsa reads staged material;
//   - a generated-name prefix covers the names built from it: `split FILE
//     PREFIX` writes PREFIXaa, PREFIXab, … while the model can only name
//     PREFIX, so a read of PREFIXaa reads staged material.
//
// The prefix test is limited to a prefix that cannot itself continue a file
// name (a separator, or punctuation), so staging /tmp/x never matches a read of
// /tmp/xyz. Both rules are one-sided: they can only label a read as staged.
func stagedMatch(key string, staged map[string]bool) bool {
	if len(staged) == 0 || key == "" {
		return false
	}
	if staged[key] {
		return true
	}
	for i := 1; i < len(key); i++ {
		c := key[i-1]
		switch {
		case c == '/' || c == '\\':
			// A write of the directory covers every name under it.
			if staged[key[:i]] || (i > 1 && staged[key[:i-1]]) {
				return true
			}
		case !isASCIINameByte(c):
			// A generated-name prefix: split PREFIX → PREFIXaa.
			if staged[key[:i]] {
				return true
			}
		}
	}
	return false
}

// isASCIINameByte reports whether c can continue a file name: a letter, a digit
// or a space. Anything else (a separator, punctuation) ends a name, so a staged
// path ending there is a prefix rather than a name.
func isASCIINameByte(c byte) bool {
	return isASCIILetter(c) || (c >= '0' && c <= '9') || c == ' ' || c >= 0x80
}

// IsEgressSink reports whether e carries data off-host: a NetEgress whose payload
// is tainted (its provenance is known, so content actually leaves the host).
func IsEgressSink(e Effect) bool {
	if e.Kind != KindNetEgress {
		return false
	}
	return !e.Taint.IsBottom()
}

// Exfil is one credential-exfiltration finding: a secret read paired with an
// outbound sink carrying tainted data — CredAccess/FSRead(secret) ⊗
// NetEgress(tainted).
type Exfil struct {
	// Source is the secret read: a CredAccess effect, or an FSRead/FSMeta of a
	// secret-bearing path.
	Source Effect `json:"source"`
	// Sink is the tainted egress that carries the read data out.
	Sink Effect `json:"sink"`
}

// DetectExfil returns every (secret source, tainted egress) pairing found in
// effects, in canonical (deterministic) order.
func DetectExfil(effects []Effect) []Exfil {
	var sources, sinks []Effect
	for _, e := range effects {
		if IsSecretRead(e) {
			sources = append(sources, e)
		}
		if IsEgressSink(e) {
			sinks = append(sinks, e)
		}
	}
	var out []Exfil
	for _, s := range sources {
		for _, k := range sinks {
			out = append(out, Exfil{Source: s, Sink: k})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source.Key() != out[j].Source.Key() {
			return out[i].Source.Key() < out[j].Source.Key()
		}
		return out[i].Sink.Key() < out[j].Sink.Key()
	})
	return out
}

// ===========================================================================
// Network data flows: cradle and ingest
// ===========================================================================

// CradleFlow is one network-to-code-execution flow: content fetched over the
// network reaches a code-execution sink. Source is a NetEgress the content could
// have arrived on; Sink is the CodeExec the analysis found reached by network
// content (a pipe to a shell/interpreter, a source/`.` of a fetched path, a sink
// invoked on a command substitution). The exec of a path a download wrote is
// not currently asserted: no frontend establishes that flow.
//
// The IR carries the flow evidence per sink (Effect.NetFlow == FlowCradle) but
// records no link from a sink to the particular egress that fed it, so Source is
// the egress set of the whole program rather than one identified connection; see
// DetectCradleFlows.
type CradleFlow struct {
	Source Effect `json:"source"`
	Sink   Effect `json:"sink"`
}

// IngestFlow is one network-to-filesystem flow: a download client writes
// content it fetched to a file. Source is a NetEgress the content could have
// arrived on; Sink is the FSWrite of the downloaded body (curl -o/-O, wget
// default/-O). As with CradleFlow, Source is the program's egress set, not a
// link to the egress that fed this sink; see DetectIngestFlows.
type IngestFlow struct {
	Source Effect `json:"source"`
	Sink   Effect `json:"sink"`
}

// IsCradleSink reports whether e is a code execution reached by network content
// (the download-cradle shape).
func IsCradleSink(e Effect) bool { return e.Kind == KindCodeExec && e.NetFlow == FlowCradle }

// IsIngestSink reports whether e is a filesystem write of downloaded content.
func IsIngestSink(e Effect) bool { return e.Kind == KindFSWrite && e.NetFlow == FlowIngest }

// DetectCradleFlows returns every network-to-code-execution flow established by
// the analysis, in canonical (deterministic) order: each CodeExec the frontend
// flagged as reached by network content (Effect.NetFlow == FlowCradle) paired
// with a NetEgress of the program.
//
// A flow is asserted only for a flagged sink: a NetEgress alone, or a CodeExec
// alone, produces no pair, so the mere co-occurrence of an egress and an
// untagged code execution asserts nothing.
//
// The pairing itself is an over-approximation, and deliberately so: the effect
// IR carries the flow evidence on the sink but no link from that sink to the
// egress that fed it (the Effect field set is frozen), so a sink flagged as
// cradle is paired with *every* NetEgress of the program. For a program that
// fetched over n connections and executed one of them, all n pairs are
// reported: the pair for the connection that actually fed the sink is always
// among them (no established flow is lost), at the cost of n-1 pairs naming a
// source that did not feed this particular sink. A consumer must therefore read
// a pair as "network content reached this sink, and this is one of the program's
// egresses", not as a confirmed end-to-end path between exactly those two
// effects.
func DetectCradleFlows(effects []Effect) []CradleFlow {
	sources := netEgressSources(effects)
	var sinks []Effect
	for _, e := range effects {
		if IsCradleSink(e) {
			sinks = append(sinks, e)
		}
	}
	var out []CradleFlow
	for _, s := range sources {
		for _, k := range sinks {
			out = append(out, CradleFlow{Source: s, Sink: k})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source.Key() != out[j].Source.Key() {
			return out[i].Source.Key() < out[j].Source.Key()
		}
		return out[i].Sink.Key() < out[j].Sink.Key()
	})
	return out
}

// DetectIngestFlows returns every network-to-filesystem flow established by the
// analysis, in canonical (deterministic) order: each FSWrite flagged as a
// download output (Effect.NetFlow == FlowIngest) paired with a NetEgress of the
// program.
//
// As with DetectCradleFlows, the source of a pair is the program's egress set
// rather than the one connection that fed the sink (the IR records no such
// link), so a program that downloaded from n connections reports n pairs per
// flagged write.
func DetectIngestFlows(effects []Effect) []IngestFlow {
	sources := netEgressSources(effects)
	var sinks []Effect
	for _, e := range effects {
		if IsIngestSink(e) {
			sinks = append(sinks, e)
		}
	}
	var out []IngestFlow
	for _, s := range sources {
		for _, k := range sinks {
			out = append(out, IngestFlow{Source: s, Sink: k})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source.Key() != out[j].Source.Key() {
			return out[i].Source.Key() < out[j].Source.Key()
		}
		return out[i].Sink.Key() < out[j].Sink.Key()
	})
	return out
}

// netEgressSources collects every NetEgress effect of the program, in the
// effects' given order. Every one of them is a candidate source for any flagged
// sink, since an effect carries no link to the egress that actually fed it (see
// DetectCradleFlows).
func netEgressSources(effects []Effect) []Effect {
	var out []Effect
	for _, e := range effects {
		if e.Kind == KindNetEgress {
			out = append(out, e)
		}
	}
	return out
}
