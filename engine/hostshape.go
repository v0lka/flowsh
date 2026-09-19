package engine

import (
	"net"
	"strings"
)

// ===========================================================================
// Host/URL grammar for egress targets
// ===========================================================================
//
// A NetEgress effect may only be created with a target that names a plausible
// network address. Before this gate, the binder reported egress "targets" that
// were ordinary words of the command line: a git subcommand (`git status` bound
// its first operand to the clone/fetch/pull/push positional and reported
// NetEgress{"status"}), a commit SHA, a pathspec, an awk regex. Downstream
// consumers that key on the mere presence of a network effect (the
// "unbounded command with network egress" control) then fired on commands with
// no network token at all, and the secret-tainting rule turned such a phantom
// into a fabricated exfiltration pair.
//
// HostShaped is the grammar a literal must pass before it becomes the target
// of a NetEgress effect. It accepts:
//
//   - a scheme-prefixed URL (any scheme: http, https, ftp, git, ssh, …);
//   - an IPv4 or IPv6 literal, including the bracketed [v6]:port form and the
//     obfuscated IPv4 spellings (0x7f000001 hex, 2130706433 decimal);
//   - an scp-style remote [user@]host[:path], when the host part is itself
//     host-shaped (git@github.com:org/repo.git passes; the git object spec
//     main:backend/config.go does not — "main" is not a host);
//   - a dotted DNS name with an optional :port (api.example.com,
//     evil.example:4444), and the reserved name localhost.
//
// A bare single-label word is NOT host-shaped: "show", "status", "origin" and
// a short SHA are exactly the phantom spellings the gate exists to reject, and
// a real destination written without a dot is indistinguishable from them at
// the grammar level. Contexts where the token's role as a destination is
// declared by the construct itself (a network client's HOST positional, a
// /dev/tcp pseudo-path, a PowerShell -ComputerName parameter) use
// HostShapedLenient, which additionally accepts a bare single-label DNS name.
const (
	// maxDNSLabel is the RFC 1123 label length limit.
	maxDNSLabel = 63
	// localhostName is the one bare single-label name accepted even by the
	// strict grammar: it is a host by definition, not by shape.
	localhostName = "localhost"
)

// HostShaped reports whether s has the grammar of a network address a literal
// NetEgress target must carry: a scheme-prefixed URL, an IPv4/IPv6 literal
// (with the known obfuscated IPv4 spellings), an scp-style remote over a
// host-shaped host, or a dotted DNS name (optionally with :port). A bare
// single-label word is rejected (see the package comment above); a path, a
// SHA, a refspec or a subcommand name never passes.
func HostShaped(s string) bool {
	return hostShaped(s, false)
}

// HostShapedLenient is HostShaped plus the bare single-label DNS name: it is
// for tokens whose role as a network destination is declared by the construct
// they appear in (a network client's HOST positional, a /dev/tcp pseudo-path,
// a PowerShell -ComputerName value), where "evil" or "bastion" is a real
// intranet host and must not lose its egress effect.
func HostShapedLenient(s string) bool {
	return hostShaped(s, true)
}

// hostShaped is the shared core of the two exported predicates.
func hostShaped(s string, lenient bool) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, " \t\r\n\\") {
		// Whitespace never appears in an address; a backslash only appears in
		// a Windows path or an escaped token — neither is a network address.
		return false
	}

	// A scheme-prefixed URL: scheme://… — the scheme prefix itself declares
	// network intent, so anything after it is accepted as-is (http://evil,
	// ftp://10.0.0.1/pub, https://2130706433/x).
	if i := strings.Index(s, "://"); i > 0 {
		return validScheme(s[:i]) && len(s) > i+3
	}

	// Strip a leading userinfo (user@host, git@github.com:…). LastIndex, so a
	// password containing '@' still leaves the host intact.
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
		if s == "" {
			return false
		}
	}

	// Cut a trailing path component (scp-style host:/path, host/path).
	if i := strings.IndexAny(s, `/\`); i >= 0 {
		s = s[:i]
		if s == "" {
			return false
		}
	}

	// A bracketed IPv6 literal, optionally with a port: [::1]:4444.
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 || end == 1 {
			return false
		}
		if net.ParseIP(s[1:end]) == nil {
			return false
		}
		rest := s[end+1:]
		return rest == "" || (strings.HasPrefix(rest, ":") && validPort(rest[1:]))
	}

	// Split an optional :port (or the scp-form :path, handled below). A bare
	// IPv6 literal contains several colons and is validated as a whole.
	if colons := strings.Count(s, ":"); colons >= 2 {
		return net.ParseIP(s) != nil
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		host, tail := s[:i], s[i+1:]
		switch {
		case tail == "":
			// "host:" — the scp form with an empty path (attacker@evil.example:/).
			s = host
		case validPort(tail):
			s = host
		default:
			// host:path with a non-numeric path: the scp/git remote form. It is
			// a network address only when the host part is itself host-shaped
			// (git@github.com:org/repo.git — "github.com" is; the git object
			// spec main:backend/config.go — "main" is not).
			return host != "" && hostShaped(host, false)
		}
	}

	return hostNameShaped(s, lenient)
}

// fileExtLabels are final DNS labels that, in a command line, name a file, not
// a host: "code-review.md", "backend.diff", "appicon.png" are pathspecs and
// artifacts, not destinations. The strict grammar rejects them; the lenient
// (declared destination) grammar keeps them, because a network client's
// operand ending in one of these is still far more plausibly a host of the
// rare single-file TLDs (.md, .sh, …) than a filename — and an http:// prefix
// bypasses the DNS check entirely, so an URL to such a host is never lost.
var fileExtLabels = map[string]bool{
	"md": true, "txt": true, "diff": true, "patch": true, "log": true,
	"json": true, "yaml": true, "yml": true, "xml": true, "html": true,
	"css": true, "js": true, "ts": true, "tsx": true, "jsx": true,
	"go": true, "py": true, "rb": true, "rs": true, "java": true,
	"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true,
	"pdf": true, "gz": true, "zip": true, "tar": true, "tgz": true,
	"tmp": true, "bak": true, "old": true, "conf": true, "ini": true,
	"env": true, "lock": true, "mod": true, "sum": true, "csv": true,
	"sql": true, "db": true, "pem": true, "key": true, "crt": true,
	"bin": true, "exe": true, "so": true, "dylib": true, "out": true,
	"sh": true,
}

// hostNameShaped reports whether s is a DNS hostname: strict demands at least
// one dot (a multi-label name) or the reserved localhost; lenient also accepts
// a bare single-label name. Labels follow RFC 1123: 1-63 characters of
// letters, digits and hyphen, not starting or ending with a hyphen, and an
// all-numeric final label is rejected (it would be indistinguishable from an
// IPv4 fragment or a bare number). The strict mode additionally rejects a
// final label that names a file extension (see fileExtLabels).
func hostNameShaped(s string, lenient bool) bool {
	if s == "" {
		return false
	}
	if strings.EqualFold(s, localhostName) {
		return true
	}
	// Obfuscated IPv4 spellings are host-shaped in both modes: a hex literal
	// 0x7f000001 or a decimal literal 2130706433 that lands inside the IPv4
	// address range (see isIPv4Literal for the digit floor).
	if isIPv4Literal(s) {
		return true
	}
	labels := strings.Split(s, ".")
	if !lenient && len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !validDNSLabel(l) {
			return false
		}
	}
	last := labels[len(labels)-1]
	allDigits := true
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return false
	}
	return lenient || !fileExtLabels[strings.ToLower(last)]
}

// validDNSLabel reports whether l is one RFC 1123 hostname label: 1-63
// characters of [A-Za-z0-9-], not hyphen-bordered. Underscores are excluded —
// a token like foo_bar is a name from some other namespace, not a hostname.
func validDNSLabel(l string) bool {
	if len(l) == 0 || len(l) > maxDNSLabel {
		return false
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// validScheme reports whether s is a URI scheme: a letter followed by letters,
// digits, '+', '-' or '.'.
func validScheme(s string) bool {
	if len(s) == 0 || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case isAlpha(c), c >= '0' && c <= '9', c == '+', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// validPort reports whether p is a decimal port number (1-5 digits).
func validPort(p string) bool {
	if len(p) == 0 || len(p) > 5 {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
	}
	return true
}

// isIPv4Literal reports whether s is an IPv4 address in one of the spellings
// curl-class tools resolve: the dotted quad (127.0.0.1), the hex form
// (0x7f000001) or the decimal form (2130706433). The decimal form requires
// 9-10 digits — every public address spelled decimally is at least 9 digits,
// while an 8-digit number is far more likely a count, a PID or a git short
// SHA than an address in the 1.0.0.0–15.255.255.255 slice.
func isIPv4Literal(s string) bool {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return hexIPv4(s[2:])
	}
	if len(s) >= 9 && len(s) <= 10 {
		allDigits := true
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return decIPv4(s)
		}
	}
	return net.ParseIP(s) != nil && strings.Count(s, ".") == 3
}

// hexIPv4 reports whether s is 7-8 hex digits that decode inside the IPv4
// range (0x7f000001 → 127.0.0.1).
func hexIPv4(s string) bool {
	if len(s) < 7 || len(s) > 8 {
		return false
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return false
		}
		v = v<<4 | d
	}
	return v >= 0x01000000 && v <= 0xFFFFFFFF
}

// decIPv4 reports whether the decimal string s is inside the IPv4 range and
// at least 1.0.0.0 (a bare small number is a count or a PID, not an address).
func decIPv4(s string) bool {
	var v uint64
	for i := 0; i < len(s); i++ {
		v = v*10 + uint64(s[i]-'0')
		if v > 0xFFFFFFFF {
			return false
		}
	}
	return v >= 0x01000000 && v <= 0xFFFFFFFF
}

// FilterEgressTargets narrows a NetEgress target scope to its host-shaped
// literals. It is the gate every NetEgress-creating lowering step must pass
// its target through.
//
//   - ⊤ passes through unchanged: it is the *unresolved egress* (the target
//     came from a dynamic word — $URL), which must keep participating in the
//     network controls; dropping it would weaken the safe side.
//   - ⊥ passes through unchanged: it is a payload-only egress (curl -d @file),
//     whose destination is carried by another parameter of the same command.
//   - literal targets that are not host-shaped are dropped from the set; when
//     nothing remains, the boolean is false and the effect must not be created
//     at all — a literal that names no address is not network evidence.
//
// lenient selects HostShapedLenient (declared destination slots) over
// HostShaped (strict grammar).
func FilterEgressTargets(s Scope, lenient bool) (Scope, bool) {
	if s.IsTop() || s.IsBottom() {
		return s, true
	}
	var keep []string
	for _, t := range s.Targets() {
		if lenient && HostShapedLenient(t) || !lenient && HostShaped(t) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		return ScopeBottom(), false
	}
	return ScopeOf(keep...), true
}
