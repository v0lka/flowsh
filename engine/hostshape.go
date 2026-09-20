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

// localURLSchemes are URI schemes that name a local or non-network resource: a
// file, an in-document payload, an email address. A token carrying one of
// these never names a network address, so the gate rejects it even though it is
// scheme-prefixed (file:///etc/passwd, data:…, mailto:a@b).
var localURLSchemes = map[string]bool{
	"file": true, "data": true, "mailto": true, "about": true,
	"blob": true, "javascript": true, "ws+file": true,
}

// hostShaped is the shared core of the two exported predicates.
func hostShaped(s string, lenient bool) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}

	// A scheme-prefixed URL: scheme://… — the scheme prefix itself declares
	// network intent, so the authority after it is accepted as-is (http://evil,
	// ftp://10.0.0.1/pub, https://2130706433/x). A scheme that names a
	// non-network resource is rejected: it declares no address.
	if i := strings.Index(s, "://"); i > 0 {
		if !validScheme(s[:i]) || localURLSchemes[strings.ToLower(s[:i])] {
			return false
		}
		return len(s) > i+3
	}
	// The same non-network schemes in their scheme:specific-part spelling
	// (file:/etc/passwd, data:text/plain,…, mailto:a@b.example): no address.
	if i := strings.IndexByte(s, ':'); i > 0 && localURLSchemes[strings.ToLower(s[:i])] {
		return false
	}

	// Whitespace never appears in an address; a backslash only appears in a
	// Windows path or an escaped token — neither is a network address.
	if strings.ContainsAny(s, " \t\r\n\\") {
		return false
	}

	// A Windows drive path (C:/x, C:\x, C:) is a filesystem path, not a host.
	if isDrivePath(s) {
		return false
	}

	// A UNC / SMB authority (//host[/share]): the leading double slash is the
	// authority introducer, not the path boundary the cut below would take it
	// for.
	if strings.HasPrefix(s, "//") {
		rest := strings.TrimLeft(s, "/")
		if i := strings.IndexAny(rest, `/\`); i >= 0 {
			rest = rest[:i]
		}
		if i := strings.LastIndexByte(rest, ':'); i > 0 {
			if tail := rest[i+1:]; tail == "" || validPort(tail) {
				rest = rest[:i]
			}
		}
		return rest != "" && hostNameShaped(rest, lenient)
	}

	// Strip a leading userinfo (user@host, git@github.com:…) only when what
	// precedes the last '@' is an authority prefix and not a path: a token whose
	// text before '@' contains a separator is a path carrying '@', not userinfo.
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		if strings.ContainsAny(s[:i], `/\`) {
			return false
		}
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

	// A bracketed IPv6 literal, optionally with a port or an scp-style path:
	// [::1], [::1]:4444, [2001:db8::1]:/tmp/x.
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 || end == 1 {
			return false
		}
		if net.ParseIP(stripZone(s[1:end])) == nil {
			return false
		}
		rest := s[end+1:]
		if rest == "" {
			return true
		}
		// The tail is an optional ":port" or the scp ":path" spelling; both
		// name an address-bearing remote, unlike a stray suffix.
		return strings.HasPrefix(rest, ":")
	}

	// A token with several colons is an IPv6 literal (optionally with a zone
	// id), an scp-form remote over an IPv6 host (host:path), or — for a
	// declared-destination caller — a client's protocol-prefixed address
	// (socat TCP:host:port, rclone :backend:host:/path).
	if colons := strings.Count(s, ":"); colons >= 2 {
		if net.ParseIP(stripZone(s)) != nil {
			return true
		}
		if i := strings.LastIndexByte(s, ':'); i > 0 {
			if net.ParseIP(stripZone(s[:i])) != nil {
				return true
			}
		}
		if lenient {
			if rest, ok := stripEgressPrefix(s); ok {
				return hostShaped(rest, true)
			}
		}
		return false
	}

	// Split an optional :port (or the scp-form :path, handled below).
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
			// spec main:backend/config.go — "main" is not). The caller's
			// leniency is forwarded, so a declared-destination slot also accepts
			// a bare single-label remote (rclone remote:bucket, ssh bastion:path).
			return host != "" && hostShaped(host, lenient)
		}
	}

	return hostNameShaped(s, lenient)
}

// isDrivePath reports whether s is a Windows drive path (C:/x, C:\x or a bare
// C:) rather than a host. A single-letter label followed by ':' and a separator
// (or the end of the token) is a drive, never a network host.
func isDrivePath(s string) bool {
	return len(s) >= 2 && isAlpha(s[0]) && s[1] == ':' &&
		(len(s) == 2 || s[2] == '/' || s[2] == '\\')
}

// stripZone removes an IPv6 zone identifier (%eth0) from an address literal,
// leaving the bare address for validation.
func stripZone(s string) string {
	if i := strings.IndexByte(s, '%'); i >= 0 {
		return s[:i]
	}
	return s
}

// egressProtocols are the transport prefixes the network clients put in front
// of their destination (socat TCP:host:port, OPENSSL:host:443). A lenient
// caller strips one before re-validating the remainder.
var egressProtocols = []string{
	"tcp:", "tcp4:", "tcp6:", "udp:", "udp4:", "udp6:",
	"openssl:", "ssl:", "socks:", "socks4:", "socks5:",
	"http:", "https:", "git:", "ssh:", "sftp:", "ftps:", "ftp:",
}

// stripEgressPrefix removes a client protocol prefix (TCP:host:port) or an
// rclone remote-backend prefix (:sftp:host:/path) from a declared-destination
// token, reporting the remainder to validate. It reports false when neither
// prefix is present.
func stripEgressPrefix(s string) (string, bool) {
	// rclone backend form: :backend:host[:/path].
	if strings.HasPrefix(s, ":") {
		if i := strings.IndexByte(s[1:], ':'); i >= 0 {
			return s[1+i+1:], true
		}
	}
	for _, p := range egressProtocols {
		if len(s) > len(p) && strings.EqualFold(s[:len(p)], p) {
			return s[len(p):], true
		}
	}
	return "", false
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
	// The version-control directory suffixes: a bare relative name like
	// "repo.git" (or "backup.repo") is a local repository path, the class of
	// phantom egress the gate exists to remove, not a host.
	"git": true, "hg": true, "svn": true, "bzr": true, "repo": true,
	"darcs": true, "fossil": true,
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
	// A single trailing dot is the RFC 1034 absolute-name marker (example.com.);
	// drop it for validation while the caller keeps the original text as the
	// target. A doubled dot is a malformed name and is left to fail below.
	if strings.HasSuffix(s, ".") && !strings.HasSuffix(s, "..") {
		s = s[:len(s)-1]
	}
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

// validPort reports whether p is a decimal port number in the TCP/UDP range
// (1-65535).
func validPort(p string) bool {
	if len(p) == 0 || len(p) > 5 {
		return false
	}
	v := 0
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
		v = v*10 + int(p[i]-'0')
	}
	return v > 0 && v <= 65535
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
			// Keep the validated (trimmed) form the grammar judged, so the gate
			// never reports a differently-shaped literal than the one it checked.
			keep = append(keep, strings.TrimSpace(t))
		}
	}
	if len(keep) == 0 {
		return ScopeBottom(), false
	}
	return ScopeOf(keep...), true
}
