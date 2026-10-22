// Command flowsh is the public entry point of the effect analyser: it takes a
// shell or PowerShell command (as an argument or on stdin) and prints the set of
// effects it implies, as a human summary or a JSON report.
//
//	flowsh [--lang bash|posix|posh|auto] [--json] [--windows] '<command>'
//	echo '<command>' | flowsh [--lang bash|posix|posh|auto] [--json]
//	flowsh --batch [--lang bash|posix|posh|auto]
//
// The command is analysed by the same pipeline the library exposes: front/bash
// or front/ps parse and lower it, bind resolves it against the embedded
// knowledge base, and engine folds the result into the frozen effect IR. Where
// the analysis cannot bound the input it degrades to ⊤ rather than guessing.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/v0lka/flowsh/api"
	"github.com/v0lka/flowsh/engine"
)

const usage = `flowsh — effect report for a shell or PowerShell command

usage:
  flowsh [--lang bash|posix|posh|auto] [--json] [--windows] '<command>'
  echo '<command>' | flowsh [--lang bash|posix|posh|auto] [--json] [--windows]
  flowsh --batch [--lang bash|posix|posh|auto] [--windows]

options:
  --lang bash|posix|posh|auto
                     dialect of the input (default: bash); "auto" sniffs the
                     input for PowerShell cmdlets/aliases and picks the dialect
  --batch            read many commands (one per line) from stdin and write one
                     JSON report per line (NDJSON) instead of a single report;
                     a line that uses a variable an earlier line assigned is
                     degraded to top/conservative (cross-line state is not
                     modelled), so a script should be analysed as one command
  --json             emit the full JSON report instead of a summary
  --explain, --why   print the why-trace explaining each effect
  --windows[=bool]   enable PowerShell Registry semantics on any host OS
                     (default: the host's OS decides)
  --version          print the tool and engine versions and exit
  -h, --help         show this help and exit

exit status:
  0  analysis produced a report
  1  analysis failed internally
  2  usage error (unknown flag or unknown --lang)
  3  input error (stdin could not be read, or the command was empty)`

// The stable exit-code contract. run returns exactly one of these; new error
// classes must be mapped onto one of them rather than inventing ad-hoc codes.
const (
	exitOK       = 0 // a report was produced (or --help / --version)
	exitInternal = 1 // the analysis or the encoding failed internally
	exitUsage    = 2 // the invocation was malformed (flags, language, no input)
	exitInput    = 3 // stdin could not be read, or the command was empty
)

// buildVersion is the release build stamp, injected by the linker at release
// time (`-ldflags "-X main.buildVersion={{ .Version }}"`, see .goreleaser.yaml).
// A plain `go build`/`go test` leaves it empty, and an empty value is not
// printed. It is additive build metadata only: the frozen report-contract
// versions below (api.ToolVersion, engine.SchemaVersion) are never affected.
var buildVersion string

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

// usageError marks an invocation error: it is the caller's mistake (a bad flag,
// an unknown language, a missing value) and maps to
// exitUsage.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

// inputError marks a failure to read the named input source: an unreadable or
// missing file, a directory, or an empty command stream. It maps to exitInput,
// distinct from a usage error so a caller can tell "you invoked me wrong" from
// "your input could not be read".
type inputError struct{ err error }

func (e *inputError) Error() string { return e.err.Error() }
func (e *inputError) Unwrap() error { return e.err }

// exitCode maps a returned error onto the stable exit-code contract.
func exitCode(err error) int {
	var ierr *inputError
	if errors.As(err, &ierr) {
		return exitInput
	}
	var uerr *usageError
	if errors.As(err, &uerr) {
		return exitUsage
	}
	return exitInternal
}

// errorLine renders err for the CLI's stderr with the "flowsh: " prefix,
// adding it only when the message does not already carry it. Errors surfaced
// from the facade (and from api.ParseLang) are already prefixed, so a bare
// "flowsh: " here would print "flowsh: flowsh: …".
func errorLine(err error) string {
	msg := err.Error()
	if strings.HasPrefix(msg, "flowsh: ") {
		return msg
	}
	return "flowsh: " + msg
}

// options is the parsed command line.
type options struct {
	lang       string
	json       bool
	explain    bool
	batch      bool
	windows    bool
	windowsSet bool
	help       bool
	version    bool
	command    string
	commandSet bool
	useStdin   bool
}

// run is the whole program as a testable function: it parses args, reads the
// command from args or stdin, analyses it and writes the report to stdout. It
// returns the process exit status.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	o, err := parseArgs(args)
	if err != nil {
		fprint(stderr, "%s\n", errorLine(err))
		fprintln(stderr, usage)
		return exitUsage
	}
	if o.help {
		fprintln(stdout, usage)
		return exitOK
	}
	if o.version {
		fprint(stdout, "%s\n", api.ToolVersion)
		fprint(stdout, "%s\n", engine.SchemaVersion)
		if buildVersion != "" {
			fprint(stdout, "flowsh %s\n", buildVersion)
		}
		return exitOK
	}

	// An explicit language is validated before the input is read, so a usage
	// error never consumes stdin. With --lang auto the dialect can only be
	// picked once the input is known, so it is deferred to below.
	auto := isAutoLang(o.lang)
	var lang api.Lang
	if !auto {
		lang, err = api.ParseLang(o.lang)
		if err != nil {
			fprint(stderr, "%s\n", errorLine(err))
			return exitUsage
		}
	}

	src, err := readInput(o, stdin)
	if err != nil {
		fprint(stderr, "%s\n", errorLine(err))
		return exitInput
	}

	if o.batch {
		if err := runBatch(o, src, lang, auto, stdout); err != nil {
			fprint(stderr, "%s\n", errorLine(err))
			return exitCode(err)
		}
		return exitOK
	}

	// --windows forces the PowerShell Registry provider on (or, with
	// --windows=false, off) independently of the host; when the flag is absent
	// the analysis keeps its host default (registry active only on Windows).
	// Root names the source the command came from, so the report says whether
	// it analysed the positional argument or stdin.
	opts := optsFor(o)
	opts.Root = src.root
	var rep *api.Report
	if auto {
		rep, err = analyzeAuto(src.src, opts)
	} else {
		rep, err = api.AnalyzeWith(lang, src.src, opts)
	}
	if err != nil {
		fprint(stderr, "%s\n", errorLine(err))
		return exitInternal
	}

	if o.json {
		out, err := rep.Encode()
		if err != nil {
			fprint(stderr, "flowsh: encode report: %v\n", err)
			return exitInternal
		}
		fprintln(stdout, string(out))
		return exitOK
	}
	writeText(stdout, rep)
	if o.explain {
		writeWhy(stdout, rep)
	}
	return exitOK
}

// parseArgs parses flags in any position, so both
// "flowsh --lang posh 'x'" and "flowsh 'x' --lang posh" work.
func parseArgs(args []string) (options, error) {
	o := options{lang: string(api.LangBash)}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help" || a == "-help":
			o.help = true
		case a == "--version" || a == "-version":
			o.version = true
		case a == "--json" || a == "-json":
			o.json = true
		case a == "--batch" || a == "-batch":
			o.batch = true
		case a == "--explain" || a == "--why" || a == "-explain" || a == "-why":
			o.explain = true
		case a == "--windows" || a == "-windows":
			o.windows = true
			o.windowsSet = true
		case strings.HasPrefix(a, "--windows=") || strings.HasPrefix(a, "-windows="):
			v := a[strings.IndexByte(a, '=')+1:]
			b, err := strconv.ParseBool(v)
			if err != nil {
				return o, &usageError{fmt.Errorf("--windows: %q is not a boolean", v)}
			}
			o.windows = b
			o.windowsSet = true
		case a == "--lang" || a == "-lang":
			if i+1 >= len(args) {
				return o, &usageError{fmt.Errorf("%s needs a value", a)}
			}
			i++
			o.lang = args[i]
		case strings.HasPrefix(a, "--lang="):
			o.lang = strings.TrimPrefix(a, "--lang=")
		case strings.HasPrefix(a, "-lang="):
			o.lang = strings.TrimPrefix(a, "-lang=")
		case a == "-":
			o.useStdin = true
		case strings.HasPrefix(a, "-") && a != "-":
			return o, &usageError{fmt.Errorf("unknown flag %q", a)}
		default:
			if o.commandSet {
				return o, &usageError{fmt.Errorf("unexpected extra argument %q", a)}
			}
			o.command = a
			o.commandSet = true
		}
	}
	if o.useStdin && o.commandSet {
		return o, &usageError{fmt.Errorf("the \"-\" stdin argument and a positional command are mutually exclusive")}
	}
	if o.batch && o.commandSet {
		return o, &usageError{fmt.Errorf("--batch and a positional command are mutually exclusive")}
	}
	if o.batch && o.explain {
		return o, &usageError{fmt.Errorf("--explain cannot be combined with --batch")}
	}
	return o, nil
}

// input is the command to analyse together with the name of the source it came
// from: a file path, or the stdin/argument marker.
type input struct {
	src  string
	root string
}

// readInput returns the command to analyse and the name of its source. The
// command comes from the positional argument, else from stdin (also when the
// argument is "-"). The root is RootStdin or RootArgument, so the report names
// its source distinctly. Failures to read the source are inputError (exit 3),
// distinct from a usage error.
//
// The analyser reads no caller-named file: the input surface is the argument
// and stdin only, so the CLI cannot be turned into an arbitrary-file-read
// primitive by a wrapper that forwards untrusted paths (SECURITY.md Hard
// Constraint 2).
func readInput(o options, stdin io.Reader) (input, error) {
	switch {
	case o.useStdin || !o.commandSet:
		s, err := readStdin(stdin)
		if err != nil {
			return input{}, err
		}
		return input{src: s, root: api.RootStdin}, nil
	default:
		cmd := strings.TrimSpace(o.command)
		if cmd == "" {
			return input{}, &inputError{fmt.Errorf("empty command argument")}
		}
		return input{src: cmd, root: api.RootArgument}, nil
	}
}

// readStdin reads and trims the whole of stdin, rejecting an empty command.
func readStdin(stdin io.Reader) (string, error) {
	data, err := io.ReadAll(stdin)
	if err != nil {
		return "", &inputError{fmt.Errorf("read stdin: %w", err)}
	}
	s := strings.TrimRight(string(data), "\r\n")
	if strings.TrimSpace(s) == "" {
		return "", &inputError{fmt.Errorf("no command given and stdin is empty")}
	}
	return s, nil
}

// runBatch analyses many commands and writes the reports as NDJSON: one
// compact, single-line JSON report per non-blank input line, in input order.
// With --lang auto the dialect is picked per line (a batch may mix dialects).
// The whole batch shares the input source's root. An empty batch is an input
// error (exit 3); a per-line analysis/encode failure is internal (exit 1).
func runBatch(o options, in input, lang api.Lang, auto bool, stdout io.Writer) error {
	lines := splitBatch(in.src)
	if len(lines) == 0 {
		return &inputError{fmt.Errorf("no commands in batch input")}
	}
	opts := optsFor(o)
	opts.Root = in.root
	var state batchState
	continued := false
	for _, line := range lines {
		var rep *api.Report
		var err error
		if auto {
			rep, err = analyzeAuto(line, opts)
		} else {
			rep, err = api.AnalyzeWith(lang, line, opts)
		}
		if err != nil {
			return err
		}
		// A line that continues onto the next one (a trailing backslash, an
		// open quote) is a fragment, and so is the line that follows it: neither
		// is the command the report describes.
		cont := lineContinues(line)
		if continued || cont {
			degrade(rep, "batch line is a fragment of a program that spans lines")
		}
		continued = cont
		state.check(rep, line)
		state.note(rep, line)
		out, err := encodeCompact(rep)
		if err != nil {
			return fmt.Errorf("encode report: %w", err)
		}
		fprintln(stdout, string(out))
	}
	return nil
}

// splitBatch splits a batch source into its commands: one per line, with
// carriage returns and surrounding whitespace stripped, blank lines dropped.
func splitBatch(src string) []string {
	var out []string
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

// encodeCompact validates the report and returns its compact single-line JSON,
// as NDJSON requires (Encode's indented form would span several lines).
func encodeCompact(r *api.Report) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

// fprint and fprintln write the CLI's terminal output. These are one-shot
// writes to stdout/stderr, where a short write cannot be recovered and the
// process exit status is already decided, so the error is deliberately
// discarded. Routing every write through these two helpers keeps that one
// decision in a single place instead of scattering //nolint directives
// across the whole output path.
func fprint(w io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }

func fprintln(w io.Writer, args ...any) { _, _ = fmt.Fprintln(w, args...) }

// writeText renders the human-readable summary.
func writeText(w io.Writer, r *api.Report) {
	fprint(w, "flowsh effect report\n")
	fprint(w, "  lang:            %s\n", sanitize(r.Lang))
	fprint(w, "  input:           %s\n", oneLine(r.Input))
	if r.Root != "" {
		fprint(w, "  root:            %s\n", sanitize(r.Root))
	}
	fprint(w, "  commands:        %d\n", r.Commands)
	fprint(w, "  effects:         %d\n", len(r.Effects))
	fprint(w, "  destructiveness: %s\n", r.Destructiveness)
	fprint(w, "  irreversibility: %s\n", r.Score.Irreversibility)
	fprint(w, "  breadth:         %s\n", r.Score.Breadth)
	fprint(w, "  influence:       %s\n", r.Score.Influence)
	fprint(w, "  grade:           %s\n", r.Score.Grade)
	fprint(w, "  confidence:      %d\n", r.Score.Confidence)
	fprint(w, "  exfil risk:      %s\n", r.Score.Exfil)
	fprint(w, "  conservative:    %t\n", r.Conservative)
	if r.Top {
		fprint(w, "  top:             true (%s)\n", sanitize(r.Reason))
	}
	if r.Resolution.Kind != "" {
		fprint(w, "  resolution:      %s %s", sanitize(string(r.Resolution.Kind)), sanitize(r.Resolution.Invoked))
		if r.Resolution.Name != "" && r.Resolution.Name != r.Resolution.Invoked {
			fprint(w, " → %s", sanitize(r.Resolution.Name))
		}
		if len(r.Resolution.AliasChain) > 0 {
			fprint(w, " [alias chain: %s]", sanitize(strings.Join(r.Resolution.AliasChain, " → ")))
		}
		fprintln(w)
	}
	for _, d := range r.Destructive {
		fprint(w, "  destructive:     %s %s (class %s): %s\n",
			sanitize(d.Command), sanitize(d.Spec), sanitize(string(d.Class)), sanitize(d.Reason))
	}
	for _, e := range r.Effects {
		fprint(w, "    - %s\n", sanitize(e.Key()))
	}
	for _, p := range r.Score.ExfilPairs {
		fprint(w, "  exfil: %s → %s\n", sanitize(p.Source.Key()), sanitize(p.Sink.Key()))
	}
	for _, n := range r.Notes {
		fprint(w, "  note: %s\n", sanitize(n))
	}
}

// writeWhy renders the why-trace: for each reported effect, the ordered chain of
// rule steps and the concrete source atoms (flags/operands/sources/sinks) that
// justify it.
func writeWhy(w io.Writer, r *api.Report) {
	if len(r.Why) == 0 {
		return
	}
	fprint(w, "why:\n")
	for _, t := range r.Why {
		fprint(w, "  %s\n", sanitize(t.Effect))
		for _, s := range t.Because {
			loc := ""
			if s.Loc != nil {
				loc = fmt.Sprintf(" @%d:%d", s.Loc.Line, s.Loc.Col)
			}
			fprint(w, "    - %s(%s)%s\n", sanitize(s.Rule), sanitize(strings.Join(s.Premises, ", ")), loc)
		}
	}
}

// oneLine collapses newlines so the summary stays one line per input, then
// strips the control characters sanitize removes.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(sanitize(s))
}

// sanitize neutralises terminal control characters in a report-derived string
// so an analysed command cannot forge report lines or drive the terminal.
// C0 controls (0x00–0x1F, including ESC and CR/LF), DEL (0x7F) and C1 controls
// (0x80–0x9F) are dropped; a tab is rendered as the two characters "\t" so
// indentation stays single-line and visible. Unicode bidi overrides
// (U+202A–U+202E, U+2066–U+2069) are dropped as well, since they reorder the
// rendered line without being control bytes.
func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			// drop C0/DEL/C1 control characters
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			// drop bidi embedding/override controls
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// optsFor builds the analysis options shared by every call site: the CLI's
// --windows override when given, otherwise the host default.
func optsFor(o options) api.Options {
	var opts api.Options
	if o.windowsSet {
		opts.Windows = api.Bool(o.windows)
	}
	return opts
}

// analyzeAuto analyses src under the sniffed dialect and, when that analysis
// is uncovered (no effects, no ⊤, not conservative), re-analyses it under the
// other dialect. The sniffer may choose the presentation, never the bound: a
// dialect whose report says "nothing happened" is not allowed to hide an input
// the other dialect reports on. When neither dialect covers the text the
// report degrades to ⊤ instead of claiming the input is effect-free.
func analyzeAuto(src string, opts api.Options) (*api.Report, error) {
	sniffed := detectLang(src)
	rep, err := api.AnalyzeWith(sniffed, src, opts)
	if err != nil {
		return nil, err
	}
	if rep.Covered() {
		return rep, nil
	}
	alt := api.LangBash
	if sniffed == api.LangBash {
		alt = api.LangPowerShell
	}
	altRep, aerr := api.AnalyzeWith(alt, src, opts)
	if aerr != nil {
		return nil, aerr
	}
	if altRep.Covered() {
		return altRep, nil
	}
	rep.Top = true
	rep.Conservative = true
	if rep.Reason == "" {
		rep.Reason = "no dialect could bound the input"
	}
	return rep, nil
}

// batchState tracks the names earlier batch lines assigned. --batch analyses
// one line per command, so a variable assigned on an earlier line is not in the
// next line's Σ. Instead of silently analysing the later line against an empty
// state (which turns "$T" into an unset empty word and can hide an exfiltration
// pair), a line that references such a name is degraded to ⊤ / conservative.
//
// The set is derived from two sources so a spelling cannot slip past it:
//
//   - the report of the line itself: every concrete target of its EnvWrite
//     effects is a name that analysis says the line assigned. This covers the
//     forms whose assignment target the effect model carries — plain
//     `T=$(…)`, `T+=…`, `T[0]=…`, `IFS= read -r T`, `printf -v T`,
//     `read -r T`, `export/declare/local/typeset`, `mapfile`/`readarray` —
//     without re-implementing the shell's grammar in a second place.
//   - a source scan for the two assignment forms the effect model reports
//     without a name (a loop variable has no EnvWrite target): `for`/`select`
//     NAME in … and `getopts SPEC NAME`.
//
// A reference is matched as a *parameter expansion* (`$T`, `${T}`, `${!T}`,
// `${#T}`, `${T[0]}`, `"$T"`), never as a substring: `$TOKEN` does not
// reference T, and a name mentioned without `$` is not a reference at all.
type batchState struct {
	assigned   map[string]bool
	positional bool
}

// assignTarget matches an assignment word's name, including the compound and
// array spellings: `T=`, `T+=`, `T[0]=`.
var assignTarget = regexp.MustCompile(`(?:^|[\s;|&(){}])([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?\+?=`)

// loopVariable matches the assignment forms the effect model does not carry as
// an EnvWrite target: `for NAME in …`, `select NAME in …` and `getopts SPEC NAME`.
var loopVariable = regexp.MustCompile(`(?:^|[\s;|&(){}])(?:for|select)\s+([A-Za-z_][A-Za-z0-9_]*)\s+in(?:\s|$)|(?:^|[\s;|&(){}])getopts\s+\S+\s+([A-Za-z_][A-Za-z0-9_]*)`)

// parameterRef matches a shell parameter reference and captures the name it
// reads: `$T`, `${T}`, `${!T}`, `${#T}`, `${T[0]}`, `${T:-x}`, `"$T"`.
var parameterRef = regexp.MustCompile(`\$(?:\{)?[!#]?([A-Za-z_][A-Za-z0-9_]*)`)

// positionalSet matches the two forms that rebind the shell's positional
// parameters: `set -- …` and `shift`. The positional channel carries a value
// exactly as a named variable does, but it has no EnvWrite target and no
// assignment word, so neither source above sees it (Finding 89).
var positionalSet = regexp.MustCompile(`(?:^|[\s;|&(){}])(?:set\s+--|shift)(?:[\s;|&(){}]|$)`)

// positionalRef matches a reference to a positional parameter or to the
// positional list: `$1`, `${1}`, `${10}`, `$@`, `$*`, `"$@"`.
var positionalRef = regexp.MustCompile(`\$(?:\{)?(?:[0-9]+|[@*])`)

// add records one assigned name.
func (s *batchState) add(name string) {
	if name == "" {
		return
	}
	if s.assigned == nil {
		s.assigned = make(map[string]bool)
	}
	s.assigned[name] = true
}

// note records the names line assigns, from its own report and from the
// assignment forms the report does not name.
func (s *batchState) note(rep *api.Report, line string) {
	if rep != nil {
		for _, e := range rep.Effects {
			if e.Kind != engine.KindEnvWrite {
				continue
			}
			for _, t := range e.Target.Targets() {
				s.add(t)
			}
		}
	}
	for _, m := range assignTarget.FindAllStringSubmatch(line, -1) {
		s.add(m[1])
	}
	for _, m := range loopVariable.FindAllStringSubmatch(line, -1) {
		if m[1] != "" {
			s.add(m[1])
		} else {
			s.add(m[2])
		}
	}
	if positionalSet.MatchString(line) {
		s.positional = true
	}
}

// check degrades rep when line references a name an earlier line assigned. The
// whole line is degraded rather than the one word: the assignment it reads may
// have carried any value, and a per-word recovery cannot know which of the
// line's effects depended on it.
func (s *batchState) check(rep *api.Report, line string) {
	if rep == nil {
		return
	}
	// The positional parameters are a cross-line channel too: `set -- $(cat
	// /etc/shadow)` on one line and `curl -d "$1" …` on the next pairs as a
	// single command and is denied, but the second line alone sees an unset
	// $1, reports no pair, and the default policy allows it (Finding 89).
	if s.positional && positionalRef.MatchString(line) {
		degrade(rep, "cross-line state: the positional parameters were rebound on an earlier batch line")
		return
	}
	if len(s.assigned) == 0 {
		return
	}
	for _, m := range parameterRef.FindAllStringSubmatch(line, -1) {
		if s.assigned[m[1]] {
			degrade(rep, "cross-line state: $"+m[1]+" was assigned on an earlier batch line")
			return
		}
	}
}

// degrade marks rep as ⊤/conservative with the given reason, unless it already
// carries a reason (the first, most specific explanation wins).
func degrade(rep *api.Report, reason string) {
	if rep == nil {
		return
	}
	rep.Top = true
	rep.Conservative = true
	if rep.Reason == "" {
		rep.Reason = reason
	}
}

// lineContinues reports whether a batch line is only the first fragment of a
// command that spans lines: it ends in an unescaped backslash, or it leaves a
// quote open. Such a line, and the fragment that follows it, are analysed as if
// they were complete commands, so both are degraded instead (Finding 69's fix
// (c): the one-command-per-line contract is enforced, not assumed).
func lineContinues(line string) bool {
	// An odd number of trailing backslashes is a line continuation.
	slashes := 0
	for i := len(line) - 1; i >= 0 && line[i] == '\\'; i-- {
		slashes++
	}
	if slashes%2 == 1 {
		return true
	}
	var inSingle, inDouble, esc bool
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case esc:
			esc = false
		case c == '\\' && !inSingle:
			esc = true
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		}
	}
	return inSingle || inDouble
}

// ---------------------------------------------------------------------------
// --lang auto: dialect sniffing
// ---------------------------------------------------------------------------

// isAutoLang reports whether a --lang value asks for dialect sniffing.
func isAutoLang(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "auto")
}

// psVerbs are the PowerShell approved verbs. A "Verb-Noun" token whose verb is
// one of these (and whose noun is capitalised) is read as a cmdlet, e.g.
// Remove-Item, Get-Content, Invoke-Expression.
var psVerbs = map[string]bool{
	"get": true, "set": true, "new": true, "remove": true, "invoke": true,
	"start": true, "stop": true, "out": true, "write": true, "read": true,
	"select": true, "where": true, "foreach": true, "clear": true, "copy": true,
	"move": true, "rename": true, "test": true, "add": true, "export": true,
	"import": true, "convertto": true, "convertfrom": true, "measure": true,
	"sort": true, "group": true, "format": true, "register": true, "unregister": true,
	"enable": true, "disable": true, "update": true, "install": true, "uninstall": true,
	"restart": true, "resume": true, "suspend": true, "wait": true, "debug": true,
	"push": true, "pop": true, "join": true, "split": true, "compare": true,
	"find": true, "resolve": true, "show": true, "hide": true, "enter": true,
	"exit": true, "mount": true, "dismount": true, "use": true, "receive": true,
	"send": true, "connect": true, "disconnect": true, "grant": true, "revoke": true,
	"optimize": true, "repair": true, "restore": true, "backup": true,
	"checkpoint": true, "lock": true, "protect": true, "unprotect": true,
	"watch": true, "switch": true, "limit": true, "block": true, "unblock": true,
}

// psParams are PowerShell named-parameter spellings (lower-cased, with the
// leading dash) that are not shell flags: -Recurse, -LiteralPath, -ErrorAction.
var psParams = map[string]bool{
	"-recurse": true, "-literalpath": true, "-erroraction": true, "-errorvariable": true,
	"-whatif": true, "-confirm": true, "-verbose": true, "-inputobject": true,
	"-computername": true, "-argumentlist": true, "-destination": true,
	"-credential": true, "-encoding": true, "-filepath": true, "-itemtype": true,
	"-stream": true, "-expandproperty": true, "-exclude": true, "-include": true,
}

// shellTokens are command names that are ordinary shell (bash/POSIX) utilities.
var shellTokens = map[string]bool{
	"rm": true, "ls": true, "cp": true, "mv": true, "cat": true, "grep": true,
	"sed": true, "awk": true, "curl": true, "wget": true, "chmod": true,
	"chown": true, "find": true, "xargs": true, "echo": true, "sh": true,
	"bash": true, "sudo": true, "dd": true, "tar": true, "ssh": true,
	"kill": true, "env": true, "export": true, "printf": true, "touch": true,
	"mkdir": true, "rmdir": true, "ln": true, "killall": true, "sleep": true,
	"head": true, "tail": true, "sort": true, "uniq": true, "tr": true,
	"wc": true, "base64": true, "python": true, "perl": true, "nc": true,
	"netcat": true, "whoami": true, "id": true, "uname": true, "cut": true,
	"nohup": true, "tee": true, "stat": true, "readlink": true, "seq": true,
}

// psSyntax are substrings that only PowerShell source uses (lower-cased, since
// detection lower-cases the input before matching).
var psSyntax = []string{
	"$env:", "${env:", "$psitem", "$psversiontable", "[cmdletbinding",
	"$profile", "$null", "hkcu:\\", "hklm:\\",
}

// shSyntax are substrings that only shell source uses.
var shSyntax = []string{"2>&1", "&>/", "#!/", "<<", ";fi", ";do", "esac", "`"}

// detectLang sniffs src and picks the dialect for --lang auto: PowerShell when
// cmdlet/parameter/syntax markers dominate, shell (bash, which also covers
// POSIX input) otherwise. It is a total heuristic over the raw text — it never
// fails, so it can never make the CLI reject otherwise-analysable input.
func detectLang(src string) api.Lang {
	ps, sh := 0, 0
	for _, tok := range sniffTokens(src) {
		lt := strings.ToLower(tok)
		if psParams[lt] {
			ps += 2
			continue
		}
		if i := strings.IndexByte(tok, '-'); i > 0 {
			if psVerbs[strings.ToLower(tok[:i])] && startsUpper(tok[i+1:]) {
				ps += 3
				continue
			}
		}
		if shellTokens[lt] {
			sh += 2
		}
	}
	lower := strings.ToLower(src)
	for _, m := range psSyntax {
		if strings.Contains(lower, m) {
			ps += 4
		}
	}
	for _, m := range shSyntax {
		if strings.Contains(src, m) {
			sh += 4
		}
	}
	if ps > sh {
		return api.LangPowerShell
	}
	return api.LangBash
}

// sniffTokens splits a command into rough tokens for the dialect sniff: it
// breaks on whitespace and the shell/PowerShell operators, so "Verb-Noun"
// cmdlets and "-Param" flags survive as single tokens.
func sniffTokens(src string) []string {
	return strings.FieldsFunc(src, func(r rune) bool {
		switch r {
		case ' ', '\t', '\r', '\n', ';', '|', '&', '(', ')', '<', '>', '\'', '"',
			'=', ',', '{', '}', '[', ']':
			return true
		}
		return false
	})
}

// startsUpper reports whether s begins with an upper-case ASCII letter, the
// shape PowerShell nouns take (Remove-Item, Get-Content).
func startsUpper(s string) bool {
	return s != "" && s[0] >= 'A' && s[0] <= 'Z'
}
