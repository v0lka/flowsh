// Package api is the embedding surface of flowsh: a thin, type-alias wrapper
// over the internal analysis facade (internal/analysis) that lets an external
// Go module embed the analyser without importing anything under internal/.
//
// Every exported type is an alias, every exported constant is a copy of the
// facade's, and every exported function forwards to it — this package adds no
// behaviour of its own, so an embedding caller sees exactly the same report
// contract the flowsh CLI emits.
//
// # Stability
//
// The report contract is versioned by two constants, both re-exported here:
//
//   - SchemaVersion (SchemaVersion, "effect-ir/v1") tags the effect IR and the
//     report's effect schema; it is bumped only when the shape of an effect
//     changes.
//   - ToolVersion (ToolVersion, "flowsh/v1") tags the report contract as a
//     whole; it is bumped when the emitted document gains, loses or changes a
//     field.
//
// A consumer can therefore pin to a contract revision by checking
// Report.ToolVersion and Report.SchemaVersion rather than by module version.
//
// The regression corpus harness (corpus.go in the facade) is deliberately NOT
// re-exported: it is an internal testing aid, not part of the embedding
// surface.
package api

import "github.com/v0lka/flowsh/internal/analysis"

// Lang names the command-line dialect a source is written in. It is an alias of
// analysis.Lang, so the values are interchangeable across the boundary.
type Lang = analysis.Lang

// Report is the flowsh JSON contract: the frozen effect IR plus the composition
// score and the conservative/⊤ flags. It is an alias of analysis.Report.
type Report = analysis.Report

// DestructiveFinding is one matched entry of the knowledge base's
// destructive-flags table, surfaced in the report. It is an alias of
// analysis.DestructiveFinding.
type DestructiveFinding = analysis.DestructiveFinding

// Analyzer holds reusable analysis state (the loaded command knowledge base) so
// that analysing many commands does not pay the KB load on every call. It is
// safe for concurrent use. It is an alias of analysis.Analyzer.
type Analyzer = analysis.Analyzer

// Options tunes the composition analysis. The zero value reproduces the
// historical host-default behaviour. It is an alias of analysis.Options.
type Options = analysis.Options

const (
	// ToolName is the tool identifier stamped into every report ("flowsh").
	ToolName = analysis.ToolName
	// SchemaVersion tags the report's effect schema ("effect-ir/v1").
	SchemaVersion = analysis.SchemaVersion
	// ToolVersion is the semantic version of the report contract ("flowsh/v1").
	ToolVersion = analysis.ToolVersion

	// RootArgument and RootStdin are the source-name markers stamped into
	// Report.Root when the analysed command did not come from a file.
	RootArgument = analysis.RootArgument
	RootStdin    = analysis.RootStdin
)

const (
	// LangBash is GNU bash argv with -flags and --options: the default dialect.
	LangBash = analysis.LangBash
	// LangPOSIX is the POSIX shell (a.k.a. sh).
	LangPOSIX = analysis.LangPOSIX
	// LangPowerShell is PowerShell cmdlet syntax (canonical name "posh").
	LangPowerShell = analysis.LangPowerShell
)

// Langs is every supported dialect, in canonical order.
var Langs = analysis.Langs

// ParseLang maps a user-supplied language name onto a Lang, accepting the
// canonical spellings ("bash", "posix", "posh") plus their common aliases.
func ParseLang(s string) (Lang, error) { return analysis.ParseLang(s) }

// Analyze runs the full pipeline for lang over src using the process-wide
// analyser and the host-default provider configuration.
func Analyze(lang Lang, src string) (*Report, error) { return analysis.Analyze(lang, src) }

// AnalyzeWith is Analyze with explicit options, letting a caller enable a
// frontend provider (today, the PowerShell Registry) on a host where it would
// otherwise be inactive. The zero Options is identical to Analyze.
func AnalyzeWith(lang Lang, src string, opts Options) (*Report, error) {
	return analysis.AnalyzeWith(lang, src, opts)
}

// NewAnalyzer returns an analyser over the embedded knowledge base. Reuse it
// across many Analyse/AnalyzeWith calls to amortise the KB load.
func NewAnalyzer() (*Analyzer, error) { return analysis.NewAnalyzer() }

// Bool returns a pointer to v. It is a convenience for setting the tri-state
// Options.Windows field: Options{Windows: Bool(true)} forces registry semantics
// on any host.
func Bool(v bool) *bool { return analysis.Bool(v) }
