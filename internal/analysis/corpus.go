package analysis

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Group names the role a corpus case plays. The GuardFall groups are the
// adversarial, guard-evading inputs; destructive and ps are the canonical
// recall cases; benign is the precision control.
const (
	// GroupGuardFall holds the guarded-evasion classes A–E.
	GroupGuardFall = "guardfall"
	// GroupDestructive holds the canonical destructive commands.
	GroupDestructive = "destructive"
	// GroupBenign holds ordinary, non-adversarial commands (precision control).
	GroupBenign = "benign"
	// GroupPS holds PowerShell-specific adversarial/recall cases.
	GroupPS = "ps"
	// GroupResolution holds recall cases for the A2 name-resolution chain: every
	// case's report must expose which command the invocation actually named
	// (builtin / function / alias / external command / unknown), so that
	// resolution is regression-covered and not merely computed and dropped.
	GroupResolution = "resolution"
)

// GuardFallClasses are the guarded-evasion categories A–E, in order. They name
// how an attacker hides intent from a surface-level scanner:
//
//	A — quoting/escaping fragments (r''m, "r"m, \rm)
//	B — separator injection ($IFS, ${IFS}, printf-built words)
//	C — indirection: command substitution and dynamically-named programs
//	D — encoded payloads fed to an interpreter (base64|sh, eval, sh -c)
//	E — unbounded/opaque work that must degrade to ⊤ (budget exhaustion, unknown)
var GuardFallClasses = []string{"A", "B", "C", "D", "E"}

// Case is one corpus entry: a command to analyse together with the metadata the
// conformance harness needs to classify it.
type Case struct {
	// ID is the stable, unique identifier (used in failure messages and sorted
	// iteration, so runs are deterministic).
	ID string `json:"id"`
	// Group is one of the Group* constants.
	Group string `json:"group"`
	// Category is the GuardFall class ("A".."E") for GroupGuardFall cases, and
	// empty otherwise.
	Category string `json:"category,omitempty"`
	// Lang is the dialect the input is written in ("bash" or "posh").
	Lang string `json:"lang"`
	// Input is the command source text.
	Input string `json:"input"`
	// Note is free-form documentation of the case's intent.
	Note string `json:"note,omitempty"`
}

// Dialect resolves the case's declared language.
func (c Case) Dialect() (Lang, error) { return ParseLang(c.Lang) }

// RequiresCoverage reports whether the case must be classified as "effect
// present or ⊤". Benign cases are excluded: an ordinary, side-effect-free
// command may legitimately yield nothing, and the GuardFall invariant is about
// not silently missing adversarial input.
func (c Case) RequiresCoverage() bool { return c.Group != GroupBenign }

// corpusFile is the on-disk shape of a corpus document. Each file is a named
// bundle of cases; the name and description document the bundle's purpose.
type corpusFile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Cases       []Case `json:"cases"`
}

// LoadCorpus reads every *.json document in dir, validates each case, and
// returns the union sorted by ID. Duplicate IDs are rejected so that the
// harness reports a stable, unambiguous set.
func LoadCorpus(dir string) ([]Case, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("flowsh: read corpus dir: %w", err)
	}

	var all []Case
	seen := make(map[string]bool)
	files := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		files++
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("flowsh: read %s: %w", e.Name(), err)
		}
		var cf corpusFile
		if err := json.Unmarshal(data, &cf); err != nil {
			return nil, fmt.Errorf("flowsh: parse %s: %w", e.Name(), err)
		}
		if cf.Name == "" {
			return nil, fmt.Errorf("flowsh: %s: missing name", e.Name())
		}
		if len(cf.Cases) == 0 {
			return nil, fmt.Errorf("flowsh: %s: no cases", e.Name())
		}
		for i, c := range cf.Cases {
			if err := c.validate(); err != nil {
				return nil, fmt.Errorf("flowsh: %s: cases[%d]: %w", e.Name(), i, err)
			}
			if seen[c.ID] {
				return nil, fmt.Errorf("flowsh: %s: duplicate case id %q", e.Name(), c.ID)
			}
			seen[c.ID] = true
			all = append(all, c)
		}
	}
	if files == 0 {
		return nil, fmt.Errorf("flowsh: no corpus documents in %s", dir)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all, nil
}

func (c Case) validate() error {
	if c.ID == "" {
		return fmt.Errorf("empty id")
	}
	if c.Input == "" {
		return fmt.Errorf("empty input")
	}
	switch c.Group {
	case GroupGuardFall, GroupDestructive, GroupBenign, GroupPS, GroupResolution:
	default:
		return fmt.Errorf("unknown group %q", c.Group)
	}
	if c.Group == GroupGuardFall {
		if !isGuardFallClass(c.Category) {
			return fmt.Errorf("guardfall case %q has invalid category %q", c.ID, c.Category)
		}
	} else if c.Category != "" {
		return fmt.Errorf("non-guardfall case %q carries a category", c.ID)
	}
	if _, err := ParseLang(c.Lang); err != nil {
		return err
	}
	return nil
}

func isGuardFallClass(s string) bool {
	for _, c := range GuardFallClasses {
		if c == s {
			return true
		}
	}
	return false
}

// Filter returns the cases of the given group, preserving the sorted order.
func Filter(cases []Case, group string) []Case {
	var out []Case
	for _, c := range cases {
		if c.Group == group {
			out = append(out, c)
		}
	}
	return out
}

// CorpusDir locates the repository's corpus directory by walking up from the
// current working directory until a go.mod is found. It lets both the CLI tests
// and the benchmark harness find the same corpus without hard-coded relative
// paths.
func CorpusDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata", "corpus"), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("flowsh: go.mod not found above %s", dir)
		}
		dir = parent
	}
}

// CorpusDirFrom locates the corpus directory relative to an explicit starting
// directory. It is the testable core of CorpusDir.
func CorpusDirFrom(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata", "corpus"), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("flowsh: go.mod not found above %s", start)
		}
		dir = parent
	}
}
