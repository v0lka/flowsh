package ps

import (
	"strings"

	"github.com/v0lka/flowsh/engine"
)

// ===========================================================================
// The abstract variable state Σ
// ===========================================================================
//
// The lowerer keeps an abstract environment of PowerShell variables so a word
// that references a statically-known variable can lower to the concrete value
// instead of degrading to ⊤. The model mirrors the bash frontend's Σ
// (front/bash/expand.go): each variable carries an optional concrete value, a
// set/known pair and a taint label, and two states reached by different branches
// are combined with a least-upper-bound join that keeps a value only when every
// path agrees.
//
// PowerShell variable names are case-insensitive, so the state keys variables
// by their lower-cased spelling; $Dir and $dir are one variable. Scope
// qualifiers ($global:x, $script:x, …) are stored under the bare name: the
// analysis models one flattened session scope, which is a sound
// over-approximation for a single script file.
//
// The state never reads the host environment or the filesystem (SECURITY.md,
// Data Protection): a variable whose value is not determined by the script text
// alone is set-but-unknown, and every word that references it degrades to ⊤.

// KV is one key→value pair of a known hashtable literal.
type KV struct {
	Key   string
	Value string
	Known bool
	Taint engine.Taint
}

// Var is the abstract value of one PowerShell variable.
type Var struct {
	// Value is the concrete value; meaningful only when Known is true.
	Value string
	// Set reports whether the variable is surely assigned on every path.
	Set bool
	// Known reports whether the value is statically determined.
	Known bool
	// Taint is the provenance carried by the value.
	Taint engine.Taint
	// Hash holds the entries of a known hashtable literal ($p = @{Path='x'}),
	// so splatting the variable can expand into parameter bindings. Value
	// keeps the raw text; Hash is nil for non-hashtable values.
	Hash []KV
}

// SetHash records an assignment of a known hashtable literal.
func (s *State) SetHash(name string, hash []KV, taint engine.Taint) {
	if s == nil || name == "" {
		return
	}
	s.Vars[strings.ToLower(name)] = &Var{Set: true, Known: true, Taint: taint, Hash: hash}
}

// hashEqual reports whether two hashtable entry lists carry the same keys,
// values and knownness.
func hashEqual(a, b []KV) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Key != b[i].Key || a[i].Value != b[i].Value || a[i].Known != b[i].Known {
			return false
		}
	}
	return true
}

// State is the abstract variable environment Σ.
type State struct {
	Vars map[string]*Var
	// Drives maps a mounted drive letter ("x") onto the root it was created
	// with, so a later `X:\…` path can be resolved to the location it really
	// names. It is the state `New-PSDrive` establishes: without it a path under
	// a drive mapped to a UNC share looks like a local path, and a credential
	// copied to it is never reported as network egress (Finding 98).
	Drives map[string]string
	// DriveUnknown records a drive whose root the script did not determine
	// statically (a variable, a computed expression). A later path under it is
	// widened to ⊤ rather than assumed local.
	DriveUnknown map[string]bool
	// AllDrivesUnknown records a `New-PSDrive` whose *name* was not determined:
	// any drive letter may then be mapped to a remote root.
	AllDrivesUnknown bool
}

// automaticVars are the automatic variables the analysis seeds as
// set-but-unknown: a script may read them without assigning them, and their
// values are never statically determined by the script text. They are stored
// lower-cased (the state's key form).
var automaticVars = []string{
	"args",    // function/script arguments
	"input",   // pipeline input enumerator
	"_",       // current pipeline item
	"psitem",  // alias of $_
	"matches", // -match results (populated dynamically)
	"error",   // session error stream
	"pid",     // host process id (a number, unknowable here)
}

// NewState returns a fresh state seeded with the automatic variables.
func NewState() *State {
	s := &State{
		Vars:         make(map[string]*Var, len(automaticVars)+8),
		Drives:       make(map[string]string),
		DriveUnknown: make(map[string]bool),
	}
	for _, n := range automaticVars {
		s.Vars[n] = &Var{Set: true, Known: false}
	}
	return s
}

// Clone returns a deep copy: the interpreter forks Σ for every branch, loop
// arm and pipeline stage, and a clone must never share variables with its
// origin.
func (s *State) Clone() *State {
	if s == nil {
		return nil
	}
	out := &State{
		Vars:             make(map[string]*Var, len(s.Vars)),
		Drives:           make(map[string]string, len(s.Drives)),
		DriveUnknown:     make(map[string]bool, len(s.DriveUnknown)),
		AllDrivesUnknown: s.AllDrivesUnknown,
	}
	for k, v := range s.Vars {
		copied := *v
		out.Vars[k] = &copied
	}
	for k, v := range s.Drives {
		out.Drives[k] = v
	}
	for k := range s.DriveUnknown {
		out.DriveUnknown[k] = true
	}
	return out
}

// driveLetter returns the lower-cased drive letter a path is rooted on when it
// is written as `X:\…`, `X:/…` or `X:`; it reports false for a relative path, a
// provider-qualified path (`Env:`, `HKLM:`) and a plain name.
func driveLetter(p string) (string, bool) {
	if len(p) < 2 || p[1] != ':' {
		return "", false
	}
	c := p[0]
	if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
		return "", false
	}
	if len(p) > 2 && p[2] != '\\' && p[2] != '/' {
		return "", false
	}
	return strings.ToLower(string(c)), true
}

// SetDrive records that drive letter names the given root.
func (s *State) SetDrive(letter, root string) {
	if s == nil {
		return
	}
	if s.Drives == nil {
		s.Drives = make(map[string]string)
	}
	delete(s.DriveUnknown, letter)
	s.Drives[letter] = root
}

// SetDriveUnknown records that drive letter is mounted on a root the analysis
// could not determine.
func (s *State) SetDriveUnknown(letter string) {
	if s == nil {
		return
	}
	if s.DriveUnknown == nil {
		s.DriveUnknown = make(map[string]bool)
	}
	delete(s.Drives, letter)
	s.DriveUnknown[letter] = true
}

// UnsetDrive forgets a drive (Remove-PSDrive).
func (s *State) UnsetDrive(letter string) {
	if s == nil {
		return
	}
	delete(s.Drives, letter)
	delete(s.DriveUnknown, letter)
}

// RewriteDrive resolves a path rooted on a mapped drive onto the root the drive
// names. present reports that the drive is known to the state at all (a mapped
// root or an unresolved one); known distinguishes the two, so the caller can
// widen an unresolved drive to ⊤ instead of treating the path as local.
func (s *State) RewriteDrive(p string) (out string, present, known bool) {
	letter, ok := driveLetter(p)
	if !ok || s == nil {
		return p, false, false
	}
	if root, ok := s.Drives[letter]; ok {
		rest := strings.TrimLeft(p[2:], `\/`)
		if rest == "" {
			return root, true, true
		}
		return strings.TrimRight(root, `\/`) + `\` + rest, true, true
	}
	if s.AllDrivesUnknown || s.DriveUnknown[letter] {
		return p, true, false
	}
	return p, false, false
}

// Get returns the variable named name (case-insensitively), or nil when it is
// not present in the state.
func (s *State) Get(name string) *Var {
	if s == nil || name == "" {
		return nil
	}
	return s.Vars[strings.ToLower(name)]
}

// Set records a statically-known assignment: the variable holds value from
// this point on, carrying taint.
func (s *State) Set(name, value string, taint engine.Taint) {
	if s == nil || name == "" {
		return
	}
	s.Vars[strings.ToLower(name)] = &Var{Value: value, Set: true, Known: true, Taint: taint}
}

// SetUnknown records an assignment whose value is not statically determined
// (an expression, a cmdlet's output, an unknown right-hand side): the variable
// becomes set-but-unknown. A prior known value is replaced, as in PowerShell.
func (s *State) SetUnknown(name string, taint engine.Taint) {
	if s == nil || name == "" {
		return
	}
	s.Vars[strings.ToLower(name)] = &Var{Set: true, Known: false, Taint: taint}
}

// Unset removes the variable (Clear-Variable, Remove-Item Variable:, an
// unknown-side assignment in one branch of a conditional). A variable missing
// from the state is not surely set, so reads of it degrade to ⊤.
func (s *State) Unset(name string) {
	if s == nil || name == "" {
		return
	}
	delete(s.Vars, strings.ToLower(name))
}

// JoinStates returns the least upper bound of two states reached by different
// branches of a control-flow split: a variable keeps its value only when both
// branches agree, becomes set-but-unknown when both set it differently, and is
// dropped when only one branch defines it (it is then not surely set).
func JoinStates(a, b *State) *State {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	out := a.Clone()
	names := make(map[string]bool, len(a.Vars)+len(b.Vars))
	for n := range a.Vars {
		names[n] = true
	}
	for n := range b.Vars {
		names[n] = true
	}
	for n := range names {
		av, bv := a.Vars[n], b.Vars[n]
		switch {
		case av == nil || bv == nil:
			delete(out.Vars, n) // defined on only one path → not surely set
		case !av.Set || !bv.Set:
			out.Vars[n] = &Var{Taint: av.Taint.Join(bv.Taint)}
		case !av.Known || !bv.Known || av.Value != bv.Value:
			out.Vars[n] = &Var{Set: true, Known: false, Taint: av.Taint.Join(bv.Taint)}
		default:
			keep := av.Hash
			if !hashEqual(av.Hash, bv.Hash) {
				keep = nil // raw values agree but the entries do not
			}
			out.Vars[n] = &Var{Set: true, Known: true, Value: av.Value, Hash: keep,
				Taint: av.Taint.Join(bv.Taint)}
		}
	}
	// A drive mapping survives a branch join only when every finger agrees on
	// it: a drive mounted on one path only, or mounted on two different roots,
	// is not statically known afterwards — widening to ⊤ keeps the join sound.
	out.Drives = make(map[string]string, len(a.Drives))
	out.DriveUnknown = make(map[string]bool, len(a.DriveUnknown)+len(b.DriveUnknown))
	out.AllDrivesUnknown = a.AllDrivesUnknown || b.AllDrivesUnknown
	for k, av := range a.Drives {
		if bv, ok := b.Drives[k]; ok && bv == av {
			out.Drives[k] = av
		} else {
			out.DriveUnknown[k] = true
		}
	}
	for k, bv := range b.Drives {
		if av, ok := a.Drives[k]; ok && av == bv {
			out.Drives[k] = bv
		} else {
			out.DriveUnknown[k] = true
		}
	}
	for k := range a.DriveUnknown {
		out.DriveUnknown[k] = true
		delete(out.Drives, k)
	}
	for k := range b.DriveUnknown {
		out.DriveUnknown[k] = true
		delete(out.Drives, k)
	}
	return out
}
