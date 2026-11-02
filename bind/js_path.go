package bind

import (
	"path"
	"slices"
	"strings"

	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/js"
)

const jsMaxPathBytes = 65536 // bounds summed path-helper input

// jsHomePrefixes are home spellings expanded via JSContext.Home.
var jsHomePrefixes = []string{"~", "$HOME", "${HOME}"}

// jsPathScope maps a path argument to its scope; unknown,
// empty, or NUL-bearing paths and an unknown home are ⊤.
func jsPathScope(value js.Value, context JSContext) engine.Scope {
	text, known := value.String()
	if !known || text == "" || strings.ContainsRune(text, 0) {
		return engine.ScopeTop()
	}
	for _, prefix := range jsHomePrefixes {
		if text == prefix || strings.HasPrefix(text, prefix+"/") {
			if context.Home == "" {
				return engine.ScopeTop()
			}
			normalized := context.Home
			if suffix := strings.TrimPrefix(text, prefix); suffix != "" {
				normalized = strings.TrimRight(context.Home, "/") + suffix
			}
			return engine.ScopeOf(text, normalized)
		}
	}
	return engine.ScopeOf(text)
}

// jsPathValue evaluates a node:path/os helper with POSIX
// semantics; unknown inputs yield an unknown string.
func jsPathValue(operation string, args []js.Value, context JSContext) js.Value {
	taint := engine.TaintBottom()
	for _, arg := range args {
		taint = taint.Join(arg.Taint)
	}
	unknown := js.Value{Taint: taint}
	if operation == "homedir" {
		if len(args) != 0 || context.Home == "" {
			return unknown
		}
		if context.SymbolicHome {
			return js.SymbolicString(context.Home)
		}
		return js.StringValue(context.Home)
	}
	anchor := -1
	if operation == "resolve" {
		anchor = jsResolveAnchor(args)
		if anchor >= 0 {
			args = args[anchor:]
		}
	}
	parts := make([]string, len(args))
	total, symbolic := 0, false
	for i, arg := range args {
		text, known := arg.String()
		if !known {
			return unknown
		}
		symbolic = symbolic || arg.Symbolic()
		total += len(text) + 1
		if total > jsMaxPathBytes {
			return unknown
		}
		parts[i] = text
	}
	var result string
	switch operation {
	case "join":
		parts = slices.DeleteFunc(parts, func(part string) bool { return part == "" })
		joined := strings.Join(parts, "/")
		result = path.Clean(joined)
		if strings.HasSuffix(joined, "/") && result != "/" {
			result += "/"
		}
	case "resolve":
		if anchor < 0 {
			if !strings.HasPrefix(context.Cwd, "/") {
				return unknown
			}
			parts = append([]string{context.Cwd}, parts...)
		}
		result = path.Join(parts...)
	case "dirname":
		if len(parts) != 1 {
			return unknown
		}
		text := parts[0]
		end := len(strings.TrimRight(text, "/"))
		if end == 0 {
			if strings.HasPrefix(text, "/") {
				result = "/"
			} else {
				result = "."
			}
			break
		}
		index := strings.LastIndexByte(text[:end], '/')
		switch {
		case index < 0:
			result = "."
		case index == 0:
			result = "/"
		case index == 1 && strings.HasPrefix(text, "//"):
			result = "//"
		default:
			result = text[:index]
		}
	case "basename":
		if len(parts) < 1 || len(parts) > 2 {
			return unknown
		}
		text := strings.TrimRight(parts[0], "/")
		result = text[strings.LastIndexByte(text, '/')+1:]
		if len(parts) == 2 && parts[1] != "" {
			suffix := parts[1]
			switch {
			case parts[0] == suffix:
				result = ""
			case len(suffix) > len(parts[0]): // cannot match
			case len(suffix) > len(result) && strings.HasSuffix(suffix, result):
				result = parts[0][len(text)-len(result):]
			case result != suffix:
				result = strings.TrimSuffix(result, suffix)
			}
		}
	default:
		return unknown
	}
	value := js.StringValue(result) // over-long results are unknown
	if symbolic {
		value = js.SymbolicString(result)
	}
	value.Taint = taint
	return value
}

// jsResolveAnchor returns the last absolute argument's index,
// or -1 if none or a later argument is unknown.
func jsResolveAnchor(args []js.Value) int {
	for i, arg := range slices.Backward(args) {
		text, known := arg.String()
		if !known {
			return -1
		}
		if strings.HasPrefix(text, "/") {
			return i
		}
	}
	return -1
}
