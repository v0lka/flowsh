package bind

import (
	"slices"
	"testing"

	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/js"
)

func TestJavaScriptPOSIXPaths(t *testing.T) {
	for _, tc := range []struct {
		operation string
		args      []string
		want      string
	}{
		{"join", []string{}, "."},
		{"join", []string{"", ""}, "."},
		{"join", []string{"a", "/b", ""}, "a/b"},
		{"join", []string{"a", "../"}, "./"},
		{"resolve", []string{"/a", "/b", "../c"}, "/c"},
		{"resolve", []string{"relative", "/absolute"}, "/absolute"},
		{"dirname", []string{"//file"}, "//"},
		{"dirname", []string{"/a//b///"}, "/a/"},
		{"dirname", []string{"file/"}, "."},
		{"basename", []string{"/"}, ""},
		{"basename", []string{"/a/b.js", ".js"}, "b"},
		{"basename", []string{"/a/b", "b"}, "b"},
		{"basename", []string{"a/b", "a/b"}, ""},
		{"basename", []string{"b/", "b"}, "b"},
		{"basename", []string{"/b/", "ab"}, "b/"},
	} {
		t.Run(tc.operation+"/"+tc.want, func(t *testing.T) {
			args := make([]js.Value, len(tc.args))
			for i, arg := range tc.args {
				args[i] = js.StringValue(arg)
				args[i].Taint = engine.TaintOf(engine.TaintFileSystem)
			}
			value := jsPathValue(tc.operation, args, JSContext{})
			text, known := value.String()
			if !known || text != tc.want {
				t.Fatalf("%s(%q) = %q/%v, want %q", tc.operation, tc.args, text, known, tc.want)
			}
			if len(args) > 0 && !slices.Contains(value.Taint.Labels(), engine.TaintFileSystem) {
				t.Fatal("path taint lost")
			}
		})
	}
	value := jsPathValue("join", []js.Value{js.StringValue("/a"), {}}, JSContext{})
	if _, known := value.String(); known {
		t.Fatal("unknown segment guessed")
	}
	value = jsPathValue("resolve", []js.Value{{}, js.StringValue("/absolute")}, JSContext{})
	if text, known := value.String(); !known || text != "/absolute" {
		t.Fatalf("irrelevant segment changed resolve: %+v", value)
	}
	if got := jsPathScope(js.StringValue("~"), JSContext{Home: "/"}).Targets(); !slices.Contains(got, "/") {
		t.Fatalf("root home lost: %v", got)
	}
}

func TestJavaScriptFilesystemWriteDataTaint(t *testing.T) {
	b, err := NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, export string
		secret       bool
	}{
		{"write data", "writeFileSync", true},
		{"append data", "appendFileSync", true},
		{"stream encoding option", "createWriteStream", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := js.StringValue("utf8")
			value.Taint = engine.TaintOf(engine.TaintSecret)
			result := b.BindJS(js.Call{Module: "fs", Export: tc.export, Args: []js.Value{js.StringValue("/tmp/output"), value}}, JSContext{})
			if !result.Resolution.Handled || result.Resolution.Reason != "" || len(result.Binding.Effects) == 0 {
				t.Fatalf("unexpected binding: %+v", result)
			}
			for _, effect := range result.Binding.Effects {
				if effect.Kind != engine.KindFSWrite || effect.Taint.Contains(engine.TaintSecret) != tc.secret {
					t.Errorf("write payload taint came from the wrong argument: %+v", effect)
				}
			}
		})
	}
}

func TestJavaScriptModuleConstants(t *testing.T) {
	b, err := NewDefault()
	if err != nil {
		t.Fatal(err)
	}
	if result := b.BindJS(js.Call{Kind: "module", Module: "fs.constants"}, JSContext{}); result.Resolution.Handled {
		t.Fatal("property-only namespace resolved as an importable module")
	}
	namespace := b.BindJS(js.Call{Kind: "property", Module: "fs", Export: "constants"}, JSContext{})
	if !namespace.Resolution.Handled || namespace.Resolution.Value.Kind() != "module" {
		t.Fatalf("fs.constants namespace lost: %+v", namespace.Resolution)
	}
	constant := b.BindJS(js.Call{Kind: "property", Module: "fs.constants", Export: "COPYFILE_EXCL"}, JSContext{})
	number, known := constant.Resolution.Value.Number()
	if !constant.Resolution.Handled || !known || number != 1 {
		t.Fatalf("COPYFILE_EXCL lost: %+v", constant.Resolution)
	}
	if result := b.BindJS(js.Call{Kind: "property", Module: "fs.constants", Export: "O_CREAT"}, JSContext{}); result.Resolution.Handled {
		t.Fatal("platform-specific constant guessed")
	}
}
