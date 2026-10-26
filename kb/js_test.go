package kb

import (
	"strings"
	"testing"
)

const jsFixture = `version: effect-kb/v4
jsModules:
  - name: fs
    aliases: [node:fs]
jsCalls:
  - module: fs
    export: readFileSync
    style: sync
    operation: filesystem
    return: content
    minArgs: 1
    maxArgs: 2
    options: 1
    optionShape: encoding
    optionKeys: [encoding, flag]
    flagOption: flag
    flagDefault: r
    effects:
      - kind: FSRead
        arg: 0
        target: path
`

func TestJavaScriptKnowledgeNamespace(t *testing.T) {
	k, err := loadSrc(map[string]string{"a.yaml": jsFixture})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := k.Command("fs.readFileSync"); ok {
		t.Fatal("JS identity escaped into shell namespace")
	}
	module, ok := k.JSModule("node:fs")
	if !ok || module.Name != "fs" {
		t.Fatal("module alias lost")
	}
	call, ok := k.JSCall(module.Name, "readFileSync")
	if !ok || call.Options != 1 || call.Return != "content" {
		t.Fatalf("call shape lost: %+v", call)
	}
	for _, version := range []string{"effect-kb/v2", "effect-kb/v3"} {
		if _, err := loadSrc(map[string]string{"a.yaml": "version: " + version + "\ncommands: []\n"}); err != nil {
			t.Fatalf("legacy version rejected: %v", err)
		}
	}
}

func TestJavaScriptKnowledgeValidation(t *testing.T) {
	for _, tc := range []struct{ name, from, to string }{
		{"unknown document key", "jsCalls:", "jsCallz:"},
		{"unknown module key", "aliases: [node:fs]", "typo: x"},
		{"duplicate module alias", "aliases: [node:fs]", "aliases: [fs]"},
		{"invalid module alias", "aliases: [node:fs]", "aliases: ['invalid alias']"},
		{"duplicate alias in list", "aliases: [node:fs]", "aliases: [node:fs, node:fs]"},
		{"unknown module reference", "module: fs", "module: missing"},
		{"alias as canonical module", "module: fs", "module: node:fs"},
		{"unknown call key", "style: sync", "styel: sync"},
		{"unknown style", "style: sync", "style: arbitrary"},
		{"unknown operation", "operation: filesystem", "operation: arbitrary"},
		{"unknown return", "return: content", "return: arbitrary"},
		{"missing required field", "    return: content\n", ""},
		{"negative selector", "arg: 0", "arg: -1"},
		{"past required args", "arg: 0", "arg: 1"},
		{"past max args", "options: 1", "options: 2"},
		{"bad integer", "options: 1", "options: one"},
		{"bad shape", "optionShape: encoding", "optionShape: arbitrary"},
		{"bad options list", "optionKeys: [encoding, flag]", "optionKeys: [flag, flag]"},
		{"unknown option", "optionKeys: [encoding, flag]", "optionKeys: [encoding, flag, unknown]"},
		{"broken flag selector", "flagOption: flag", "flagOption: flags"},
		{"bad target", "target: path", "target: guessed"},
		{"bad kind", "kind: FSRead", "kind: FsCreate"},
		{"unknown effect key", "arg: 0", "argument: 0"},
		{"duplicate effect", "        target: path", "        target: path\n      - kind: FSRead\n        arg: 0\n        target: path"},
		{"pure side effects", "style: sync", "style: pure"},
		{"legacy shape", "version: effect-kb/v4", "version: effect-kb/v3"},
		{"duplicate key", "export: readFileSync", "export: readFileSync\n    export: duplicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadSrc(map[string]string{"a.yaml": strings.Replace(jsFixture, tc.from, tc.to, 1)})
			if err == nil {
				t.Fatal("invalid model accepted")
			}
		})
	}
	for _, extra := range []string{
		"jsModules:\n  - name: fs\n",
		"jsCalls:\n  - module: fs\n    export: readFileSync\n    style: sync\n    operation: filesystem\n    return: unknown\n    minArgs: 1\n    maxArgs: 1\n    effects:\n      - kind: FSRead\n        arg: 0\n        target: path\n",
	} {
		if _, err := loadSrc(map[string]string{"a.yaml": jsFixture, "b.yaml": "version: effect-kb/v4\n" + extra}); err == nil {
			t.Fatal("duplicate identity accepted")
		}
	}
	for _, properties := range []string{"      promises: missing\n", "      readFileSync: fs\n"} {
		src := strings.Replace(jsFixture, "    aliases: [node:fs]", "    properties:\n"+strings.TrimSuffix(properties, "\n"), 1)
		if _, err := loadSrc(map[string]string{"a.yaml": src}); err == nil {
			t.Fatal("broken module property accepted")
		}
	}
	for _, row := range []string{
		"      - option: recursive\n        class: E\n        reason: deletion\n",
		"      - option: flag\n        class: E\n        reason: deletion\n",
	} {
		if _, err := loadSrc(map[string]string{"a.yaml": jsFixture + "    destructive:\n" + row}); err == nil {
			t.Fatal("invalid destructive predicate accepted")
		}
	}
	destructive := strings.Replace(jsFixture, "[encoding, flag]", "[encoding, flag, recursive]", 1) +
		"    destructive:\n      - option: recursive\n        class: E\n        reason: deletion\n"
	if _, err := loadSrc(map[string]string{"a.yaml": destructive}); err != nil {
		t.Fatalf("valid destructive predicate rejected: %v", err)
	}
	if _, err := loadSrc(map[string]string{"a.yaml": strings.Replace(destructive, "class: E", "class: Z", 1)}); err == nil {
		t.Fatal("invalid destructive class accepted")
	}
}

const jsConstantsFixture = `version: effect-kb/v4
jsModules:
  - name: fs
    aliases: [node:fs]
    properties:
      constants: fs.constants
  - name: fs.constants
    internal: true
    constants:
      F_OK: 0
      COPYFILE_EXCL: 1
`

func TestJavaScriptModuleConstants(t *testing.T) {
	k, err := loadSrc(map[string]string{"a.yaml": jsConstantsFixture})
	if err != nil {
		t.Fatal(err)
	}
	module, ok := k.JSModule("fs.constants")
	if !ok || !module.Internal || len(module.Constants) != 2 || module.Constants["COPYFILE_EXCL"] != 1 {
		t.Fatalf("constants namespace lost: %+v", module)
	}
	for _, tc := range []struct{ name, from, to, want string }{
		{"non-integer constant", "F_OK: 0", "F_OK: zero", "must be an integer"},
		{"fractional constant", "F_OK: 0", "F_OK: 1.5", "must be an integer"},
		{"inexact constant", "F_OK: 0", "F_OK: 9007199254740993", "exact integer range"},
		{"overlong constant name", "F_OK: 0", strings.Repeat("A", 129) + ": 0", "invalid JS module constant"},
		{"duplicate constant", "F_OK: 0", "F_OK: 0\n      F_OK: 1", "duplicate key"},
		{"non-boolean internal", "internal: true", "internal: yes", "true or false"},
		{"internal module with alias", "internal: true", "internal: true\n    aliases: [node:fs/constants]", "cannot declare aliases"},
		{"unreferenced internal module", "    properties:\n      constants: fs.constants\n", "", "not a module property target"},
		{"constant shadowing a property", "      COPYFILE_EXCL: 1", "      COPYFILE_EXCL: 1\n    properties:\n      COPYFILE_EXCL: fs", "conflicting JS constant/property"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadSrc(map[string]string{"a.yaml": strings.Replace(jsConstantsFixture, tc.from, tc.to, 1)})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("invalid constants model accepted or misreported: %v", err)
			}
		})
	}
	conflict := jsConstantsFixture + "jsCalls:\n  - module: fs.constants\n    export: F_OK\n    style: pure\n    operation: join\n    return: unknown\n    minArgs: 0\n    maxArgs: 1\n"
	if _, err := loadSrc(map[string]string{"a.yaml": conflict}); err == nil || !strings.Contains(err.Error(), "conflicting JS constant/export") {
		t.Fatalf("constant/export conflict accepted or misreported: %v", err)
	}
}
