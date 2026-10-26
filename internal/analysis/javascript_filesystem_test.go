package analysis

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/v0lka/flowsh/engine"
)

func jsHasTarget(r *Report, kind engine.EffectKind, target string) bool {
	for _, effect := range r.Effects {
		if effect.Kind == kind && slices.Contains(effect.Target.Targets(), target) {
			return true
		}
	}
	return false
}

func TestJavaScriptFilesystemMatrix(t *testing.T) {
	a := mustAnalyzer(t)
	for _, family := range []struct {
		name, args string
		kind       engine.EffectKind
		target     string
	}{
		{"readFile", `'/etc/passwd', 'utf8'`, engine.KindFSRead, "/etc/passwd"},
		{"writeFile", `'/tmp/out', 'data'`, engine.KindFSWrite, "/tmp/out"},
		{"appendFile", `'/tmp/out', 'data'`, engine.KindFSWrite, "/tmp/out"},
		{"unlink", `'/tmp/out'`, engine.KindFSWrite, "/tmp/out"},
		{"rename", `'/tmp/from', '/tmp/to'`, engine.KindFSMeta, "/tmp/from"},
		{"mkdir", `'/tmp/tree', {recursive:true}`, engine.KindFSMeta, "/tmp/tree"},
		{"rmdir", `'/tmp/tree', {recursive:true}`, engine.KindFSMeta, "/tmp/tree"},
		{"rm", `'/tmp/tree', {recursive:true, force:true}`, engine.KindFSWrite, "/tmp/tree"},
		{"copyFile", `'/tmp/from', '/tmp/to'`, engine.KindFSRead, "/tmp/from"},
		{"chmod", `'/tmp/file', 0o644`, engine.KindFSMeta, "/tmp/file"},
		{"stat", `'/tmp/file'`, engine.KindFSRead, "/tmp/file"},
		{"mkdtemp", `'/tmp/prefix-'`, engine.KindFSWrite, ""},
	} {
		for _, style := range []string{"sync", "promise", "callback"} {
			t.Run(family.name+"/"+style, func(t *testing.T) {
				callee := "fs." + family.name + "Sync"
				expr := callee + "(" + family.args + ")"
				if style == "promise" {
					callee = "fs.promises." + family.name
					expr = "await " + callee + "(" + family.args + ")"
				}
				if style == "callback" {
					callee = "fs." + family.name
					expr = callee + "(" + family.args + ", (err,value)=>{})"
				}
				r := a.AnalyzeWith(LangJavaScript, "const fs=require('node:fs');\n"+expr, Options{Root: "filesystem.js"})
				if r.Top || r.Conservative != (style == "callback") || r.HasTop() != (style == "callback") {
					t.Fatalf("unexpected uncertainty: %+v", r)
				}
				if family.target != "" && !jsHasTarget(r, family.kind, family.target) {
					t.Fatalf("missing %s %s: %+v", family.kind, family.target, r.Effects)
				}
				if family.name == "mkdtemp" {
					found := false
					for _, effect := range r.Effects {
						if effect.Kind == engine.KindFSWrite && effect.Target.IsTop() {
							found = true
						}
					}
					if !found {
						t.Fatalf("invented temporary suffix: %+v", r.Effects)
					}
				}
				if family.name == "rename" || family.name == "copyFile" {
					if !jsHasTarget(r, engine.KindFSWrite, "/tmp/to") {
						t.Fatalf("missing destination write: %+v", r.Effects)
					}
				}
				if family.name == "rm" || family.name == "rmdir" {
					if r.Destructiveness != engine.DestructCritical || r.Score.Grade != engine.DestructCritical || len(r.Destructive) == 0 || r.Destructive[0].Class != "E" {
						t.Fatalf("missing recursive class: %+v", r)
					}
				}
				if len(r.CommandCalls) != 1 || r.CommandCalls[0].Invoked != callee || r.Resolution.Name == "" || r.Commands != 1 {
					t.Fatalf("missing metadata: %+v", r)
				}
				if gaps := engine.WhyGaps(r.Effects, r.Why); len(gaps) > 0 {
					t.Fatal(gaps)
				}
				located := false
				for _, why := range r.Why {
					for _, step := range why.Because {
						if step.Loc != nil && step.Loc.File == "filesystem.js" && step.Loc.Line == 2 {
							located = true
						}
					}
				}
				if !located {
					t.Fatalf("missing source evidence: %+v", r.Why)
				}
			})
		}
	}
}

func TestJavaScriptModuleIdentity(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`const fs=require('fs');fs.readFileSync('/etc/passwd','utf8')`,
		`const fs=require('node:fs');const disk=fs;const read=disk.readFileSync;read('/etc/passwd')`,
		`const load=require;const {readFileSync: read}=load('fs');read('/etc/passwd')`,
		`const {promises: disk}=require('fs');await disk.readFile('/etc/passwd')`,
		`const {readFile: read}=require('node:fs/promises');await read('/etc/passwd')`,
		`import fs from 'node:fs';fs.readFileSync('/etc/passwd')`,
		`import * as fs from 'fs';fs.readFileSync('/etc/passwd')`,
		`import {readFileSync as read} from 'fs';read('/etc/passwd')`,
		`import {promises as disk} from 'fs';await disk.readFile('/etc/passwd')`,
		`import {default as fs} from 'fs';fs.readFileSync('/etc/passwd')`,
		`import {readFile} from 'node:fs/promises';await readFile('/etc/passwd')`,
		`read('/etc/passwd');import {readFileSync as read} from 'fs';`,
		`const fs=require('fs');fs['readFileSync']('/etc/passwd')`,
	} {
		t.Run(src, func(t *testing.T) {
			r := a.Analyze(LangJavaScript, src)
			if r.Conservative || r.Top || !jsHasTarget(r, engine.KindFSRead, "/etc/passwd") {
				t.Fatalf("lost builtin identity: %+v", r)
			}
		})
	}
	for _, src := range []string{
		`const fs={readFileSync: ()=>{}};fs.readFileSync('/etc/passwd')`,
		`const require=()=>({});require('fs').readFileSync('/etc/passwd')`,
		`const fs=require('fs');{const fs={};fs.readFileSync('/etc/passwd')}`,
		`let fs=require('fs');fs={};fs.readFileSync('/etc/passwd')`,
		`const fs=require('fs');fs.readFileSync=unknown;fs.readFileSync('/etc/passwd')`,
		`const fs=require('fs');const read=fs.readFileSync;unknown();read('/etc/passwd')`,
		`const fs=require('fs');unknown();require('fs').readFileSync('/etc/passwd')`,
		`const fs=require('./fs.js');fs.readFileSync('/etc/passwd')`,
		`const fs=require('fs-extra');fs.readFileSync('/etc/passwd')`,
	} {
		t.Run(src, func(t *testing.T) {
			r := a.Analyze(LangJavaScript, src)
			if !r.Conservative || !r.HasTop() || r.Reason == "" || jsHasTarget(r, engine.KindFSRead, "/etc/passwd") {
				t.Fatalf("incorrect trusted identity: %+v", r)
			}
		})
	}
}

func TestJavaScriptModuleNamespaceIdentity(t *testing.T) {
	a := mustAnalyzer(t)
	for _, branch := range []string{
		`if(ns!==fs)fs.rmSync('/tmp/tree',{recursive:true})`,
		`switch(ns){case fs:break;default:fs.rmSync('/tmp/tree',{recursive:true})}`,
	} {
		r := a.Analyze(LangJavaScript, `import fs from 'node:fs';import * as ns from 'fs';`+branch)
		if r.Conservative || !jsHasTarget(r, engine.KindFSWrite, "/tmp/tree") || len(r.Destructive) == 0 {
			t.Fatalf("namespace equality hid deletion: %+v", r)
		}
	}
}

func TestJavaScriptBuiltinCoercionAndLoaderGuards(t *testing.T) {
	a := mustAnalyzer(t)
	t.Run("namespace conversion", func(t *testing.T) {
		r := a.Analyze(LangJavaScript, "import * as ns from 'fs';try{`${ns}`}catch(e){}")
		if !r.Conservative || !r.HasTop() {
			t.Fatalf("unsupported namespace conversion hidden: %+v", r)
		}
	})
	for _, src := range []string{
		`import fs from 'fs';if(typeof require==='undefined')fs.rmSync('/tmp/tree',{recursive:true})`,
		`import fs from 'fs';try{require}catch(e){fs.rmSync('/tmp/tree',{recursive:true})}`,
	} {
		t.Run(src, func(t *testing.T) {
			r := a.Analyze(LangJavaScript, src)
			if !jsHasTarget(r, engine.KindFSWrite, "/tmp/tree") || len(r.Destructive) == 0 {
				t.Fatalf("loader presence hid deletion: %+v", r)
			}
		})
	}
}

func TestJavaScriptImportInitializationIsHoisted(t *testing.T) {
	a := mustAnalyzer(t)
	for _, statement := range []string{
		`import './payload.js'`,
		`export * from './payload.js'`,
		`export {value} from './payload.js'`,
	} {
		t.Run(statement, func(t *testing.T) {
			r := a.Analyze(LangJavaScript, `import fs from 'node:fs';fs.readFileSync('/etc/passwd');throw 0;`+statement)
			if !r.Conservative || !r.HasTop() || !strings.Contains(r.Reason, "module initialization") {
				t.Fatalf("unreachable import hid initialization: %+v", r)
			}
		})
	}
}

func TestJavaScriptStreamAndExistenceModels(t *testing.T) {
	a := mustAnalyzer(t)
	for _, tc := range []struct {
		name string
		kind engine.EffectKind
	}{
		{"createReadStream", engine.KindFSRead},
		{"createWriteStream", engine.KindFSWrite},
		{"existsSync", engine.KindFSRead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := a.Analyze(LangJavaScript, `const fs=require('fs');fs.`+tc.name+`('/tmp/file')`)
			if r.Conservative || r.Top || len(r.Effects) != 1 || !jsHasTarget(r, tc.kind, "/tmp/file") || len(r.CommandCalls) != 1 || r.CommandCalls[0].Resolved != "fs."+tc.name {
				t.Fatalf("stream/existence model lost precision: %+v", r)
			}
		})
	}
}

func TestJavaScriptFilesystemControlFlow(t *testing.T) {
	a := mustAnalyzer(t)
	for _, expr := range []string{`fs.readFileSync('/missing')`, `await fs.promises.readFile('/missing')`} {
		r := a.Analyze(LangJavaScript, `const fs=require('fs');try{`+expr+`}catch(err){fs.rmSync('/tmp/tree',{recursive:true,force:true})}finally{fs.writeFileSync('/tmp/done','ok')}`)
		if r.Conservative || !jsHasTarget(r, engine.KindFSWrite, "/tmp/tree") || !jsHasTarget(r, engine.KindFSWrite, "/tmp/done") || len(r.Destructive) != 2 {
			t.Fatalf("failure path lost: %+v", r)
		}
	}
	r := a.Analyze(LangJavaScript, `const fs=require('fs');if(fs.existsSync('/tmp/file'))fs.writeFileSync('/tmp/yes','x');else fs.writeFileSync('/tmp/no','x')`)
	if r.Conservative || !jsHasTarget(r, engine.KindFSWrite, "/tmp/yes") || !jsHasTarget(r, engine.KindFSWrite, "/tmp/no") {
		t.Fatalf("existence guessed: %+v", r)
	}
	r = a.Analyze(LangJavaScript, `const fs=require('fs');fs.readFile('/tmp/file',()=>fs.rmSync('/tmp/tree',{recursive:true}))`)
	if !jsHasTarget(r, engine.KindFSRead, "/tmp/file") || !r.HasTop() || !strings.Contains(r.Reason, "callback") {
		t.Fatalf("callback hidden: %+v", r)
	}
	for _, src := range []string{
		`fs.rmSync('/tmp/tree',{recursive:missing,force:true})`,
		`fs.rmSync('/tmp/tree',missing)`,
		`fs.readFileSync(missing)`,
		`fs.readFileSync(3)`,
		`fs.createReadStream('/tmp/file',{fd:3})`,
		`fs.createWriteStream('/tmp/file',{fs:custom})`,
		`fs.writeFileSync('/tmp/file','x',{flag:missing})`,
		`fs.chmodSync('/tmp/file',0o4755)`,
	} {
		t.Run(src, func(t *testing.T) {
			r := a.Analyze(LangJavaScript, `const fs=require('fs');`+src)
			if !r.HasTop() || !r.Conservative || r.Reason == "" || len(r.Effects) < 2 {
				t.Fatalf("unsupported value hidden: %+v", r)
			}
			if strings.Contains(src, "rmSync") && (len(r.Destructive) == 0 || r.Destructiveness != engine.DestructCritical) {
				t.Fatalf("unknown deletion downgraded: %+v", r)
			}
		})
	}
}

func TestJavaScriptPureHelpersDoNotReachCatch(t *testing.T) {
	a := mustAnalyzer(t)
	for _, tc := range []struct{ name, expr string }{
		{"join", `path.join('a','b')`},
		{"resolve", `path.resolve('/a','b')`},
		{"dirname", `path.dirname('/a/b')`},
		{"basename", `path.basename('/a/b.js','.js')`},
		{"posix join", `path.posix.join('/a','b')`},
		{"homedir", `os.homedir()`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := `const fs=require('fs'),path=require('path'),os=require('os');try{` + tc.expr + `}catch(e){fs.rmSync('/tmp/tree',{recursive:true,force:true})}fs.readFileSync('/tmp/ok')`
			r := a.Analyze(LangJavaScript, src)
			if r.Top || r.Conservative || r.HasTop() || len(r.Destructive) != 0 || r.Commands != 2 || len(r.Effects) != 1 || !jsHasTarget(r, engine.KindFSRead, "/tmp/ok") {
				t.Fatalf("pure helper reached an impossible catch: %+v", r)
			}
		})
	}
	r := a.Analyze(LangJavaScript, `const fs=require('fs'),path=require('path');try{path.join(1)}catch(e){fs.rmSync('/tmp/tree',{recursive:true,force:true})}`)
	if !r.Conservative || !r.HasTop() || r.Commands != 2 {
		t.Fatalf("unsupported helper arguments lost the catch path: %+v", r)
	}
}

func TestJavaScriptFilesystemTransferTaint(t *testing.T) {
	a := mustAnalyzer(t)
	for _, tc := range []struct {
		name, operation, source string
		secret                  bool
	}{
		{"copy secret", "copyFile", "/etc/shadow", true},
		{"copy ordinary", "copyFile", "/tmp/input", false},
		{"rename secret", "rename", "/etc/shadow", true},
		{"rename ordinary", "rename", "/tmp/input", false},
	} {
		for _, style := range []string{"sync", "promise", "callback"} {
			t.Run(tc.name+"/"+style, func(t *testing.T) {
				args := fmt.Sprintf(`(%q,'/tmp/output')`, tc.source)
				expr := "fs." + tc.operation + "Sync" + args
				if style == "promise" {
					expr = "await fs.promises." + tc.operation + args
				}
				if style == "callback" {
					expr = fmt.Sprintf(`fs.%s(%q,'/tmp/output',()=>{})`, tc.operation, tc.source)
				}
				r := a.Analyze(LangJavaScript, `const fs=require('fs');`+expr)
				if r.Top || r.Conservative != (style == "callback") {
					t.Fatalf("unexpected transfer uncertainty: %+v", r)
				}
				found := false
				for _, effect := range r.Effects {
					if effect.Kind == engine.KindFSWrite && effect.Target.Contains("/tmp/output") {
						found = true
						if !effect.Taint.Contains(engine.TaintFileSystem) || effect.Taint.Contains(engine.TaintSecret) != tc.secret {
							t.Errorf("destination lost source provenance: %+v", effect)
						}
					}
				}
				if !found {
					t.Fatal("missing destination write")
				}
				if gaps := engine.WhyGaps(r.Effects, r.Why); len(gaps) != 0 {
					t.Fatalf("unexplained transfer effects: %v", gaps)
				}
			})
		}
	}
}

func TestJavaScriptPathHelpersAndCanonicalTargets(t *testing.T) {
	a := mustAnalyzer(t)
	for _, tc := range []struct{ expr, want string }{
		{`path.join(os.homedir(),'.ssh','id_rsa')`, "/root/.ssh/id_rsa"},
		{`path.join('/one','/two')`, "/one/two"},
		{`path.resolve('/one','/two')`, "/two"},
		{`path.resolve(missing,'/absolute')`, "/absolute"},
		{`path.join('','x','')`, "x"},
		{`path.join('','')`, "."},
		{`path.join('a','b/')`, "a/b/"},
		{`path.dirname('/a//b')`, "/a/"},
		{`path.basename('/a/b.js','.js')`, "b"},
		{`path.posix.join('/a','..','b')`, "/b"},
		{`'~/file'`, "/root/file"},
		{`'$HOME/file'`, "/root/file"},
		{`'file$literal;tail'`, "file$literal;tail"},
		{`'-filename'`, "-filename"},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			r := a.Analyze(LangJavaScript, `const fs=require('fs'),path=require('path'),os=require('os');fs.readFileSync(`+tc.expr+`)`)
			if r.Conservative || !jsHasTarget(r, engine.KindFSRead, tc.want) {
				t.Fatalf("path model: %+v", r)
			}
			found := false
			for _, effect := range r.Canonical.Effects {
				if slices.Contains(effect.Target.Targets(), tc.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("canonical target dropped: %+v", r.Canonical)
			}
		})
	}
	r := a.AnalyzeWith(LangJavaScript, `const path=require('path'),fs=require('fs');fs.readFileSync(path.resolve('x'))`, Options{JavaScript: &JavaScriptContext{Home: "/home/test", Cwd: "/workspace"}})
	if r.Conservative || !jsHasTarget(r, engine.KindFSRead, "/workspace/x") {
		t.Fatalf("explicit context: %+v", r)
	}
	r = a.Analyze(LangJavaScript, `const path=require('path'),fs=require('fs');fs.readFileSync(path.resolve('x'))`)
	if !r.HasTop() || r.Reason == "" {
		t.Fatalf("host cwd guessed: %+v", r)
	}
	for _, flag := range []string{"w", "a+", "r+"} {
		r = a.Analyze(LangJavaScript, fmt.Sprintf(`const fs=require('fs');fs.readFileSync('/tmp/file',{flag:%q})`, flag))
		if r.Conservative || !jsHasTarget(r, engine.KindFSWrite, "/tmp/file") {
			t.Fatalf("open flags dropped write: %+v", r)
		}
	}
}

func TestJavaScriptModelsRetainBoundsAndLocations(t *testing.T) {
	a := mustAnalyzer(t)
	src := `const fs=require('fs');fs.readFileSync('/etc/passwd');while(true)fs.writeFileSync('/tmp/file','x')`
	r := a.Analyze(LangJavaScript, src)
	if !r.Top || !r.Conservative || !jsHasTarget(r, engine.KindFSRead, "/etc/passwd") || len(r.CommandCalls) > maxJSMetadata {
		t.Fatalf("bound lost prior work: %+v", r)
	}
	r = a.AnalyzeWith(LangJavaScript, "const fs=require('fs');\nfs.readFileSync('/tmp/file');\nfs.readFileSync('/tmp/file');", Options{Root: "repeat.js"})
	lines := map[int]bool{}
	for _, why := range r.Why {
		for _, step := range why.Because {
			if step.Loc != nil {
				lines[step.Loc.Line] = true
			}
		}
	}
	if !lines[2] || !lines[3] {
		t.Fatalf("repeated call location lost: %+v", r.Why)
	}
	first, _ := r.Encode()
	second, _ := a.AnalyzeWith(LangJavaScript, r.Input, Options{Root: "repeat.js"}).Encode()
	if string(first) != string(second) {
		t.Fatal("nondeterministic JS report")
	}
	r = a.AnalyzeWith(LangJavaScript, `const fs=require('fs'),path=require('path');fs.readFileSync('/etc/passwd');path.resolve('x')`, Options{JavaScript: &JavaScriptContext{Cwd: "/" + strings.Repeat("a", 60000)}})
	if !r.Top || !jsHasTarget(r, engine.KindFSRead, "/etc/passwd") {
		t.Fatalf("context work escaped bounds: %+v", r)
	}
}

func TestJavaScriptFilesystemConstants(t *testing.T) {
	a := mustAnalyzer(t)
	for _, src := range []string{
		`const fs=require('fs');fs.copyFileSync('/tmp/from','/tmp/to',fs.constants.COPYFILE_EXCL)`,
		`const {constants}=require('node:fs');const fs=require('fs');fs.copyFileSync('/tmp/from','/tmp/to',constants.COPYFILE_FICLONE)`,
		`import fs from 'fs';const {constants:{COPYFILE_EXCL}}=fs;fs.copyFileSync('/tmp/from','/tmp/to',COPYFILE_EXCL)`,
		`const fs=require('fs');fs.createReadStream('/tmp/from',{flags:fs.constants.O_RDONLY})`,
		`const fs=require('fs');if(fs.constants===fs.constants&&typeof fs.constants==='object')fs.copyFileSync('/tmp/from','/tmp/to')`,
	} {
		t.Run(src, func(t *testing.T) {
			r := a.Analyze(LangJavaScript, src)
			if r.Conservative || r.Top || !jsHasTarget(r, engine.KindFSRead, "/tmp/from") {
				t.Fatalf("constants namespace lost precision: %+v", r)
			}
		})
	}
	for _, src := range []string{
		`const fs=require('fs');fs.copyFileSync('/tmp/from','/tmp/to',fs.constants.O_CREAT)`,
		`const constants=require('fs.constants');const fs=require('fs');fs.copyFileSync('/tmp/from','/tmp/to',constants.COPYFILE_EXCL)`,
		"const fs=require('fs');`${fs.constants}`",
	} {
		t.Run(src, func(t *testing.T) {
			r := a.Analyze(LangJavaScript, src)
			if !r.Conservative || !r.HasTop() || r.Reason == "" {
				t.Fatalf("unmodeled constant or namespace guessed: %+v", r)
			}
		})
	}
}
