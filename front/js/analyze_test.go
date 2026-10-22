package js

import (
	"encoding/json"
	"math"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/v0lka/flowsh/engine"
)

func evaluate(t *testing.T, src string) (*Result, *state) {
	t.Helper()
	r, s := analyze("test.js", src, nil)
	if r.Top || r.Conservative || s == nil {
		t.Fatalf("unexpected degradation: %+v", r)
	}
	return r, s
}

func expectValue(t *testing.T, s *state, name string, want Value) {
	t.Helper()
	got, i := s.lookup(name)
	if i < 0 || !got.initialized || !sameValue(got.value, want) {
		t.Fatalf("%s = %+v, want %+v", name, got, want)
	}
}

func TestValuesAndStatements(t *testing.T) {
	cases := []struct {
		name, src, variable string
		want                Value
	}{
		{"string escape", `const x = 'a\x62\u0063';`, "x", stringValue("abc")},
		{"unicode escape", `const x = '\u{1f600}';`, "x", stringValue("😀")},
		{"line separator continuation", "const x='\\ ';", "x", stringValue("")},
		{"paragraph separator continuation", "const x='\\ ';", "x", stringValue("")},
		{"number", `const x = 0o10 + 0x10 + 0b10 + 1_000;`, "x", numberValue(1026)},
		{"bitwise", `const x=(5&3)|(2^1);`, "x", numberValue(3)},
		{"exponent infinity", `const x = 1 ** (1 / 0);`, "x", numberValue(math.NaN())},
		{"exponent NaN", `const x = 1 ** (0 / 0);`, "x", numberValue(math.NaN())},
		{"template", "const a = 3; const x = `item-${a}`;", "x", stringValue("item-3")},
		{"null", `let x = null;`, "x", Value{kind: "null"}},
		{"undefined", `let x;`, "x", undefined()},
		{"hoisted var", `let x = a; var a = 2;`, "x", undefined()},
		{"var scope", `{ var x = 'outer'; }`, "x", stringValue("outer")},
		{"var redeclaration", `var x=1;var x;`, "x", numberValue(1)},
		{"block scope", `let x = 1; {let x = 2;}`, "x", numberValue(1)},
		{"array destructuring", `const [x,,...tail] = [1,2,3];`, "x", numberValue(1)},
		{"object destructuring", `const {a:x} = {a:'path'};`, "x", stringValue("path")},
		{"destructuring default", `const {a:x=2} = {a:undefined};`, "x", numberValue(2)},
		{"array default", `const [x=7] = [undefined];`, "x", numberValue(7)},
		{"object rest", `const {a,...rest}={a:1,b:2}; const x=rest.b;`, "x", numberValue(2)},
		{"array rest", `const [a,...rest]=[1,2,3]; const x=rest[1];`, "x", numberValue(3)},
		{"member literal", `const a={x:3}; const x=a['x'];`, "x", numberValue(3)},
		{"array holes", `const a=[,,];const x=a.length;`, "x", numberValue(2)},
		{"for", `let x=0; for(let i=0;i<4;i++){x+=i;}`, "x", numberValue(6)},
		{"for expression initializer", `let x=0; let i; for(i=0;i<3;i++) x++;`, "x", numberValue(3)},
		{"for literal initializer", `let x=1;for(true;false;)x=2;`, "x", numberValue(1)},
		{"for empty initializer", `let x=0;for(;x<3;)x++;`, "x", numberValue(3)},
		{"for without condition", `let x=0;for(;;){if(x>2)break;x++;}`, "x", numberValue(3)},
		{"for of", `let x=0; for(const n of [1,2,3]) x+=n;`, "x", numberValue(6)},
		{"for in", `let x='';for(const k in {b:1,a:2}) x+=k;`, "x", stringValue("ba")},
		{"while", `let x=0;while(x<3)x++;`, "x", numberValue(3)},
		{"do while", `let x=0;do{x++}while(x<3);`, "x", numberValue(3)},
		{"break continue", `let x=0;for(let i=0;i<5;i++){if(i===1)continue;if(i===3)break;x+=i;}`, "x", numberValue(2)},
		{"known branch", `let x=0;if('0'){x=1}else{x=2}`, "x", numberValue(1)},
		{"known false", `let x=0;if(0)x=1;else x=2;`, "x", numberValue(2)},
		{"joined agree", `let x=0;if(missing)x=2;else x=2;`, "x", numberValue(2)},
		{"joined disagree", `let x=0;if(missing)x=1;else x=2;`, "x", Value{}},
		{"unknown with no else", `let x=0;if(missing)x=1;`, "x", Value{}},
		{"ternary", `const x=missing?'a':'b';`, "x", Value{}},
		{"logical short circuit", `let x=0;false && (x=1);true || (x=2);`, "x", numberValue(0)},
		{"logical unknown joins", `let x=0;missing && (x=1);`, "x", Value{}},
		{"nullish", `const x=null??3;`, "x", numberValue(3)},
		{"switch fallthrough", `let x=0;switch(1){case 1:x++;case 2:x++;break;default:x=7;}`, "x", numberValue(2)},
		{"switch default", `let x=0;switch(9){case 1:x=1;break;default:x=7;}`, "x", numberValue(7)},
		{"switch unknown", `let x=0;switch(missing){case 1:x=1;break;default:x=7;}`, "x", Value{}},
		{"switch scope", `let x=1;switch(0){case 0:let x=2;break;}`, "x", numberValue(1)},
		{"switch break stays in loop", `let x=0;for(let i=0;i<3;i++){switch(1){case 1:break}x++}`, "x", numberValue(3)},
		{"throw catch finally", `let x=0;try{throw 2;x=9}catch(e){x=e}finally{x+=1}`, "x", numberValue(3)},
		{"no spurious catch", `let x=0;try{x=1}catch(e){x=9}`, "x", numberValue(1)},
		{"typeof undefined does not throw", `let x=1;try{typeof undefined}catch(e){x=2}`, "x", numberValue(1)},
		{"typeof unresolved", `const x=typeof missing;`, "x", Value{}},
		{"finally overrides break", `let x=0;while(true){try{break}finally{x=2}}`, "x", numberValue(2)},
		{"export declaration", `export const x=3;`, "x", numberValue(3)},
		{"comments", `/*a*/const x=1;//b`, "x", numberValue(1)},
		{"trivial label", `empty: ; const x=1;`, "x", numberValue(1)},
		{"await primitive", `const x=await 3;`, "x", numberValue(3)},
		{"uninvoked arrow", `const x=(p)=>{return p+1;};`, "x", Value{kind: "function"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, s := evaluate(t, tc.src)
			if tc.want.kind == "function" {
				got, _ := s.lookup(tc.variable)
				if got.value.kind != "function" || got.value.body == nil {
					t.Fatal("function body lost")
				}
				return
			}
			expectValue(t, s, tc.variable, tc.want)
		})
	}
}

func TestDegradeRules(t *testing.T) {
	cases := []struct{ name, src string }{
		{"parse", `let = (`},
		{"class", `class X { method(){return 1} }`},
		{"generator", `function* f(){yield 1}; f();`},
		{"getter", `const o={get x(){return 1}};o.x;`},
		{"setter", `const o={set x(v){}};o.x=1;`},
		{"proxy", `const p=new Proxy({},{});`},
		{"with", `with (o) { x=1 }`},
		{"label", `label: while(true){break label}`},
		{"computed access", `const a={x:1};const k='x';a[k];`},
		{"computed object", `const a={['x']:1};`},
		{"unknown property key", `const o={'\uD800':1,'\uD801':2};if(o['\uD800']===1)dangerous();`},
		{"unknown call", `mystery();`},
		{"node API", `require('node:fs').rmSync('/tmp/example');`},
		{"local call", `function f(p){return p};f(1);`},
		{"import", `import {x} from './local.js';`},
		{"reexport", `export * from './local.js';`},
		{"TDZ", `const x=y;let y=1;`},
		{"constant write", `const x=1;x=2;`},
		{"unknown iterable", `for(const k of missing){}`},
		{"async iteration", `for await(const k of [1]){}`},
		{"console log", `console.log('x');`},
		{"unknown loop", `let x=0;while(missing){x++}`},
		{"unknown do while", `let x=0;do{x++}while(missing);`},
		{"unknown await", `await missing;`},
		{"unknown template", "const x = `prefix-${missing}`;"},
		{"unknown coercion", `const x=missing+1;`},
		{"unknown destructuring", `const {x}=missing;`},
		{"object coercion", `const x='a'+{};`},
		{"inherited destructuring", `const {toString}={};if(toString)mystery();`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Analyze(tc.src)
			checkContract(t, r)
			if !r.Conservative || r.Reason == "" {
				t.Fatalf("missing degradation: %+v", r)
			}
		})
	}
}

func TestUnsupportedValuesDegrade(t *testing.T) {
	for _, tc := range []struct{ name, src, reason string }{
		{"bigint", `const x=10n;`, "unsupported JavaScript numeric literal"},
		{"legacy octal", `const x=010;`, "unsupported JavaScript numeric literal"},
		{"numeric overflow", `const x=1e400;`, "unsupported JavaScript numeric literal"},
		{"large hexadecimal", `const x=0x20000000000001;`, "unsupported JavaScript numeric literal"},
		{"invalid escape", `const x="\u{110000}";`, "unsupported JavaScript string literal"},
		{"lone surrogate", `const x="\uD800";`, "unsupported JavaScript string literal"},
		{"string postfix", `let x="a";const y=x++;`, "JavaScript update coercion is unmodelled"},
		{"boolean prefix", `let x=true;const y=--x;`, "JavaScript update coercion is unmodelled"},
		{"null postfix", `let x=null;const y=x--;`, "JavaScript update coercion is unmodelled"},
		{"undefined prefix", `let x;const y=++x;`, "JavaScript update coercion is unmodelled"},
		{"primitive unary", `const x=+"1";`, "JavaScript primitive coercion is unmodelled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, s := analyze("values.js", tc.src, nil)
			checkContract(t, r)
			if r.Top || !r.Conservative || r.Reason != tc.reason || s == nil {
				t.Fatalf("unsupported value lacks a local degradation: %+v", r)
			}
			expectValue(t, s, "x", Value{})
			if strings.Contains(tc.src, "const y=") {
				expectValue(t, s, "y", Value{})
			}
			if len(r.Derivations) == 0 || len(r.Derivations[0].Atoms) == 0 {
				t.Fatal("missing degradation provenance")
			}
			loc := r.Derivations[0].Atoms[0].Loc
			if loc == nil || loc.File != "values.js" || loc.Line != 1 {
				t.Fatalf("missing source location: %+v", loc)
			}
		})
	}
}

func TestHashbangIsInert(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"pure loop", "#!/usr/bin/env node\nconst N=3;for(let i=0;i<N;i++){const x=i*2;}"},
		{"CRLF", "#!/usr/bin/env node\r\nconst x=1;"},
		{"hashbang only", "#!/usr/bin/env node"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := evaluate(t, tc.src)
			if len(r.Effects) != 0 || r.Reason != "" {
				t.Fatalf("hashbang fabricated an effect: %+v", r)
			}
		})
	}
}

func TestForEachTDZPreservesCatchPath(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"of", `let x=[1];try{for(let x of x){}}catch(e){unknown()}`},
		{"in", `let x={a:1};try{for(let x in x){}}catch(e){unknown()}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Analyze(tc.src)
			if !r.Conservative || !hasReason(r, "JavaScript call effects are unmodelled") {
				t.Fatalf("TDZ catch path was lost: %+v", r)
			}
		})
	}
}

func hasReason(r *Result, reason string) bool {
	for _, d := range r.Derivations {
		for _, atom := range d.Atoms {
			if atom.Text == reason {
				return true
			}
		}
	}
	return false
}

func checkContract(t *testing.T, r *Result) {
	t.Helper()
	if r == nil {
		t.Fatal("nil result")
	}
	found := false
	for _, eff := range r.Effects {
		if err := eff.Validate(); err != nil {
			t.Fatal(err)
		}
		if eff.Kind == engine.KindCodeExec && eff.Target.IsTop() {
			found = true
		}
	}
	if (r.Top || r.Conservative) && (!found || r.Reason == "") {
		t.Fatalf("inconsistent top: %+v", r)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatal(err)
	}
}

func TestFunctionBodiesUseStatementEvaluator(t *testing.T) {
	root, reason := parse(`function f(p){try{return p+1}finally{p=9}}`)
	if root == nil {
		t.Fatal(reason)
	}
	body := root.first().get("body")
	s := newState()
	s.scopes[0]["p"] = binding{value: numberValue(2), initialized: true}
	e := &evaluator{result: &Result{}, budget: defaultBudget}
	out := e.exec(body, s)
	if out[returning] == nil || out[returning].value.number != 3 {
		t.Fatalf("return lost: %+v", out)
	}
	expectValue(t, out[returning].state, "p", numberValue(9))
	r := Analyze(`function dormant(){unknown()};const arrow=()=>unknown();`)
	if r.Conservative || len(r.Effects) > 0 {
		t.Fatalf("declaration invoked body: %+v", r)
	}
}

func TestUnknownJoinPreservesTaint(t *testing.T) {
	secret := stringValue("secret")
	secret.Taint = engine.TaintOf(engine.TaintSecret)
	got := joinValue(secret, stringValue("public"))
	if got.kind != "" || !got.Taint.Contains(engine.TaintSecret) {
		t.Fatalf("lost provenance: %+v", got)
	}
}

func TestDeterminismAndIndependentResults(t *testing.T) {
	src := `const o={a:1,b:2};let x=0;if(missing)x=1;else x=2;unknown(x);`
	want, _ := json.Marshal(Analyze(src))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			got := Analyze(src)
			encoded, _ := json.Marshal(got)
			if !slices.Equal(want, encoded) {
				t.Error("non-deterministic analysis")
			}
			if len(got.Effects) > 0 {
				got.Effects[0].Target = engine.ScopeOf("mutated")
			}
		})
	}
	wg.Wait()
	got, _ := json.Marshal(Analyze(src))
	if !slices.Equal(want, got) {
		t.Fatal("shared mutable result")
	}
}

func TestAdversarialBounds(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"deep", strings.Repeat("(", maxDepth+1) + "0" + strings.Repeat(")", maxDepth+1)},
		{"parser recovery", strings.Repeat("(", 64_000) + strings.Repeat(")", 64_000)},
		{"brackets", strings.Repeat("[", 32_000) + strings.Repeat("]", 32_000)},
		{"braces", strings.Repeat("{", 32_000) + strings.Repeat("}", 32_000)},
		{"mixed delimiters", strings.Repeat("([{", maxDepth) + strings.Repeat("}])", maxDepth)},
		{"raw literal delimiters", "'" + strings.Repeat("(", maxDepth+1) + "'"},
		{"raw comment delimiters", "/*" + strings.Repeat("{", maxDepth+1) + "*/"},
		{"size", strings.Repeat(" ", maxSourceBytes+1)},
		{"growth", `let x='x';while(true){x+=x;}`},
		{"container cap", "[" + strings.Repeat("1,", maxRecorded) + "1]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			r := Analyze(tc.src)
			// Leave room for scheduling and parser cleanup, including -race.
			if elapsed := time.Since(start); elapsed > 6*time.Second {
				t.Fatalf("adversarial analysis exceeded its latency bound: %s", elapsed)
			}
			checkContract(t, r)
			if !r.Top {
				t.Fatalf("expected bounded failure: %+v", r)
			}
		})
	}
}

func TestParserTimeoutDiscardsPartialTree(t *testing.T) {
	// Flat source passes the delimiter check. A 25 ms budget is longer than
	// a Windows clock tick but too short to parse half a million statements.
	src := strings.Repeat("0;", maxSourceBytes/2)
	root, reason := parseWithTimeout(src, 25_000)
	if root != nil || reason != "JavaScript parse timeout" {
		t.Fatalf("timeout retained a partial tree: root=%v reason=%q", root != nil, reason)
	}
}

func FuzzAnalyze(f *testing.F) {
	for _, src := range []string{"", `const x=1`, `while(true){}`, `try{throw 1}catch(e){}finally{}`, `const {x}={x:1}`, "let x='unterminated", `function* f(){yield 1}`, `if(x) unknown()`} {
		f.Add(src)
	}
	f.Fuzz(func(t *testing.T, src string) { checkContract(t, Analyze(src)) })
}

func TestUnknownTemplateIsNotLiteral(t *testing.T) {
	r, s := analyze("", "const x=`prefix-${missing}`;", nil)
	checkContract(t, r)
	expectValue(t, s, "x", Value{})
}

func TestFinallyOverridesAbruptCompletion(t *testing.T) {
	root, reason := parse(`function f(){try{throw 1}finally{return 2}}`)
	if root == nil {
		t.Fatal(reason)
	}
	e := &evaluator{result: &Result{}, budget: defaultBudget}
	out := e.exec(root.first().get("body"), newState())
	if out[throwing] != nil || out[returning] == nil || out[returning].value.number != 2 {
		t.Fatalf("finally failed to override throw: %+v", out)
	}
}

func TestMaterializationConsumesBudget(t *testing.T) {
	r := Analyze("const x='" + strings.Repeat("x", defaultBudget) + "';")
	if !r.Top || !strings.Contains(r.Reason, "budget") {
		t.Fatalf("string decoding bypassed the budget: %+v", r)
	}
}

func TestWholeUnitFailureExplainsTheAbort(t *testing.T) {
	r := Analyze("unknown();while(true){}")
	if !r.Top || !strings.Contains(r.Reason, "budget") {
		t.Fatalf("earlier local uncertainty hid the whole-unit failure: %+v", r)
	}
}

func TestUnmodelledCoercionsPreserveCatchPaths(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"unresolved read", `try{missing}catch(e){record()}`},
		{"unary", `try{+missing}catch(e){record()}`},
		{"update", `let x=missing;try{x++}catch(e){record()}`},
		{"unsupported binary", `try{1 in 2}catch(e){record()}`},
		{"unknown iterable", `try{for(const k of missing){}}catch(e){record()}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			r := AnalyzeWith("", tc.src, func(c Call) Resolution {
				if c.Callee == "record" {
					reached = true
				}
				return Resolution{Handled: true, Value: undefined()}
			})
			if !reached || tc.name != "unresolved read" && !r.Conservative {
				t.Fatalf("coercion lost execution or catch: reached=%v result=%+v", reached, r)
			}
		})
	}
}

func TestBudgetPreservesEffects(t *testing.T) {
	effect := engine.Effect{Kind: engine.KindFSRead, Target: engine.ScopeOf("/test-input"), Mode: engine.ModeDirect, Certainty: engine.CertaintyCertain, Reversible: true}
	r := AnalyzeWith("input.js", `record();while(true){}`, func(c Call) Resolution {
		return Resolution{Handled: true, Value: undefined(), Effects: []engine.Effect{effect}, Derivations: []engine.Derivation{{Effect: effect, Atoms: []engine.Atom{{Kind: engine.AtomCommand, Text: "record", Loc: &c.Loc}}}}}
	})
	checkContract(t, r)
	if !r.Top || !strings.Contains(r.Reason, "budget") {
		t.Fatalf("not budget exhaustion: %+v", r)
	}
	if len(r.Effects) != 2 || !r.Effects[0].Target.Equal(effect.Target) {
		t.Fatalf("lost earlier effect: %+v", r)
	}
}

func TestHeadersAndUnknownExceptions(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string
	}{
		{"condition", `if(mark('condition')){}`, []string{"condition"}},
		{"loop headers", `for(mark('init');false;mark('update')){};do{}while(mark('do'));`, []string{"init", "do"}},
		{"iterable", `for(const x of mark('iterable')){}`, []string{"iterable"}},
		{"case test", `switch(1){case mark('case'):break}`, []string{"case"}},
		{"catch", `try{unknown()}catch(e){mark('catch')}finally{mark('finally')}`, []string{"catch", "finally"}},
		{"computed key", `const x={[mark('key')]:mark('value')}`, []string{"key", "value"}},
		{"dead arm", `if(false){mark('dead')}else{mark('live')}`, []string{"live"}},
		{"short circuit", `false&&mark('dead');true||mark('dead');null??mark('live')`, []string{"live"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seen := []string{}
			r := AnalyzeWith("input.js", tc.src, func(c Call) Resolution {
				if c.Callee != "mark" {
					return Resolution{}
				}
				if len(c.Args) > 0 {
					v, _ := c.Args[0].String()
					seen = append(seen, v)
				}
				return Resolution{Handled: true, Value: boolValue(false)}
			})
			checkContract(t, r)
			// Finally can run on normal and throwing paths.
			for _, want := range tc.want {
				if !slices.Contains(seen, want) {
					t.Fatalf("missing %s: %v", want, seen)
				}
			}
			for _, got := range seen {
				if got == "dead" {
					t.Fatalf("evaluated dead expression: %v", seen)
				}
			}
		})
	}
}

func TestValueTaintSurvivesUnknownJoin(t *testing.T) {
	var observed Value
	r := AnalyzeWith("", `let x=source();if(missing)x='public';observe(x);`, func(c Call) Resolution {
		if c.Callee == "source" {
			v := stringValue("synthetic")
			v.Taint = engine.TaintOf(engine.TaintSecret)
			return Resolution{Handled: true, Value: v}
		}
		observed = c.Args[0]
		return Resolution{Handled: true, Value: undefined()}
	})
	if r.Conservative || observed.kind != "" || !observed.Taint.Contains(engine.TaintSecret) {
		t.Fatalf("lost provenance: %+v %+v", r, observed)
	}
}

func TestSwitchEntryStates(t *testing.T) {
	var got []float64
	r := AnalyzeWith("", `let x=0;switch(missing){case (x=1):observe(x);break;case (x=2):observe(x);break;}`, func(c Call) Resolution {
		got = append(got, c.Args[0].number)
		return Resolution{Handled: true, Value: undefined()}
	})
	if r.Conservative || !slices.Equal(got, []float64{1, 2}) {
		t.Fatalf("case entry states lost: %v %+v", got, r)
	}
}

func TestAnalyzeSourceContract(t *testing.T) {
	reason := Analyze("const OTHER_JS_SOURCE = '").Reason
	for _, tc := range []struct {
		name string
		src  string
		top  bool
	}{
		{"empty", "", false},
		{"whitespace", " \t\r\n", false},
		{"malformed", "const PRIVATE_JS_SOURCE = '", true},
		{"valid", "const PRIVATE_JS_SOURCE = 1;", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Analyze(tc.src)
			if !tc.top {
				if len(got.Effects) != 0 || got.Top || got.Conservative || got.Reason != "" {
					t.Fatalf("expected a pure result, got %+v", got)
				}
				return
			}
			if len(got.Effects) != 1 {
				t.Fatalf("got %d effects, want one", len(got.Effects))
			}
			e := got.Effects[0]
			if e.Kind != engine.KindCodeExec || !e.Target.IsTop() {
				t.Fatalf("expected CodeExec over top, got %+v", e)
			}
			if e.Mode != engine.ModeDirect || e.Certainty != engine.CertaintyCertain {
				t.Fatalf("unexpected mode or certainty: %+v", e)
			}
			if !e.Taint.IsBottom() || e.Reversible {
				t.Fatalf("unexpected taint or reversibility: %+v", e)
			}
			if !got.Top || !got.Conservative {
				t.Fatalf("expected top and conservative, got %+v", got)
			}
			if got.Reason == "" || got.Reason != reason || strings.Contains(got.Reason, "PRIVATE_JS_SOURCE") {
				t.Fatalf("expected a fixed, source-free reason, got %q", got.Reason)
			}
		})
	}
}

func TestAnalyzeResultsAreIndependent(t *testing.T) {
	first := Analyze("first()")
	second := Analyze("second()")
	first.Effects[0].Kind = engine.KindFSRead
	if second.Effects[0].Kind != engine.KindCodeExec {
		t.Fatal("mutating one result changed another")
	}
	if Analyze("third()").Effects[0].Kind != engine.KindCodeExec {
		t.Fatal("mutating one result changed later analyses")
	}
}
