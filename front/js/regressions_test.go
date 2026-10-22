package js

import (
	"math"
	"strings"
	"testing"

	"github.com/v0lka/flowsh/engine"
)

func TestReportedReachableCalls(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"inherited property", `const {toString}={};if(toString)dangerous();`},
		{"shadowed undefined", `{let undefined=1;if(undefined===1)dangerous();}`},
		{"signed zero join", `let x=-0;if(missing)x=0;if(1/x===1/0)dangerous();`},
		{"catch default finally", `let x=0;try{try{throw {a:void 0}}catch({a=missing}){}finally{x=1}}catch(e){if(x===1)dangerous();}`},
		{"postfix conversion", `let x='';if(x++===0)dangerous();`},
		{"numeric keys", `const o={1e21:1,1e22:2};if(o[1e21]===1)dangerous();`},
		{"unknown key null receiver", `try{null[1e21]}catch(e){dangerous()}`},
		{"catch parameter TDZ", `let a=1;try{try{throw {a:void 0}}catch({a=a}){}}catch(e){dangerous()}`},
		{"array spread mutation", `let x=0;const it={[Symbol.iterator]:function*(){x=1;yield 1}};x=0;[...it];if(x===1)dangerous();`},
		{"iteration default TDZ", `let a=1;try{for(const [a=a] of [[undefined]]){}}catch(e){dangerous()}`},
		{"let iteration default TDZ", `let a=1;try{for(let [a=a] of [[undefined]]){}}catch(e){dangerous()}`},
		{"class undefined", `class undefined{};if(undefined)dangerous();`},
		{"generator undefined", `function* undefined(){};if(undefined)dangerous();`},
		{"import undefined", `import undefined from './x.js';if(undefined===1)dangerous();`},
		{"import alias undefined", `import {x as undefined} from './x.js';if(undefined===1)dangerous();`},
		{"import named undefined", `import {undefined} from './x.js';if(undefined===1)dangerous();`},
		{"import namespace undefined", `import * as undefined from './x.js';if(undefined)dangerous();`},
		{"unknown key rest", `const o={'':1,a:2};const {[missing]:x,...rest}=o;if(rest['']===void 0)dangerous();`},
		{"array hole", `const [x]=[,];if(x)dangerous();`},
		{"typeof host global", `if(typeof process !== 'undefined')dangerous();`},
		{"typeof host function", `if(typeof require === 'function')dangerous();`},
		{"typeof host accessor throws", `try{typeof hostValue}catch(e){dangerous();}`},
		{"catch var initializer", `var x=0;try{throw 2}catch(x){var x=1}if(x===0)dangerous();`},
		{"catch var iteration", `var x=0;try{throw 2}catch(x){for(var x of [1]){}}if(x===0)dangerous();`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			r := AnalyzeWith("witness.js", tc.src, func(c Call) Resolution {
				if c.Callee == "dangerous" {
					reached = true
				}
				return Resolution{Handled: true, Value: undefined()}
			})
			checkContract(t, r)
			if !reached || r.Top {
				t.Fatalf("reachable call lost: reached=%v result=%+v", reached, r)
			}
		})
	}
}

func TestEscapedIdentifiersDegrade(t *testing.T) {
	for _, src := range []string{
		`let x=0;{let \u0078=1;if(x===1)dangerous();}`,
		`const o={\u0078:1};`,
		`const {\u0078}={x:1};`,
		`label: { break l\u0061bel; }`,
	} {
		r := Analyze(src)
		checkContract(t, r)
		if !r.Top || !strings.Contains(r.Reason, "escaped JavaScript identifiers") {
			t.Fatalf("escaped identifier was not rejected: %+v", r)
		}
	}
}

func TestSignedZeroComparisons(t *testing.T) {
	positive, negative := numberValue(0), numberValue(math.Copysign(0, -1))
	if sameValue(positive, negative) || sameValue(negative, positive) {
		t.Fatal("lattice conflates zero signs")
	}
	if !strictEqual(positive, negative) || joinValue(positive, negative).kind != "" {
		t.Fatal("strict equality or signed-zero join is incorrect")
	}
	if !sameValue(numberValue(math.NaN()), numberValue(math.NaN())) {
		t.Fatal("NaN must be stable under lattice equivalence")
	}
	if strictEqual(numberValue(math.NaN()), numberValue(math.NaN())) {
		t.Fatal("NaN must differ under strict equality")
	}
}

func TestOwnPropertyAndUpdatePrecision(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want Value
	}{
		{`const {'':x}={'':2};`, numberValue(2)},
		{`const o={'':2};const x=o[''];`, numberValue(2)},
		{`const {toString:x=2}={toString:undefined};`, numberValue(2)},
		{`const [x=7]=[undefined];`, numberValue(7)},
		{`let a=2;const x=a++;`, numberValue(2)},
		{`let a=2;const x=++a;`, numberValue(3)},
		{`let a=2;const x=a--;`, numberValue(2)},
		{`let a=2;const x=--a;`, numberValue(1)},
		{`const x=-0===0;`, boolValue(true)},
		{`let x;try{throw {a:undefined,b:undefined}}catch({a=1,b=a}){x=b}`, numberValue(1)},
		{`let x;for(const [a=1,b=a] of [[undefined,undefined]])x=b;`, numberValue(1)},
		{`var a=0;let x;try{throw 2}catch(a){var a=1;x=a}`, numberValue(1)},
		{`var a=0;let x;try{throw 2}catch(a){var a;x=a}`, numberValue(2)},
		{`const x=typeof undefined;`, stringValue("undefined")},
		{`let process=1;const x=typeof process;`, stringValue("number")},
		{`var process;const x=typeof process;`, stringValue("undefined")},
	} {
		_, s := evaluate(t, tc.src)
		expectValue(t, s, "x", tc.want)
	}
	var got Value
	r := AnalyzeWith("", `let x=source();observe(x++);`, func(c Call) Resolution {
		if c.Callee == "source" {
			v := stringValue("")
			v.Taint = engine.TaintOf(engine.TaintSecret)
			return Resolution{Handled: true, Value: v}
		}
		got = c.Args[0]
		return Resolution{Handled: true, Value: undefined()}
	})
	if r.Top || got.kind != "" || !got.Taint.Contains(engine.TaintSecret) {
		t.Fatalf("postfix conversion lost unknownness or taint: %+v %+v", got, r)
	}
}
