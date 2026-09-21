package kb_test

import (
	"testing"

	"github.com/v0lka/flowsh/bind"
	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/front/bash"
	"github.com/v0lka/flowsh/kb"
)

// This file is the coverage gate for the routine command-line surface. Its
// purpose is the soundness property that motivated the CLI-surface dataset:
// an unmodelled binary makes a composite command degrade to the top element ⊤
// (a Direct CodeExec over the any-target scope, see bind/bind.go's unresolved
// branch), which forces a composite command to be judged as a whole instead of
// by its parts. A binary that the knowledge base resolves — even one whose
// invocation matches no parameter — contributes a bounded effect set (at worst
// the command's intrinsic ProcSpawn) and never ⊤.
//
// commonBinaries is the maintained inventory: every entry must be present in
// the knowledge base and must bind without resolving to ⊤. Adding a binary to
// the dataset means adding it here; removing one is a deliberate deletion that
// this test will catch.
var commonBinaries = []string{
	// Code-host and modern VCS clients.
	"gh", "glab", "jj", "git",
	// Command discovery and file inspection.
	"which", "file", "markitdown",
	// Language runtimes and their ecosystem tooling.
	"node", "bun", "python", "uv", "poetry", "ruby", "bundle",
	"java", "mvn", "gradle", "dotnet", "php", "composer", "elixir", "mix",
	"npm", "yarn", "pnpm", "pip", "gem", "cargo", "go", "rustc",
	// Build, test and lint drivers.
	"make", "cmake", "ninja", "tsc", "eslint", "prettier", "vitest", "jest",
	// golangci-lint is deliberately absent (see linting.yaml): the marker
	// already tolerates it as an unresolved verification driver (the
	// ⊤-on-CodeExec-only "unknown-driver signature"), and bounding it would
	// silently clear the marker on the audited TRUE_DENY shape that rewrites
	// the module graph (GOFLAGS=-mod=mod + a `> go.work` write, silent-audit
	// event 966665).
	"gofmt", "staticcheck", "ruff", "black", "mypy",
	"clippy-driver", "cargo-clippy", "shellcheck",
	// Data and query tools.
	"jq", "yq", "sqlite3", "psql", "redis-cli", "rg", "fd", "ag",
	// Container and infrastructure tooling.
	"docker", "docker-compose", "kubectl", "helm", "terraform",
	"ansible", "ansible-playbook", "ansible-vault", "ansible-galaxy",
	// Cloud provider clients.
	"aws", "gcloud", "az",
	// Extended language-ecosystem tooling: Go, Node.js and Python runtimes,
	// package managers, bundlers, framework CLIs and code generators (the
	// extended toolchain.yaml surface). Keeping them here is the maintained
	// bind probe: each must resolve and bind without ⊤.
	"gopls", "dlv", "goreleaser", "air", "mockgen", "swag", "wire", "stringer",
	"corepack", "deno", "tsx", "ts-node", "nodemon", "vite", "webpack", "rollup",
	"esbuild", "swc", "parcel", "next", "nuxt", "react-scripts", "turbo", "nx",
	"lerna", "gulp", "grunt", "pm2", "node-gyp",
	"uvx", "pipenv", "pdm", "hatch", "tox", "nox", "conda", "mamba",
	"virtualenv", "pipx", "ipython", "jupyter", "twine", "pyinstaller",
	// Extended language-ecosystem build/test/lint drivers (the extended
	// linting.yaml surface).
	"goimports", "gofumpt", "govulncheck", "gotestsum", "errcheck", "revive",
	"ineffassign", "gosec", "benchstat", "go-junit-report", "ginkgo",
	"mocha", "ava", "playwright", "cypress", "biome", "oxlint", "tsd",
	"typedoc", "uvu", "rimraf", "concurrently", "cross-env", "serve",
	"pytest", "flake8", "isort", "pylint", "pyright", "bandit", "coverage",
	"sphinx", "autopep8", "pydocstyle",
	// Extended language-ecosystem tooling: the JVM (Java/Scala/Kotlin), Rust
	// and Zig toolchains, package managers and build drivers (the extended
	// toolchain.yaml surface) plus the Rust formatter (linting.yaml).  Keeping
	// them here is the maintained bind probe: every name — including the mvnw
	// and cargo-fmt aliases — must resolve and bind without ⊤.
	"javac", "javadoc", "jar", "jshell", "keytool", "scala", "scalac", "sbt",
	"scala-cli", "mill", "kotlin", "kotlinc", "kotlinc-jvm", "kscript", "ant",
	"jbang", "coursier", "groovy", "clojure", "lein", "mvnd", "mvnw",
	"rustup", "rustdoc", "rust-analyzer", "nextest", "cargo-audit", "cargo-deny",
	"cargo-watch", "cargo-expand", "cargo-tarpaulin", "wasm-pack", "trunk",
	"cross", "bacon", "zig", "zls",
	"rustfmt", "cargo-fmt",
}

// acceptanceBinaries are the binaries named by the task's acceptance clause:
// each must resolve (no ⊤). Pinned separately so a regression names them.
var acceptanceBinaries = []string{"which", "file", "gh", "markitdown"}

// familyProbes is a representative invocation per family. Every one must bind
// to a bounded, non-conservative result — no ⊤.
var familyProbes = []struct {
	family string
	src    string
}{
	{"code-host", "gh pr list"},
	{"code-host", "glab mr list"},
	{"code-host", "jj log"},
	{"plumbing", "which bash"},
	{"plumbing", "file a.bin"},
	{"plumbing", "markitdown a.pdf"},
	{"toolchain", "node app.js"},
	{"toolchain", "python app.py"},
	{"toolchain", "go build ./..."},
	{"toolchain", "cargo build"},
	{"toolchain", "npm install"},
	{"toolchain", "uv sync"},
	{"toolchain", "poetry install"},
	{"toolchain", "ruby app.rb"},
	{"toolchain", "bundle install"},
	{"toolchain", "java -jar app.jar"},
	{"toolchain", "mvn package"},
	{"toolchain", "gradle build"},
	{"toolchain", "dotnet build"},
	{"toolchain", "php app.php"},
	{"toolchain", "composer install"},
	{"toolchain", "elixir app.exs"},
	{"toolchain", "mix compile"},
	{"build-test-lint", "make all"},
	{"build-test-lint", "cmake -S . -B build"},
	{"build-test-lint", "tsc -b"},
	{"build-test-lint", "eslint ."},
	{"build-test-lint", "prettier --write ."},
	{"build-test-lint", "vitest run"},
	{"build-test-lint", "jest"},
	// The runner and project-local bin-path spellings of the same binaries
	// (bind/runner.go): the everyday JS-stack verification loop the silent-mode
	// audit recorded as C6 false denies — they must bound, never ⊤.
	{"build-test-lint", "npx vitest run src/lib/x.test.tsx --reporter=basic"},
	{"build-test-lint", "npx tsc -b"},
	{"build-test-lint", "bunx eslint ."},
	{"build-test-lint", "./node_modules/.bin/vitest run"},
	// The package-runner spellings now also bind the NEW Node binaries from
	// toolchain.yaml: npx/bunx resolve their first non-flag operand through the
	// knowledge base, so the runner forms of vite/tsx/esbuild/next/turbo stay
	// bounded (no ⊤) and share one canonical identity with the bare forms.
	{"build-test-lint", "npx vite build"},
	{"build-test-lint", "npx tsx src/app.ts"},
	{"build-test-lint", "bunx esbuild app.ts"},
	{"build-test-lint", "npx next build"},
	{"toolchain", "npx turbo run build"},
	// The new tooling families and drivers must bound too: a runner/runtime, a
	// dependency manager, the test runners, a doc generator and a formatter.
	{"toolchain", "deno run app.ts"},
	{"toolchain", "pipenv install"},
	{"build-test-lint", "pytest -q"},
	{"build-test-lint", "playwright test"},
	{"build-test-lint", "coverage html"},
	{"build-test-lint", "gofumpt -w ."},
	{"build-test-lint", "gofmt -l ."},
	{"build-test-lint", "staticcheck ./..."},
	{"build-test-lint", "ruff check ."},
	{"build-test-lint", "black --check ."},
	{"build-test-lint", "mypy ."},
	{"build-test-lint", "cargo-clippy"},
	{"build-test-lint", "shellcheck a.sh"},
	// The JVM, Rust and Zig toolchains (the extended toolchain.yaml surface):
	// a compiler, a script runner, a build driver, a toolchain manager and the
	// Zig compiler/build system, plus the Rust formatter (linting.yaml).
	{"toolchain", "javac Foo.java"},
	{"toolchain", "scala app.scala"},
	{"toolchain", "sbt compile"},
	{"toolchain", "kotlinc app.kt"},
	{"toolchain", "rustup show"},
	{"toolchain", "zig build"},
	{"build-test-lint", "rustfmt src/main.rs"},
	{"data-query", "jq . f.json"},
	{"data-query", "yq . f.yaml"},
	{"data-query", "sqlite3 db.sqlite"},
	{"data-query", "psql -c 'select 1'"},
	{"data-query", "redis-cli ping"},
	{"data-query", "rg foo ."},
	{"data-query", "fd foo"},
	{"data-query", "ag foo"},
	{"container-infra", "docker run alpine"},
	{"container-infra", "docker-compose up"},
	{"container-infra", "kubectl get pods"},
	{"container-infra", "helm list"},
	{"container-infra", "terraform plan"},
	{"container-infra", "ansible all -m ping"},
	{"container-infra", "ansible-playbook site.yml"},
	{"container-infra", "ansible-vault view a.yml"},
	{"container-infra", "ansible-galaxy collection install x"},
	{"cloud", "aws s3 ls"},
	{"cloud", "gcloud compute instances list"},
	{"cloud", "az group list"},
}

// newBinder builds a binder over the embedded knowledge base.
func newBinder(t *testing.T) *bind.Binder {
	t.Helper()
	b, err := bind.NewDefault()
	if err != nil {
		t.Fatalf("bind.NewDefault: %v", err)
	}
	return b
}

// bindSrc binds the first simple command of src.
func bindSrc(t *testing.T, b *bind.Binder, src string) *bind.Result {
	t.Helper()
	prog := bash.Parse(bash.Bash, "t", src)
	if prog.Top || len(prog.Stmts) == 0 || prog.Stmts[0].Cmd == nil {
		t.Fatalf("parse %q failed", src)
	}
	return b.BindBash(prog.Stmts[0].Cmd, prog)
}

// topCodeExec reports whether res carries the ⊤ marker: a Direct CodeExec over
// the any-target scope (bind/bind.go's unresolved-command branch).
func topCodeExec(res *bind.Result) bool {
	for _, e := range res.Effects {
		if e.Kind == engine.KindCodeExec && e.Target.IsTop() {
			return true
		}
	}
	return false
}

// TestCommonBinaryInventory proves every maintained binary is actually in the
// knowledge base, and that the inventory is broad enough not to pass vacuously.
func TestCommonBinaryInventory(t *testing.T) {
	k, err := kb.Load()
	if err != nil {
		t.Fatalf("kb.Load: %v", err)
	}
	if len(commonBinaries) < 55 {
		t.Fatalf("inventory shrank to %d binaries; it is meant to be maintained", len(commonBinaries))
	}
	for _, name := range commonBinaries {
		if _, ok := k.Command(name); !ok {
			t.Errorf("common binary %q is not in the knowledge base", name)
		}
	}
	for _, name := range acceptanceBinaries {
		if _, ok := k.Command(name); !ok {
			t.Errorf("acceptance binary %q is not in the knowledge base", name)
		}
	}
}

// TestCommonBinaryResolvesWithoutTop binds every binary in the maintained
// inventory as a bare invocation and asserts it does not degrade to ⊤: the
// name resolves to a command (or builtin), the result is not conservative, and
// no effect is the ⊤ CodeExec marker.
func TestCommonBinaryResolvesWithoutTop(t *testing.T) {
	b := newBinder(t)
	for _, name := range commonBinaries {
		res := bindSrc(t, b, name)
		if res.Resolution.Kind == bind.ResolveUnknown || res.Resolution.Name == "" {
			t.Errorf("%s: resolved to unknown (⊤)", name)
			continue
		}
		if res.Conservative {
			t.Errorf("%s: result is conservative (⊤)", name)
		}
		if topCodeExec(res) {
			t.Errorf("%s: contributes the ⊤ CodeExec marker", name)
		}
	}
}

// TestFamilyReportsBounded proves a representative command from every family
// binds to a bounded, non-conservative result with at least one effect and no
// ⊤ marker — the composite-command case the dataset exists to avoid.
func TestFamilyReportsBounded(t *testing.T) {
	b := newBinder(t)
	for _, p := range familyProbes {
		res := bindSrc(t, b, p.src)
		if res.Resolution.Kind == bind.ResolveUnknown || res.Conservative {
			t.Errorf("%s: %q degraded to ⊤ (resolution %q, conservative %v)",
				p.family, p.src, res.Resolution.Kind, res.Conservative)
			continue
		}
		if len(res.Effects) == 0 {
			t.Errorf("%s: %q produced an empty effect set", p.family, p.src)
		}
		if topCodeExec(res) {
			t.Errorf("%s: %q contributed the ⊤ CodeExec marker", p.family, p.src)
		}
	}
}
