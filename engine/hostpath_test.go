package engine

import "testing"

// TestHostPath pins the remote-path grammar (Finding 99): the `[user@]host:/path`
// spelling an NFS mount source and an scp/rsync destination share names a host,
// while a Windows drive path, a scheme prefix, a host:port and a local filename
// containing a colon do not.
func TestHostPath(t *testing.T) {
	accept := []struct{ in, host string }{
		{"a.example:/export", "a.example"},
		{"a.example:/", "a.example"},
		{"user@a.example:/e", "a.example"},
		{"user@a.example:/e/", "a.example"},
		{"10.0.0.1:/srv", "10.0.0.1"},
		{"a.example:\\share", "a.example"},
		{"sub.a.example:/x", "sub.a.example"},
	}
	for _, c := range accept {
		if host, ok := HostPath(c.in); !ok || host != c.host {
			t.Errorf("HostPath(%q) = (%q, %v), want (%q, true)", c.in, host, ok, c.host)
		}
	}

	reject := []string{
		"",
		"/mnt",
		"./a.example:/x",
		"C:/x",                 // a Windows drive letter is single-label
		"C:\\x",                // the same, backslash spelling
		"http://a.example/x",   // a scheme, not an authority:port
		"https://a.example:/x", // the scheme is not the host
		"a.example:443",        // host:port, not a path
		"a.example:file",       // a local filename, and scp's relative form
		"b:/x",                 // a single-label host is not proven
		"dir:name/x",           // a local directory whose name contains a colon
		"localhost:/x",         // loopback is local by definition
		"127.0.0.1:/x",         // the same
		"[::1]:/x",             // the same, bracketed
		"@a.example:/x",        // no user, no host
	}
	for _, in := range reject {
		if host, ok := HostPath(in); ok {
			t.Errorf("HostPath(%q) = (%q, true), want rejected", in, host)
		}
	}
}
