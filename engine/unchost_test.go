package engine

import "testing"

// TestUNCHost pins the named UNC authority grammar (Findings 81, 87). An
// authority is named when the text proves it: the backslash spelling is a UNC
// path by construction, and the forward-slash spelling needs a dotted name or
// an address literal, because POSIX also reads `//host/share` as a doubled
// separator. A loopback or share-less path names no remote authority.
func TestUNCHost(t *testing.T) {
	cases := []struct {
		in   string
		host string
		ok   bool
	}{
		// The backslash spelling: single-label NetBIOS names are authorities.
		{`\\attacker\share\x`, "attacker", true},
		{`\\attacker\share`, "attacker", true},
		{`\\bastion.example\share`, "bastion.example", true},
		{`\\attacker/share\x`, "attacker", true},

		// The forward-slash spelling: only an unambiguous authority is named.
		{`//bastion.example/share`, "bastion.example", true},
		{`//attacker.example/share/x`, "attacker.example", true},
		{`//10.0.0.7/share/x`, "10.0.0.7", true},
		{`//attacker\share/x`, "", false}, // single label via forward slashes

		// Local authorities.
		{`//localhost/share/x`, "", false},
		{`\\localhost\share\x`, "", false},
		{`//127.0.0.1/share/x`, "", false},
		{`\\127.0.0.1\share`, "", false},

		// Not authorities: no share component, ordinary paths, single slash.
		{`/etc/shadow`, "", false},
		{`C:\Users\x`, "", false},
		{`//`, "", false},
		{`//host`, "", false},
		{`\\host`, "", false},
		{`//host/`, "", false},
		{`\\\\`, "", false},
	}
	for _, tc := range cases {
		host, ok := UNCHost(tc.in)
		if ok != tc.ok || host != tc.host {
			t.Errorf("UNCHost(%q) = (%q, %v), want (%q, %v)", tc.in, host, ok, tc.host, tc.ok)
		}
	}
}

// TestUNCUnresolved pins the ambiguous spelling (Finding 87): a forward-slash
// path whose authority is a single-label name is a UNC path to Windows and a
// doubled separator to POSIX, so it must not be silently classified either
// way. Everything the named grammar accepts is excluded (it is not ambiguous),
// and so is everything that names no share.
func TestUNCUnresolved(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// The ambiguous spelling.
		{`//attacker/share/x`, true},
		{`//attacker/share`, true},
		{`//tmp/x`, true},
		{`//SERVER01/share/x`, true},

		// Named authorities are not ambiguous.
		{`//attacker.example/share/x`, false},
		{`//10.0.0.7/share/x`, false},
		{`\\attacker\share\x`, false},
		{`\\tmp\x`, false},

		// Not authorities at all.
		{`//localhost/share/x`, false},
		{`//127.0.0.1/share/x`, false},
		{`/etc/shadow`, false},
		{`//host`, false},
		{`//host/`, false},
		{`//`, false},
		{`//bad label/share`, false},
	}
	for _, tc := range cases {
		if got := UNCUnresolved(tc.in); got != tc.want {
			t.Errorf("UNCUnresolved(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}

	// The two predicates are complementary over the UNC spellings: a path is
	// either a named authority or unresolved, never both and never neither.
	for _, p := range []string{`//attacker/share/x`, `//a.example/s`, `\\h\s`, `//localhost/s`} {
		host, named := UNCHost(p)
		ambiguous := UNCUnresolved(p)
		if named && ambiguous {
			t.Errorf("%q is both named (%q) and unresolved", p, host)
		}
	}
}
