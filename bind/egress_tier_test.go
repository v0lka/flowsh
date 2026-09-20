package bind

import (
	"testing"

	"github.com/v0lka/flowsh/engine"
	"github.com/v0lka/flowsh/kb"
)

// TestEgressTierInventory pins, from the binder's own side, the tier applied to
// every dialect that actually carries NetEgress parameters. The kb package
// cannot import bind (the import graph is one-way), so its inventory test
// (kb.TestNetEgressDialectInventory) pins only the dialect *set*; nothing there
// checks the strings against bind.lenientHostDialect, which is how the
// systemctl -H mis-tier went unnoticed. This test drives the real
// lenientHostDialect over the loaded KB, so a dialect silently moved between
// tiers fails here.
func TestEgressTierInventory(t *testing.T) {
	k, err := kb.Load()
	if err != nil {
		t.Fatalf("kb.Load: %v", err)
	}
	lenientWant := map[kb.Dialect]bool{
		kb.DialectCurl:      true, // destination positionals (URL)
		kb.DialectWget:      true, // destination positionals (URL)
		kb.DialectNetcat:    true, // destination positionals (HOST/PORT)
		kb.DialectOpenSSH:   true, // destination positionals (HOST)
		kb.DialectNetTools:  true, // dig/ping/telnet/smbclient/…
		kb.DialectRsync:     true, // destination positionals (remote specs)
		kb.DialectUtilLinux: true, // logger -n/--server
		kb.DialectSystemd:   true, // systemctl -H/--host declares a destination host
	}
	seen := map[kb.Dialect]bool{}
	for i := range k.Commands {
		c := &k.Commands[i]
		hasEgress := false
		for _, p := range c.Params {
			if p.Effect.Kind == engine.KindNetEgress {
				hasEgress = true
				break
			}
		}
		if !hasEgress {
			continue
		}
		seen[c.Dialect] = true
		if got, want := lenientHostDialect(c), lenientWant[c.Dialect]; got != want {
			t.Errorf("%s (dialect %q): lenientHostDialect = %v, want %v", c.Name, c.Dialect, got, want)
		}
	}
	// Every expected lenient dialect must actually be in use, so the table
	// cannot rot with a stale entry.
	for d := range lenientWant {
		if !seen[d] {
			t.Errorf("lenient tier lists dialect %q, but no KB command of it carries NetEgress parameters", d)
		}
	}
}
