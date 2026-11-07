# Command Wrappers

## Role

This component documents the wrapper machinery of the bash frontend: the closed inventory of command wrappers the normalizer peels off the front of a simple command (`sudo`, `env`, `timeout`, …), the option/operand consumption rules each wrapper follows, the wrappers that carry their payload as a shell command *string* (`su -c CMD`), the one multi-word wrapper (`ip netns exec`), and the `find(1)` exec-action payloads that are commands of their own.

## Key Files

- `front/bash/normalize.go` — `wrapperSpec` (the per-wrapper consumption spec), `wrapperSpecs` (the closed 41-entry inventory), `commandStringWrappers`, `takesValue`/`dynamicValueOption`, `unwrap` (the peel loop), `ipNetnsExec`, `setarchArchitectures`, `SudoValueOpts`, and the find(1) payload extraction (`findExecActions`/`findPayloads`/`findPayload`).
- `front/bash/exec.go` — `commandStringPayload`/`wrapperCommandString`/`wrapperOptionsCommandString` (execution-time analysis of `-c` command strings), the find-payload dispatch (bounded by `maxFindDepth`), and the ⊤ "wrapper consumed the whole command line" degrade.

## Behavior

### The wrapper spec

```go
type wrapperSpec struct {
	valueOpts     map[string]bool // option tokens that consume the next word as their value
	envAssigns    bool            // NAME=value words after the options lift onto the wrapped command
	fixedArgs     int             // positional words the wrapper consumes after its options
	fixedUnless   map[string]bool // options whose presence replaces the fixed positional (taskset -c MASK)
	fixedIfIn     map[string]bool // consume the fixed positional only when its literal is in the set (setarch ARCH)
	requirePayload bool           // peel only when a payload word actually follows (chrt -p, ionice -p, flock FILE)
	defaultCmd    string          // implied command when nothing follows (xargs → echo)
}
```

### The closed inventory (`wrapperSpecs`, 41 entries)

Legacy eight (documented first in `parse-normalize.md`):

| Wrapper    | value-taking options | lifts env assigns | fixed positional | payload required | default command |
| ---------- | -------------------- | ----------------- | ---------------- | ---------------- | --------------- |
| `sudo`     | `-u/--user -g/--group -h/--host -D/--chdir -R/--chroot -p/--prompt -C/--close-from -T/--command-timeout -r/--role -t/--type -U/--other-user` | yes | 0 | — | — |
| `env`      | `-u/--unset -C/--chdir -S/--split-string` | yes | 0 | — | — |
| `nohup`    | — | no | 0 | — | — |
| `command`  | — | no | 0 | — | — |
| `nice`     | `-n/--adjustment` | no | 0 | — | — |
| `timeout`  | `-k/--kill-after -s/--signal` | no | 1 (the duration) | — | — |
| `xargs`    | `-n -I -i -d -P -s -E -L -a` and long forms | no | 0 | — | `echo` |
| `setsid`   | — | no | 0 | — | — |

Remaining flag/launcher wrappers:

| Wrapper       | value-taking options | fixed positional | payload required | notes |
| ------------- | -------------------- | ---------------- | ---------------- | ----- |
| `builtin`     | — | 0 | — | forces the shell builtin |
| `stdbuf`      | `-i/-o/-e/--input/--output/--error` | 0 | — | buffering-mode flags take the mode as their value |
| `watch`       | `-n/--interval` | 0 | — | other options are plain flags |
| `nsenter`     | `-t/--target -N/--net-socket -G/--setgid -S/--setuid` | 0 | — | a command-less nsenter executes `$SHELL`, so the peel stays unconditional |
| `unshare`     | `-R/--root -w/--wd -S/--setuid -G/--setgid -l/--load-interp` and the map-/owner/propagation/setgroups/monotonic/boottime long options | 0 | — | namespace options take an *optional* value and stay flags |
| `systemd-run` | the documented systemd set (`-u/--unit -p/--property -E/--setenv -H/--host -M/--machine -C/--capsule --json`, timer/calendar/slice/description/uid/gid/working-directory families) | 0 | yes | |
| `ssh-agent`   | `-a -E -O -P -t` | 0 | yes | a command-less ssh-agent starts a daemon and runs nothing |

Payload wrappers whose command-less form is a query or usage error — peeled only when a payload word follows (`requirePayload`):

| Wrapper       | value-taking options | fixed positional | notes |
| ------------- | -------------------- | ---------------- | ----- |
| `flock`       | `-c/--command -E/--conflict-exit-code -w/--wait --timeout --start --length` | 1 (the lock file) | also a command-string wrapper (below) |
| `taskset`     | `-c/--cpu-list -p/--pid` | 1 (MASK), suppressed by `fixedUnless {-c, --cpu-list}` | `-c` supplies the CPU list, so the MASK positional disappears |
| `ionice`      | `-c/--class -n/--classdata -p/--pid -P/--pgid -u/--uid` | 0 | |
| `chrt`        | `-T/--sched-runtime -P/--sched-period -D/--sched-deadline -p/--pid` | 1 (PRIORITY) | |
| `strace`, `ltrace`, `valgrind` | documented tracer sets (see `normalize.go`) | 0 | strace: `-a -b -e -E -I -O -p -P -s -S -u -X -o --output --trace --inject --fault …`; ltrace: `-a -A -b -e -l -n -o -p -s -u -x --output --config`; valgrind: `--tool --log-file … --xml-fd` |
| `caffeinate`  | `-t -w` | 0 | |
| `chroot`      | `--userspec --groups` | 1 (NEWROOT) | command-less runs `${SHELL} -i` |
| `runcon`      | `-c/--compute -t/--type -u/--user -r/--role -l/--range` | 0 | |
| `prlimit`     | `-p/--pid -o/--output` plus every resource long option (`--as --core --cpu --data --fsize --locks --memlock --msgqueue --nice --nofile --nproc --rss --rtprio --rttime --sigpending --stack`) and their util-linux short aliases | 0 | `--nofile 1024` separated form; `=`-attached is skipped |
| `switch_root` | `-c/--console` | 2 (NEW_ROOT NEW_INIT) | |
| `setarch`     | — | 1 (ARCH), consumed only when the literal is in `setarchArchitectures` (`fixedIfIn`) | the closed vocabulary of `setarch --list` |
| `linux32`, `linux64` | — | 0 | setarch with the architecture preset |
| `busybox`, `toybox` | — | 0 | the applet word is the payload command |
| `envdir`      | — | 1 (DIR) | |
| `softlimit`   | `-a -c -d -f -l -m -o -p -r -s -t` | 0 | |
| `faketime`    | `-f/--format --exclude-monotonic -m` | 1 (TIMESTAMP) | |
| `unbuffer`    | `-p` | 0 | |
| `xvfb-run`    | `-n -s -f -e -p --server-num --server-args --auth-file --error-file --auto-servernum` | 0 | |
| `systemd-cat` | `-t/--identifier -p/--priority --stderr --namespace -u/--unit` | 0 | command-less reads stdin |
| `torsocks`    | `-u/--user -p/--pass -P/--port -a/--address -i/--isolate` | 0 | |
| `proxychains`, `proxychains4` | `-f` | 0 | the version-suffixed name is its own entry |

### Peel rules (`unwrap`)

- `--` and a bare `-` terminate a wrapper's option run. A value attached to an option (`--user=root`, `-uroot`) is not a separate value (`takesValue`); a long option with `=` never consumes the next word.
- A partially dynamic word whose literal prefix names a value-taking option records that option unsatisfied (`@` placeholder) and is absorbed only when its dynamic tail is quoted (one field); an unquoted expansion field-splits, ends the option run, and stays the dynamically-named inner command (`dynamicValueOption`).
- `fixedUnless`: when any recorded option is in the set, the fixed positional is not consumed (taskset's `-c/--cpu-list` replaces the MASK positional).
- `fixedIfIn`: the fixed positional is consumed only when its literal text is a member of the set (setarch's ARCH word, from the closed `setarchArchitectures` vocabulary) — consuming the program word as ARCH would bind the payload's first option as a command.
- GNU option permutation: after the fixed positional is consumed, the option run is re-processed once — an option may follow the fixed positional (`setarch x86_64 -R cmd`, `timeout 5 -k 1 cmd`) because getopt permutes non-option words to the end; a payload command never starts with `-`, and `--` still terminates.
- `requirePayload`: a wrapper whose command-less form runs nothing (a query or usage error: `chrt -p PID`, `ionice -p PID`, `flock FILE`, `systemd-run --scope`) is peeled only when a payload word actually follows; otherwise the wrapper word stays the command and its own knowledge-base row binds it.
- When nothing remains after a wrapper chain, the wrapper's `defaultCmd` (`xargs` → `echo`) becomes the effective command.

### Command-string wrappers (`commandStringWrappers`)

`su`, `runuser`, `script` and `flock` take their payload as a *shell command string* (`su -c CMD`, `script -c CMD [FILE]`, `flock -c CMD FILE`) rather than as argv words. The word-level peel cannot express that payload, so `front/bash/exec.go` extracts the string, parses it as the shell line it is, and analyses it as the invocation it performs — degrading to ⊤ ("wrapper payload is a command string the analysis cannot bound") when it cannot be bound. The command-name-to-option mapping lives in `exec.go` (`wrapperCommandStringOpts`), keeping the normalizer free of binding decisions. `flock` is therefore a word-peel wrapper for its `FILE COMMAND` form *and* a command-string wrapper for its `-c` form.

### The multi-word wrapper (`ip netns exec`)

`ip [OPTIONS] netns exec NS COMMAND [ARG…]` is the one multi-word wrapper: without the peel, `ip netns exec ns1 rm -rf /x` graded Low because the destructive payload vanished. `ipNetnsExec` matches the shape (skipping ip's own value-taking global options `-n/--netns -f/--family -l/--loops -rc/--rcvbuf`), records the namespace operand as the wrapper's one arg, and leaves the payload as the effective command. Any other ip invocation (`ip netns list`, `ip addr`) runs no program and is not peeled.

### find(1) exec actions

`findPayloads` extracts the commands a `find(1)` invocation runs through its `-exec`/`-execdir`/`-ok`/`-okdir` actions: the words up to the `;`/`\;`/`+`/`\+` terminator are a command line of their own, peeled like any other (wrappers included). Each `{}` operand stands for a matched file — a path under one of the literal search roots — and is replaced by those roots (one word per root when bare `{}` meets several roots). A dynamically-named command, an expansion-bearing word, or an unresolvable search root leaves the payload unbounded (`findPayload.Certain == false`) and the executor degrades it to ⊤ ("find exec payload not analyzable") rather than binding a fabricated, narrow effect set — the same fail-closed rule the peel follows. Payload analysis is nested-bound by `maxFindDepth = 8` (`find … -exec find …`).

### Exported helper

`SudoValueOpts(opt)` reports whether `opt` is one of sudo's value-taking options — exported so the binder's wrapper-elevation pass, which re-walks the recorded option words, can tell consumed values from free-standing flags.

### Execution-time degrade

At execution, a wrapper chain that consumed the whole command line with no `defaultCmd` and no `-c` payload leaves no effective command (`env -S '<cmd>'` unbound, `sudo -i`, `timeout 5`, bare `env`/`xargs` without payload): the executor records a ⊤ effect ("wrapper consumed the whole command line") rather than failing open to an empty report, and still consults the resolver seam for the wrappers' own effects (`elevateWrappers`).

## Error Handling

- An unterminated find exec action is a find usage error: find runs no payload, and none is extracted.
- An unbound command-string payload or an unbounded find payload degrades to a ⊤ effect, never to a narrow fabricated one.
- A wrapper peel that would leave no command on a `requirePayload` wrapper is simply not performed — the wrapper word stays the command.

## Invariants

- `wrapperSpecs` is a closed set: a word names a wrapper only when it is fully literal and in the table (plus the `ip netns exec` shape).
- The peel never consumes a word it cannot statically recognize: a dynamic option value is recorded as an unsatisfied `@` placeholder, never glued to a following option.
- A wrapper is peeled only when a program provably runs: `requirePayload` wrappers stay whole without a payload word, and `fixedIfIn` consumes the positional only from its closed vocabulary.
- Payload extraction is fail-closed: uncertain payloads (dynamic command, expansion-bearing word, unresolvable root) degrade to ⊤.

## Related Specs

- [Parse & Normalize](parse-normalize.md) — where the peel runs during normalization.
- [Abstract Execution](abstract-exec.md) — command-string payloads, find payloads, and the wrapper-consumed-the-line ⊤.
- [Bash Frontend](README.md) — domain overview.
- [Binding](../binding.md) — wrapper elevation (`SudoValueOpts`) and the binder's copy of the env-assignment channels.
