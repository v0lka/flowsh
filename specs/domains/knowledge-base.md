# Knowledge Base

## Purpose

The knowledge base (`kb`) is the effect dataset of the analysis: a hand-verified mapping from a command's command-line parameters to the effects those parameters contribute, plus a separate destructive-flags table. It is authored as YAML under `kb/data/*.yaml`, compiled into the binary with `go:embed`, and parsed at start-up without ever touching the filesystem. The document schema is frozen and versioned (`effect-kb/v2`), so a data file authored against an unknown schema is rejected rather than silently mis-read.

## Key Files

- `kb/schema.go` — the frozen document schema and its types: `SchemaVersion`, `KnownVersions`, `Dialect`, `ParamKind`, `ValueSource`, `Effect`, `Param`, `Command`, `DestructiveClass`, `Destructive`, `KB`, and the validation methods.
- `kb/loader.go` — the loader: `go:embed data/*.yaml`, `Load`/`loadFS`/`documentNames`, `EmbeddedFiles` (the sorted names of the embedded documents), the decode/merge/build/validate pipeline, `Default`, and a dependency-free minimal YAML reader.

The `kb/data/` directory holds one YAML document per command tradition (discovery is automatic, so the set grows by adding files):

- `kb/data/builtins.yaml` — shell builtins (POSIX sh and common bash extensions), dialect `builtin`.
- `kb/data/coreutils.yaml` — POSIX utilities and GNU coreutils extensions, dialects `posix`/`gnu`.
- `kb/data/gnu.yaml` — the extended GNU coreutils set (informational, checksum/encoding, text filters, filesystem utilities), dialect `gnu`.
- `kb/data/findutils.yaml` — GNU findutils (`find`, `xargs`) and `tar`, dialects `findutils`/`tar`.
- `kb/data/util-linux.yaml` — util-linux commands (`mount`, `umount`, `wipefs`, `fdisk`, `losetup`, `chroot`, `su`, `mkfs`, …), dialect `util-linux`.
- `kb/data/bsd.yaml` — BSD/macOS variants (`chflags`, `sysctl -w`, …), dialect `bsd`.
- `kb/data/net.yaml` — network, remote-access and security tooling (net-tools, curl, wget, netcat, openssh, rsync), dialects `net-tools`/`curl`/`wget`/`netcat`/`openssh`/`rsync`.
- `kb/data/remote.yaml` — `rsync` and `git`, dialects `rsync`/`git`.
- `kb/data/vcs.yaml` — version-control clients other than git (`svn`, `hg`, `bzr`, `fossil`, `darcs`), dialect `vcs`.
- `kb/data/archive.yaml` — archivers and compressors (`gzip`, `bzip2`, `xz`, `zstd`, `zip`, `7z`, `cpio`, `pax`, `ar`, …, `isoinfo`), dialect `archive`.
- `kb/data/pkgmgr.yaml` — package managers (`apt`, `dpkg`, `rpm`, `pacman`, `pip`, `npm`, `cargo`, `go`, …), dialect `pkgmgr`.
- `kb/data/build.yaml` — build drivers, compilers/linkers, binary inspectors and debuggers (`make`, `cmake`, `gcc`, `ld`, `nm`, `objdump`, `readelf`, `strip`, `gdb`, `strace`, `patch`, `diff`, …), dialect `build`.
- `kb/data/procps.yaml` — procps-ng / process and system inspection (`ps`, `top`, `free`, `vmstat`, `uptime`, `pgrep`, `pkill`, `killall`, `watch`, `lsof`, …), dialect `procps`.
- `kb/data/security.yaml` — users, permissions, security policy and auditing (`passwd`, `useradd`, `setfacl`, `chcon`, `auditctl`, `gpg`, …), dialect `security`.
- `kb/data/systemd.yaml` — processes, services and system control (`systemctl`, `journalctl`, `service`, `crontab`, `at`, `screen`, `tmux`, …), dialect `systemd`.
- `kb/data/codehost.yaml` — code-host and modern version-control clients (`gh`, `glab`, `jj`), dialect `vcs`.
- `kb/data/plumbing.yaml` — command discovery and file inspection (`which`, `file`) and the document converter `markitdown`, dialects `builtin`/`build`/`gnu`. (`markitdown`'s optional remote Document-Intelligence endpoint is deliberately left UNMODELLED — accepted recall gap: modelling it would put the `gnu` dialect on the network-egress inventory, so only the local-path read is modelled; see `plumbing.yaml` and `kb/loader_test.go TestNetEgressDialectInventory`.)
- `kb/data/toolchain.yaml` — language runtimes and ecosystem tooling (`node`, `bun`, `python`, `uv`, `poetry`, `ruby`, `bundle`, `java`, `mvn`, `gradle`, `dotnet`, `php`, `composer`, `elixir`, `mix`), dialect `pkgmgr`.
- `kb/data/linting.yaml` — front-end build/test/lint drivers (`tsc`, `eslint`, `prettier`, `vitest`, `jest`, `gofmt`, `staticcheck`, `ruff`, `black`, `mypy`, `clippy-driver`, `cargo-clippy`, `shellcheck`), dialect `build`. (`golangci-lint` is deliberately left UNMODELLED — the verification marker tolerates it as an unresolved driver, and bounding it would silently clear the marker on the audited TRUE_DENY shape that rewrites the module graph; see `linting.yaml`.)
- `kb/data/datatools.yaml` — data and query tools (`jq`, `yq`, `sqlite3`, `psql`, `redis-cli`, `rg`, `fd`, `ag`), dialects `gnu`/`findutils`/`net-tools`.
- `kb/data/containers.yaml` — container and infrastructure tooling (`docker`, `docker-compose`, `kubectl`, `helm`, `terraform`, `ansible` and its per-binary entry points), dialect `systemd`.
- `kb/data/cloud.yaml` — cloud provider clients (`aws`, `gcloud`, `az`), dialect `net-tools`.
- `kb/data/destructive.yaml` — the destructive-flags table: `(command, spec)` pairs known to be destructive, with a severity class and a reason.
- `kb/loader_test.go` — loader tests, including version-rejection and referential-integrity cases.
- `kb/coverage_test.go` — the common-binary inventory gate: every maintained routine CLI binary resolves (no ⊤), and a representative command per family binds to a bounded, non-conservative report.

## Core Types

### Dialect

Names the implementation family (command tradition) a command's parameter set is documented against. A command belongs to exactly one family.

```go
type Dialect string

const (
	DialectPOSIX     Dialect = "posix"      // POSIX.1-2017 utilities
	DialectGNU       Dialect = "gnu"        // GNU coreutils/extensions
	DialectBSD       Dialect = "bsd"        // BSD/macOS variants
	DialectUtilLinux Dialect = "util-linux" // util-linux
	DialectFindutils Dialect = "findutils"  // GNU findutils
	DialectTar       Dialect = "tar"        // GNU tar / bsdtar
	DialectNetTools  Dialect = "net-tools"  // net-tools (ifconfig, route, …)
	DialectCurl      Dialect = "curl"
	DialectWget      Dialect = "wget"
	DialectNetcat    Dialect = "netcat" // nc
	DialectOpenSSH   Dialect = "openssh"
	DialectRsync     Dialect = "rsync"
	DialectGit       Dialect = "git"
	DialectPkgmgr    Dialect = "pkgmgr"   // distribution package managers
	DialectBuild     Dialect = "build"    // compilers, linkers, build systems
	DialectProcps    Dialect = "procps"   // procps-ng process/system utilities
	DialectSystemd   Dialect = "systemd"  // systemd services and journal
	DialectArchive   Dialect = "archive"  // archive and compression tools
	DialectSecurity  Dialect = "security" // users, permissions, audit, crypto
	DialectVCS       Dialect = "vcs"      // version-control clients
	DialectBuiltin   Dialect = "builtin"  // shell builtins
)
```

The `Dialects` slice in `kb/schema.go` lists every valid dialect in canonical order (the order above), and `Dialect.Valid()` derives from its membership set. Each new dialect names a real tradition: the process/system utilities are `procps`, the service/journal/scheduling/power-control tier is `systemd`, the archivers and compressors are `archive`, the users/permissions/audit/crypto tier is `security`, the version-control and code-host clients (`svn`, `hg`, `bzr`, `fossil`, `darcs`, `gh`, `glab`, `jj`) are `vcs`, and package managers, language toolchains and build tooling are `pkgmgr` and `build`. macOS variants of the process/system utilities stay under `bsd`.

### Command to dialect map (roadmap B2-B9)

The expanded command sets are laid out one document per tradition, and every command in a document carries that tradition's dialect (a command belongs to exactly one dialect). The map below is the reference for that layout; the data files remain the single source of truth. macOS variants of the process/system utilities stay under `bsd`, and `find`, `tar`, `git` and `rsync` keep their dedicated dialects.

- `posix` (`coreutils.yaml`): cat, chmod, chown, cp, dd, grep, ln, ls, mkdir, mv, rm, rmdir, sed, sort, touch.
- `gnu` (`coreutils.yaml`, `gnu.yaml`, `plumbing.yaml`, `datatools.yaml`): arch, b2sum, base32, base64, basename, cksum, comm, csplit, cut, date, df, dir, dircolors, dirname, du, env, expand, expr, factor, fmt, fold, groups, head, hostid, hostname, id, install, jq, join, link, logname, markitdown, md5sum, mkfifo, mknod, mktemp, nice, nl, nohup, nproc, numfmt, od, paste, pathchk, pinky, pr, printenv, ptx, readlink, realpath, runcon, seq, sha1sum, sha224sum, sha256sum, sha384sum, sha512sum, shred, shuf, sleep, split, sqlite3, stat, stdbuf, stty, sum, sync, tac, tail, tee, timeout, tr, truncate, tsort, tty, uname, unexpand, uniq, unlink, users, vdir, wc, who, whoami, yes, yq.
- `findutils` (`findutils.yaml`, `datatools.yaml`): ag, fd, find, rg, xargs.
- `tar` (`findutils.yaml`): tar.
- `util-linux` (`util-linux.yaml`): blkdiscard, blkid, blockdev, cal, cfdisk, chattr, chroot, chrt, dmesg, eject, fallocate, fdisk, findmnt, flock, fsck, getopt, hexdump, hwclock, ionice, ipcmk, ipcrm, ipcs, isosize, last, ldattach, logger, login, look, losetup, lsattr, lsblk, lscpu, lslocks, lsmem, lsns, mdadm, mkfs, mkfs.ext4, mkswap, more, mount, mountpoint, namei, newgrp, nsenter, parted, partx, pivot_root, prlimit, raw, rename, renice, rev, rtcwake, runuser, script, setsid, setterm, sfdisk, sgdisk, su, swapoff, swapon, switch_root, tailf, taskset, ul, umount, unshare, uuidgen, wall, whereis, wipefs, write, zramctl.
- `procps` (`procps.yaml`): free, fuser, killall, lsof, pgrep, pkill, pmap, ps, pstree, slabtop, top, uptime, vmstat, w, watch.
- `systemd` (`systemd.yaml`, `containers.yaml`): ansible, ansible-config, ansible-doc, ansible-galaxy, ansible-inventory, ansible-playbook, ansible-vault, at, batch, crontab, docker, docker-compose, halt, helm, init, journalctl, kubectl, poweroff, reboot, runlevel, screen, service, shutdown, systemctl, systemd-run, telinit, terraform, tmux.
- `net-tools` (`net.yaml`, `datatools.yaml`, `cloud.yaml`): arp, aws, az, dig, firewall-cmd, ftp, gcloud, host, ifconfig, ip, ip6tables, iptables, ldapsearch, masscan, mtr, netstat, nft, nmap, nslookup, openssl, ping, ping6, psql, redis-cli, route, rpcclient, smbclient, smbget, ss, tcpdump, telnet, tftp, tracepath, traceroute, tshark, ufw.
- `netcat` (`net.yaml`): nc, ncat, socat.
- `curl` (`net.yaml`): curl.
- `wget` (`net.yaml`): wget.
- `openssh` (`net.yaml`): autossh, scp, sftp, ssh, ssh-add, ssh-agent, ssh-copy-id, ssh-keygen, ssh-keyscan.
- `rsync` (`net.yaml`, `remote.yaml`): rclone, rsync.
- `git` (`remote.yaml`): git.
- `archive` (`archive.yaml`): 7z, 7za, ar, bunzip2, bzip2, compress, cpio, genisoimage, gunzip, gzip, isoinfo, mkisofs, pax, rar, uncompress, unrar, unxz, unzip, xz, zcat, zip, zstd.
- `pkgmgr` (`pkgmgr.yaml`, `toolchain.yaml`): apk, apt, bun, bundle, cargo, composer, dnf, dotnet, dpkg, elixir, flatpak, gem, go, gradle, java, mix, mvn, node, npm, pacman, php, pip, pnpm, poetry, python, rpm, ruby, rustc, snap, uv, yarn, yum, zypper.
- `build` (`build.yaml`, `plumbing.yaml`, `linting.yaml`): as, black, cargo-clippy, clippy-driver, cmake, cmp, diff, eslint, file, gcc, gdb, gofmt, jest, ld, ltrace, make, mypy, ninja, nm, objdump, patch, prettier, readelf, ruff, shellcheck, staticcheck, strace, strings, strip, tsc, valgrind, vitest.
- `security` (`security.yaml`): auditctl, ausearch, chage, chcon, chfn, chpasswd, chsh, getfacl, gpasswd, gpg, groupadd, groupdel, groupmod, passwd, restorecon, semanage, setfacl, useradd, userdel, usermod, visudo.
- `vcs` (`vcs.yaml`, `codehost.yaml`): bzr, darcs, fossil, gh, glab, hg, jj, svn.
- `bsd` (`bsd.yaml`): caffeinate, chflags, defaults, diskutil, dscl, launchctl, mdfind, mdls, open, pbcopy, pbpaste, softwareupdate, sw_vers, sysctl, xattr.
- `builtin` (`builtins.yaml`, `plumbing.yaml`): bind, caller, cd, command, compgen, complete, declare, echo, enable, eval, exec, export, fc, hash, help, history, kill, local, mapfile, printf, pwd, read, readonly, set, source, test, trap, type, ulimit, umask, unset, wait, which.

### ParamKind / ValueSource

`ParamKind` classifies how a parameter is written; `ValueSource` says which token of the invocation becomes the effect's target.

```go
type ParamKind string

const (
	ParamFlag       ParamKind = "flag"       // -r, --recursive, -delete
	ParamOption     ParamKind = "option"     // -o FILE, --output=FILE
	ParamPositional ParamKind = "positional" // rm FILE, cp SRC DEST
	ParamAssign     ParamKind = "assign"     // dd of=FILE, if=FILE
)

type ValueSource string

const (
	ValueArgs      ValueSource = "args"      // positional arguments
	ValueFlagValue ValueSource = "flagValue" // the value attached to the flag
	ValueStdin     ValueSource = "stdin"     // standard input
	ValueEnv       ValueSource = "env"       // the process environment
	ValueCwd       ValueSource = "cwd"       // the current working directory
	ValueSelf      ValueSource = "self"      // the command's own binary/image
	ValueLiteral   ValueSource = "literal"   // a literal encoded in the flag value
)
```

### Effect / Param / Command

`Effect` reuses the core's closed `EffectKind`/`EffectMode` sets (see the engine spec) and adds the KB-specific value source. `fileRef` marks the `@file` convention.

```go
type Effect struct {
	Kind      engine.EffectKind `yaml:"kind"`
	Mode      engine.EffectMode `yaml:"mode"`
	ValueFrom ValueSource       `yaml:"valueFrom"`
	FileRef   bool              `yaml:"fileRef,omitempty"` // @path / @- ; requires ValueFlagValue
}

type Param struct {
	Spec   string    `yaml:"spec"`   // "-r", "-o", "FILE", "of="
	Kind   ParamKind `yaml:"kind"`
	Effect Effect    `yaml:"effect"`
}

type Command struct {
	Name    string   `yaml:"name"`
	Dialect Dialect  `yaml:"dialect"`
	Aliases []string `yaml:"aliases,omitempty"`
	Params  []Param  `yaml:"params"`
}
```

`Effect.Validate`, `Param.Validate` and `Command.Validate` enforce well-formedness; `Effect.EngineEffect(target, taint, certainty)` lowers a KB effect into a core `engine.Effect`, and `DefaultReversible(kind)` supplies the conservative reversibility default. `Command.buildIndex()` precomputes a `Spec`→position index (`paramIndex`) over `Params`, and `Command.AssignParams()` returns its `ParamAssign` params in declaration order (the binder consumes both for O(1) parameter lookup).

### DestructiveClass / Destructive

The classes are lettered A–E and line up with the core `Destructiveness` lattice (A ↔ None … E ↔ Critical), so a class folds into a report without a second taxonomy.

```go
type DestructiveClass string

const (
	ClassNone     DestructiveClass = "A" // None
	ClassLow      DestructiveClass = "B" // Low
	ClassMedium   DestructiveClass = "C" // Medium
	ClassHigh     DestructiveClass = "D" // High
	ClassCritical DestructiveClass = "E" // Critical
)

type Destructive struct {
	Command string           `yaml:"command"`
	Spec    string           `yaml:"spec"`
	Class   DestructiveClass `yaml:"class"`
	Reason  string           `yaml:"reason"`
}
```

`DestructiveClass.Severity()` maps the class onto `engine.Destructiveness`.

### KB

```go
type KB struct {
	Version     string        // the single schema version shared by all documents
	Commands    []Command     // sorted by Name
	Destructive []Destructive // sorted by (Command, Spec)

	byName  map[string]*Command     // keyed by name and every alias
	byDestr map[string]*Destructive // keyed by "command|spec"
}
```

Lookups: `Command(name)` (name or alias), `DestructiveFor(command, spec)`, `CommandNames()`, and `Validate()`.

## Flow

```
kb/data/*.yaml  (embedded via //go:embed data/*.yaml)
        │
        ▼  Load()
   loadFS(dataFS, "data")
        │
        ├─ documentNames()        enumerate + sort *.yaml / *.yml names
        │
        ▼  for each document name (sorted)
   parseDocument(raw, src)         minimal YAML reader → document
        │
        ▼
   KB.merge(doc, src)              require a known, single, non-conflicting version
        │
        ▼  after all documents
   KB.build()                      stable-sort Commands by Name,
        │                          stable-sort Destructive by (Command, Spec),
        │                          build byName (name + aliases) and byDestr maps,
        │                          and each Command's Spec→position index
        ▼
   KB.Validate()                   version known; every Command/Param/Destructive valid;
                                   every destructive entry references a declared param
        │
        ▼
      *KB  (cached by Default())
```

`Load` reads only from the embedded filesystem, so it works from any working directory with no external files present. `Default()` parses the embedded KB at most once (`sync.Once`).

## Invariants

- Every data document declares exactly one schema version, and all documents in a load agree on it; a missing, unknown, or conflicting version is a hard error.
- `kb` imports the frozen core (`github.com/v0lka/flowsh/engine`); the core never imports `kb` — the dependency is one-way.
- Loading reads only the embedded filesystem; it never opens a file on disk at run time.
- `build` canonicalises order before indexing: `Commands` is sorted by `Name`, `Destructive` by `(Command, Spec)`; the indexes hold pointers into those sorted slices.
- Command names and aliases are unique across the whole KB; a duplicate name/alias is a build error.
- Destructive entries are unique by `(command|spec)`.
- Every destructive entry refers to a parameter that is actually declared on a known command (referential integrity).
- A parameter's `spec` syntax matches its `kind`: `flag`/`option` specs start with `-`, `assign` specs end with `=`, `positional` specs do not start with `-`.
- An effect's `kind` and `mode` are members of the core's closed sets, and `fileRef` is set only when `valueFrom: flagValue`.
- Distinct documents' commands are merged by appending; conflicts surface either as a duplicate name/alias (build) or a duplicate destructive key.
- A command belongs to exactly one dialect, and every dialect listed in `Dialects` is exercised by at least one command (`TestDialectCoverage` in `kb/loader_test.go`).

## Configuration

- `SchemaVersion` = `"effect-kb/v2"` — the only accepted value today; every data file declares `version: effect-kb/v2`.
- `KnownVersions` = `[]string{SchemaVersion}` — the explicit list the loader accepts; extend it to add a version.
- `dataDir` = `"data"` — the directory inside the embedded FS holding the schema documents.
- Document discovery accepts `.yaml` and `.yml`; at least one document must exist.
- Supported YAML subset (a strict, documented subset — anything else is an explicit error): block mappings, block sequences, single-line flow collections, plain/single/double-quoted scalars, and `#` comments. Anchors, aliases, tags, multi-line scalars and tab indentation are rejected.
- `Default()` caches a single parsed KB; use `Load()` for a fresh, independently-parsed copy.

## Extension Points

- **Add a command or parameter**: append to the relevant `kb/data/*.yaml` document (or add a new `*.yaml` file — discovery is automatic). Keep the `kind`/`spec` syntax consistent; validation rejects drift.
- **Add a dialect**: append to the `Dialect` constants and to the `Dialects` slice in `kb/schema.go`.
- **Add a destructive flag**: add a `(command, spec, class, reason)` entry to `kb/data/destructive.yaml`. The spec must already be declared on the command.
- **Add a parameter/effect field shape**: bump `SchemaVersion` and add the new value to `KnownVersions` (this is exactly why v2 added `fileRef` and bumped the version rather than extending v1 in place).
- **Add a new `ParamKind`/`ValueSource`/`DestructiveClass`**: extend the corresponding slice; `Valid()` derives from the slice's membership set.

## Related Specs

- [Binding](binding.md) — consumes the KB to bind a normalized invocation into effects.
- [Bash Frontend](bash-frontend/README.md) — produces the normalized invocations the binder binds.
- [PowerShell Frontend](powershell-frontend.md) — resolves against its own alias/cmdlet tables, not the bash KB.
- engine core (`engine/effect.go`, `engine/lattice.go`) — defines the `EffectKind`/`EffectMode` sets and the `Destructiveness` lattice the KB maps onto.
