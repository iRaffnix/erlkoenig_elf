# erlkoenig_elf

Static analysis service for ELF64 binaries. Extracts syscalls, generates
seccomp profiles, detects languages and dependencies, patches functions.
Pure Erlang, no NIFs.

Part of the [Erlkoenig](https://github.com/iRaffnix/erlkoenig) container
runtime. Erlkoenig uses erlkoenig_elf at container start to automatically
generate minimal seccomp-BPF filters from the binary being launched — instead
of shipping fixed profiles, the filter is derived from what the binary actually
does. Dependencies are checked for anomalous syscall usage (e.g. a JSON library
calling `connect`) and flagged in the audit log. Symbol tables feed into
[erlkoenig_bpf](https://github.com/iRaffnix/erlkoenig_bpf) for uprobe-based
runtime monitoring per package.

Runs as a standalone OTP daemon on a Unix socket. Cluster-capable via
standard epmd (hardened with `ERL_EPMD_ADDRESS`), fixed distribution port 9103.

## Capabilities

| Feature | Description |
|---|---|
| ELF64 Parse | Header, sections, segments, symbols, notes |
| Syscall Extraction | Scan `.text` for `SYSCALL`/`SVC` instructions, backward-resolve register values |
| Seccomp Generation | Minimal allow-list BPF filter from extracted syscalls (JSON + raw BPF) |
| Language Detection | Go (gopclntab, buildinfo), Rust (v0 demangling, panic strings), Zig, C/C++ (DWARF) |
| Dependency Analysis | Go modules from buildinfo, Rust crates from symbols |
| Anomaly Detection | Flag dependencies with unexpected capabilities (e.g. network access in a parser) |
| Binary Patching | Neutralize functions in-place (ret_zero, ret_one, ret_neg, nop + INT3 padding) |

Architectures: x86-64, AArch64.

## Install

> **Important:** Always use `make install` or `install.sh` — do not extract the
> release tarball manually. The installer sets file ownership, fixes the CLI
> shebang to use the bundled ERTS, and makes `releases/<vsn>/` writable so
> `vm.args` can be generated at startup. Without these steps the daemon will
> fail to start.

### From GitHub Releases (recommended)

Download the installer, review it, run it:

```sh
curl -fsSL -o install.sh \
  https://github.com/iRaffnix/erlkoenig_elf/releases/latest/download/install.sh
less install.sh
sudo sh install.sh --version v0.2.0
```

Options:

```
--version VERSION   Download release from GitHub (e.g., v0.2.0)
--local DIR         Install from local directory (CI artifacts)
--prefix DIR        Installation directory (default: /opt/erlkoenig_elf)
--bind IP           Bind epmd/distribution to this IP (default: auto-detect)
--force             Force reinstall even if same version
```

### From CI artifacts

```sh
gh run download <run-id> -D /tmp/artifacts
sudo sh install.sh --local /tmp/artifacts
```

### Build from source

Requires OTP 28 + rebar3. No OTP needed on the target machine — ERTS is
bundled in the release.

```sh
# On the build machine:
make release                     # builds prod tarball with bundled ERTS
sudo make install                # extracts, sets permissions, configures systemd

# Or build + deploy to a remote host:
rebar3 as prod tar
scp _build/prod/rel/erlkoenig_elf/erlkoenig_elf-0.2.0.tar.gz root@target:/tmp/
ssh root@target "sh install.sh --local /tmp"
```

### After installation

```sh
sudo systemctl enable --now erlkoenig_elf   # start + autostart on boot
/opt/erlkoenig_elf/bin/erlkoenig-elf ping   # verify: should print "pong"
```

## Quick start

```sh
# Start and enable
sudo systemctl enable --now erlkoenig_elf

# Full analysis report
erlkoenig-elf analyze /usr/bin/ls | jq .

# Extract syscalls
erlkoenig-elf syscalls /path/to/binary

# Generate seccomp profile (Docker/OCI JSON)
erlkoenig-elf seccomp /path/to/binary > seccomp.json

# Detect source language
erlkoenig-elf language /path/to/binary

# Show embedded dependencies (Go modules, Rust crates)
erlkoenig-elf deps /path/to/binary

# Neutralize a function (default: ret_zero)
erlkoenig-elf patch /path/to/binary funcName

# Neutralize with a specific strategy
erlkoenig-elf patch /path/to/binary funcName --strategy nop

# Check if daemon is running
erlkoenig-elf ping

# Show version
erlkoenig-elf version
```

Patch strategies: `ret_zero` (default), `ret_one`, `ret_neg`, `nop`.

The CLI connects to the daemon via Unix socket for fast analysis. If the
daemon is not running, it falls back to local (in-process) analysis
automatically. Override the socket path with `ERLKOENIG_ELF_SOCKET`.

See [USAGE.md](USAGE.md) for the full CLI reference, Erlang API,
Unix socket protocol, and output formats.

## Erlang API

All analysis goes through the `erlkoenig_elf` facade module:

```erlang
{ok, Elf} = erlkoenig_elf:parse("/usr/bin/myapp").
{ok, Report} = erlkoenig_elf:analyze(Elf).
{ok, Json} = erlkoenig_elf:seccomp_json(Elf).
go = erlkoenig_elf:language(Elf).
{ok, Deps} = erlkoenig_elf:deps(Elf).
Anomalies = erlkoenig_elf:dep_anomalies(Elf).
```

Full API with all functions (`syscalls`, `syscall_names`, `seccomp_profile`,
`seccomp_bpf`, `go_info`, `rust_info`, `dep_capabilities`, `dep_anomalies/2`,
`patch`, `patch_at`), output formats, Unix socket protocol, and `erl_call`
examples: see [USAGE.md](USAGE.md).

### Use as dependency

```erlang
%% rebar.config
{deps, [
    {erlkoenig_elf, {git, "https://github.com/iRaffnix/erlkoenig_elf.git", {tag, "v0.2.0"}}}
]}.
```

### Remote shell

```sh
RELX_COOKIE=$(cat /opt/erlkoenig_elf/cookie) \
  /opt/erlkoenig_elf/bin/erlkoenig_elf remote_console
```

## Architecture

```
                      erlkoenig_elf (Facade)
                              |
        +----------+----------+----------+-----------+
        v          v          v          v           v
    elf_parse  elf_syscall  elf_lang   elf_patch  elf_seccomp
        |          |          |
        v          v          v
    elf_parse   elf_decode  elf_lang_go      elf_dep (dependency
    _symtab     _x86_64    elf_lang_rust     analysis + anomalies)
                _aarch64   elf_lang_dwarf
                                             elf_report (reporting)

    elf_syscall_db (syscall number <-> name mapping)

    erlkoenig_elf_srv (gen_server, Unix socket)
    erlkoenig_elf_sup (supervisor)
    erlkoenig_elf_app (OTP application)
```

18 modules, pure Erlang, no NIFs, no external dependencies.

## Project structure

```
src/            Erlang source (18 modules)
include/        Erlang headers (elf_parse.hrl, elf_seccomp.hrl, ...)
test/           EUnit + PropEr tests (16 test modules)
config/         sys.config, vm.args.src (templates for relx)
bin/            CLI escript (erlkoenig-elf)
dist/           systemd unit
```

## Deployment

```
/opt/erlkoenig_elf/
+-- bin/
|   +-- erlkoenig_elf              relx start wrapper
|   +-- erlkoenig-elf              CLI escript
+-- cookie                         Distribution cookie (440)
+-- dist/
|   +-- erlkoenig_elf.service      systemd unit
+-- erts-*/                        Bundled Erlang runtime
+-- lib/                           OTP libraries
+-- releases/0.2.0/
    +-- sys.config
    +-- vm.args.src                Template (vm.args generated at start)
```

Socket: `/run/erlkoenig_elf/ctl.sock`
Distribution: Port 9103, epmd on private IP via `ERL_EPMD_ADDRESS`
Runs as: `erlkoenig` user (not root)

## Role in the Erlkoenig ecosystem

```
                        Container Start
                              |
                    +---------v----------+
                    |  erlkoenig (core)  |
                    |  Container Runtime |
                    +---------+----------+
                              | parse binary
                    +---------v----------+
                    |   erlkoenig_elf    |
                    |   ELF Analysis     |
                    +--+------+-------+--+
                       |      |       |
              +--------v+  +--v----+  v
              | Seccomp  |  | Deps  |  Symbols
              | Profile  |  | Audit |    |
              +----+-----+  +---+---+  +-v-----------+
                   |             |      |erlkoenig_bpf|
                   v             v      |  uprobes    |
              install BPF    log to    +-------------+
              at exec()    audit.jsonl
```

- **erlkoenig** calls `erlkoenig_elf:parse/1` + `seccomp_profile/1` during
  container creation. The generated BPF filter is installed before `exec()` —
  only syscalls the binary actually uses are allowed. No fixed profiles.
- **Dependency anomaly detection**: if a JSON library suddenly uses `connect`
  or `sendto`, `dep_anomalies/1` flags it for the audit log.
- **erlkoenig_bpf** receives function symbols + address ranges to attach
  uprobe programs for per-package runtime monitoring.

## Development

```sh
make compile          # compile
make test             # run EUnit + PropEr tests
make dialyzer         # type analysis
make fmt              # format code with erlfmt
make fmt-check        # check formatting (CI)
make xref             # cross-reference analysis
make lint             # fmt-check + xref + dialyzer
make check            # all quality checks
make release          # OTP release tarball
```

## Uninstall

```sh
sudo make uninstall
# or manually:
sudo systemctl stop erlkoenig_elf
sudo systemctl disable erlkoenig_elf
sudo rm /etc/systemd/system/erlkoenig_elf.service
sudo systemctl daemon-reload
sudo rm -rf /opt/erlkoenig_elf
```

## License

Apache-2.0
