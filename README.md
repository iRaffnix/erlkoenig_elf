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
| Binary Patching | Neutralize functions in-place (ret_zero, ret_one, ret_neg, nop + INT3 padding) |

Architectures: x86-64, AArch64.

## Install

### From GitHub Releases

```sh
sudo sh install.sh --version v0.1.0
```

### From local build / CI artifacts

```sh
sudo sh install.sh --local /path/to/artifacts
```

The installer auto-detects the private network IP and configures
distribution + epmd binding. Override with `--bind <ip>`.
Default prefix: `/opt/erlkoenig_elf`.

### Build from source

Requires OTP 27 + rebar3. Ubuntu 24.04: use `ppa:rabbitmq/rabbitmq-erlang-27`.

```sh
make release
sudo make install
```

## Quick start

```sh
# Start and enable
sudo systemctl enable --now erlkoenig_elf

# Analyze a binary
erlkoenig-elf analyze /usr/bin/ls | jq .

# Extract syscalls
erlkoenig-elf syscalls /path/to/binary

# Generate seccomp profile (Docker/OCI)
erlkoenig-elf seccomp /path/to/binary > seccomp.json

# Detect language
erlkoenig-elf language /path/to/binary

# Show dependencies (Go modules, Rust crates)
erlkoenig-elf deps /path/to/binary

# Patch a function
erlkoenig-elf patch /path/to/binary funcName --strategy ret_zero
```

See [USAGE.md](USAGE.md) for the full CLI reference, Erlang API,
Unix socket protocol, and output formats.

### Remote shell

```sh
RELX_COOKIE=$(cat /opt/erlkoenig_elf/cookie) \
  /opt/erlkoenig_elf/bin/erlkoenig_elf remote_console
```

### Erlang API

```erlang
{ok, Elf} = erlkoenig_elf:parse("/usr/bin/myapp"),
{ok, Report} = erlkoenig_elf:analyze(Elf),
{ok, Json} = erlkoenig_elf:seccomp_json(Elf),
go = erlkoenig_elf:language(Elf),
{ok, Deps} = erlkoenig_elf:deps(Elf).
```

### Use as dependency

```erlang
%% rebar.config
{deps, [
    {erlkoenig_elf, {git, "https://github.com/iRaffnix/erlkoenig_elf.git", {tag, "v0.1.0"}}}
]}.
```

## Architecture

```
                      erlkoenig_elf (Facade)
                              │
        ┌─────────┬──────────┼──────────┬──────────────┐
        ▼         ▼          ▼          ▼              ▼
    elf_parse  elf_syscall  elf_lang   elf_patch   elf_seccomp
        │         │          │
        ▼         ▼          ▼
    elf_parse  elf_decode  elf_lang_go
    _symtab    _x86_64    elf_lang_rust
               _aarch64   elf_lang_dwarf

    erlkoenig_elf_srv (gen_server)
        └── Unix Socket: /run/erlkoenig_elf/ctl.sock
```

18 modules, pure Erlang, no NIFs, no external dependencies.

## Project structure

```
src/            Erlang source (18 modules)
include/        Erlang headers (elf_parse.hrl, elf_seccomp.hrl, ...)
test/           EUnit tests (13 test modules)
config/         sys.config, vm.args.src (templates for relx)
bin/            CLI escript (erlkoenig-elf)
dist/           systemd unit
```

## Deployment

```
/opt/erlkoenig_elf/
├── bin/
│   ├── erlkoenig_elf              relx start wrapper
│   └── erlkoenig-elf              CLI escript
├── cookie                         Distribution cookie (440)
├── dist/
│   └── erlkoenig_elf.service      systemd unit
├── erts-*/                        Bundled Erlang runtime
├── lib/                           OTP libraries
└── releases/0.1.0/
    ├── sys.config
    └── vm.args.src                Template (vm.args generated at start)
```

Socket: `/run/erlkoenig_elf/ctl.sock`
Distribution: Port 9103, epmd on private IP via `ERL_EPMD_ADDRESS`
Runs as: `erlkoenig` user (not root)

## Role in the Erlkoenig ecosystem

```
                        Container Start
                              │
                    ┌─────────▼──────────┐
                    │  erlkoenig (core)   │
                    │  Container Runtime  │
                    └─────────┬──────────┘
                              │ parse binary
                    ┌─────────▼──────────┐
                    │   erlkoenig_elf    │
                    │   ELF Analysis     │
                    └──┬──────┬───────┬──┘
                       │      │       │
              ┌────────▼┐  ┌──▼────┐  ▼
              │ Seccomp  │  │ Deps  │  Symbols
              │ Profile  │  │ Audit │    │
              └────┬─────┘  └───┬───┘  ┌─▼──────────┐
                   │            │      │erlkoenig_bpf│
                   ▼            ▼      │  uprobes    │
              install BPF    log to    └─────────────┘
              at exec()    audit.jsonl
```

- **erlkoenig** calls `erlkoenig_elf:parse/1` + `seccomp_profile/1` during
  container creation. The generated BPF filter is installed before `exec()` —
  only syscalls the binary actually uses are allowed. No fixed profiles.
- **Dependency anomaly detection**: if a JSON library suddenly uses `connect`
  or `sendto`, `dep_anomalies/1` flags it for the audit log.
- **erlkoenig_bpf** receives function symbols + address ranges to attach
  uprobe programs for per-package runtime monitoring.

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
