# erlkoenig_elf

ELF64 binary analysis service for statically linked Linux binaries
(Go, Rust, Zig, C/musl). Part of the
[Erlkoenig](https://github.com/iRaffnix/erlkoenig) container runtime.

Runs as a standalone OTP daemon on a Unix socket. Analyzes binaries,
extracts syscalls, generates seccomp profiles. No epmd — custom EPMD
module with fixed port for remote shell access.

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

Default prefix: `/opt/erlkoenig_elf`. Override with `--prefix`.

### Build from source

```sh
make release
sudo make install
```

## Usage

### Service management

```sh
sudo systemctl start erlkoenig_elf
sudo systemctl enable erlkoenig_elf
sudo systemctl status erlkoenig_elf
journalctl -u erlkoenig_elf -f
```

### Remote shell (live debugging)

```sh
sudo /opt/erlkoenig_elf/bin/erlkoenig_elf_remsh
```

```erlang
(erlkoenig_elf@127.0.0.1)1> {ok, Elf} = erlkoenig_elf:parse("/usr/bin/ls").
(erlkoenig_elf@127.0.0.1)2> erlkoenig_elf:language(Elf).
c
(erlkoenig_elf@127.0.0.1)3> erlkoenig_elf:syscall_names(Elf).
{ok, [<<"close">>, <<"exit_group">>, <<"fstat">>, ...]}
```

### Erlang API

```erlang
{ok, Elf} = erlkoenig_elf:parse("/usr/bin/myapp"),

%% Syscalls
{ok, #{syscalls := Syscalls}} = erlkoenig_elf:syscalls(Elf),

%% Seccomp profile (JSON for Docker/OCI)
{ok, Json} = erlkoenig_elf:seccomp_json(Elf),

%% Seccomp BPF (raw filter program)
{ok, Bpf} = erlkoenig_elf:seccomp_bpf(Elf),

%% Language detection
go = erlkoenig_elf:language(Elf),
{ok, GoInfo} = erlkoenig_elf:go_info(Elf),

%% Full analysis
{ok, Report} = erlkoenig_elf:analyze(Elf).
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

    erlkoenig_epmd (custom EPMD)
        └── TCP 127.0.0.1:9103 (remote shell)
```

19 modules, pure Erlang, no NIFs, no external dependencies.

## Project structure

```
src/            Erlang source (19 modules)
include/        Erlang headers (elf_parse.hrl, elf_seccomp.hrl, ...)
test/           EUnit tests (13 test modules)
config/         sys.config, vm.args
dist/           systemd unit, launcher scripts
```

## Deployment

```
/opt/erlkoenig_elf/
├── bin/erlkoenig_elf_run       Daemon launcher
├── bin/erlkoenig_elf_remsh     Remote shell
├── config/                     sys.config, vm.args
├── cookie                      Distribution cookie (400)
├── dist/                       systemd unit
├── erts-*/                     Bundled Erlang runtime
├── lib/                        OTP libraries
└── releases/                   Release metadata
```

Socket: `/run/erlkoenig_elf/ctl.sock` (systemd RuntimeDirectory)
Distribution: `127.0.0.1:9103` (no epmd, custom EPMD module)

## Integration

- **erlkoenig**: automatic seccomp filter at `exec()` — parse binary, extract
  syscalls, install BPF filter before handing control to the process.
- **erlkoenig_bpf**: uprobe attachment points from symbol table for runtime
  tracing.

## Uninstall

```sh
sudo systemctl stop erlkoenig_elf
sudo systemctl disable erlkoenig_elf
sudo rm /etc/systemd/system/erlkoenig_elf.service
sudo systemctl daemon-reload
sudo rm -rf /opt/erlkoenig_elf
```

## License

Apache-2.0
